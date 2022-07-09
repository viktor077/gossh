package gossh

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var INPUT_PROMPT = []string{
	`^(?:<|\[)[\w\d\_\-\.\|\/]+(?:>|])$`, //huawei switch
	`^.*[\w\d@-]+:[\/\w\d-_~]+\s*\$\s*`,  //bash
}

type Client struct {
	ssh      *ssh.Client
	session  *ssh.Session
	stdin    io.WriteCloser
	stdout   io.Reader
	banner   []byte
	resp     []byte
	respdone chan bool
	custom   Config
}

type Config struct {
	KeyExchanges      []string
	HostKeyAlgorithms []string
	Ciphers           []string
	InputPrompt       []string
}

func NewClient() *Client {
	return &Client{}
}

func (c *Client) Config(conf *Config) {
	c.custom = *conf
}

// Открываем неинтерактивную shell сессию
func (c *Client) connect(addr string, port string, config *ssh.ClientConfig) error {
	var err error

	c.ssh, err = ssh.Dial("tcp", strings.Join([]string{addr, port}, ":"), config)
	if err != nil {
		return err
	}

	c.session, err = c.ssh.NewSession()
	if err != nil {
		return err
	}

	// Параметры виртуальной консоли. Все коды смотри в RFC4254
	err = c.session.RequestPty("xterm", 80, 40, ssh.TerminalModes{
		ssh.TTY_OP_ISPEED: 4,
		ssh.TTY_OP_OSPEED: 4,
	})
	if err != nil {
		return err
	}

	// Стандартный ввод/вывод назначаем в фэйковые stdin/stdout
	c.stdin, err = c.session.StdinPipe()
	if err != nil {
		return err
	}

	c.stdout, err = c.session.StdoutPipe()
	if err != nil {
		return err
	}

	// Отправляем запрос открыть shell на сервере
	if err := c.session.Shell(); err != nil {
		return err
	}

	// при подключении получаем баннер сервреа, поэтому указываем адрес баннера в response
	// c.resp = &c.banner
	c.respdone = make(chan bool)

	// чтение из канала бокируемая функция, поэтому запускаем ее в горутине сразу после подключения.
	// далее вызывать ее нет необходимости, это только увеличит количество запущеных горутин и они не заколются до закрытия канала.
	// в receive() получаем данные и сохраняем по указателю и функция будет заблокирована до появления следующих данных.
	// при выполнении следующих команд просто меняем буфер приема.
	go c.receive(&c.resp)
	<-c.respdone
	c.banner = c.resp

	return nil
}

// Подключиться с логином и паролем
func (c *Client) ConnectWithPassword(addr string, port string, login string, pass string) error {
	config, err := c.config()
	if err != nil {
		return err
	}

	config.User = login
	config.Auth = append(config.Auth, ssh.Password(pass))

	err = c.connect(addr, port, config)
	if err != nil {
		return err
	}

	return nil
}

// Подключиться с ключом
func (c *Client) ConnectWithPrivateKey(addr string, port string, login string, privateKey []byte, passphrase ...string) error {
	config, err := c.config()
	if err != nil {
		return err
	}
	config.User = login
	var signer ssh.Signer

	if len(passphrase) > 0 {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(privateKey, []byte(passphrase[0]))
		if err != nil {
			return err
		}
	} else {
		signer, err = ssh.ParsePrivateKey(privateKey)
		if err != nil {
			return err
		}
	}

	config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	err = c.connect(addr, port, config)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) Disconnect() error {
	err := c.session.Close()
	if err != nil {
		return err
	}
	c.ssh.Close()
	if err != nil {
		return err
	}
	return nil
}

// Выполнить команду и записать ответ в receiveBuffer.
// Функция вернет ошибку в случе неудачи и receiveBuffer будет пустым
func (c *Client) Exec(cmd string) (string, error) {
	err := c.send(append([]byte(cmd), byte(13)), true)
	if err != nil {
		return "", err
	}

	return string(c.resp), nil
}

// Функция отправляет на сервер команду и если receiveBuffer не указан, не ждет ответа от сервера.
// Испольуется для отправки непечатаемых символов, наприер Enter (0x13), Backspace (0x8), Tab (0x09) и т.д. и контрольны команд
// например Ctrl-X, Ctrl-Z и т.д.
// Если receiveBuffer указан, в receiveBuffer будет записан ответ сервера.
func (c *Client) Send(cmd []byte, waitAnswer bool) (*[]byte, error) {
	err := c.send(cmd, waitAnswer)
	if err != nil {
		return nil, err
	}

	return &c.resp, nil
}

func (c *Client) send(cmd []byte, waitAnswer bool) error {
	c.resp = []byte{}
	l := len(cmd)
	n := 0

	var err error

	for n, err = c.stdin.Write(cmd); n < l; {
		if err != nil {
			return err
		}

		l -= n
	}

	if waitAnswer {
		<-c.respdone
	}

	return nil
}

func (c *Client) receive(receiveBuffer *[]byte) {
	// так как используется session.Shell() чтение блокируется до получения новых данных.
	// если новые данные не появляются в канале dataChan, значит чтение не завершено, возможно заблокировано.
	// в этом случем необходимо проверить есть ли в выводе приглашение к вводу.
	// если есть - считаем данные приянты все.
	// в коммутаторах huawei приглашение к вводу вида <имя_коммутатора>
	for {
		buf := make([]byte, 1024)
		n, err := c.stdout.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Fatal(err)
			}
		}

		*receiveBuffer = append(*receiveBuffer, buf[:n]...)
		lastCR := bytes.LastIndex(*receiveBuffer, []byte{13})

		if lastCR > 0 && lastCR < len([]byte(*receiveBuffer)) {

			// if last rown match regular expression of c.custom.InputPrompt
			if c.matchInputPrompt([]byte(*receiveBuffer)[lastCR+1:]) {
				c.respdone <- true
			}
		}
	}
}

func (c *Client) matchInputPrompt(buf []byte) bool {
	row := strings.TrimSpace(string(buf))

	for _, v := range INPUT_PROMPT {
		reg := regexp.MustCompile(v)
		if reg.MatchString(row) {
			return true
		}
	}

	return false
}

// config returns the client configuration for connecting to the server
func (c *Client) config() (*ssh.ClientConfig, error) {
	return &ssh.ClientConfig{
		User:              "",
		Auth:              []ssh.AuthMethod{},
		HostKeyCallback:   hostKeyCallback,
		HostKeyAlgorithms: append(c.custom.HostKeyAlgorithms, []string{ssh.KeyAlgoRSA}...),
		Config: ssh.Config{
			KeyExchanges: append(c.custom.KeyExchanges, []string{
				"curve25519-sha256",
				"curve25519-sha256@libssh.org",
				"ecdh-sha2-nistp256",
				"ecdh-sha2-nistp384",
				"ecdh-sha2-nistp521",
				"diffie-hellman-group-exchange-sha256",
				"diffie-hellman-group16-sha512",
				"diffie-hellman-group18-sha512",
				"diffie-hellman-group14-sha256"}...),
			Ciphers: append(c.custom.Ciphers, []string{
				"chacha20-poly1305@openssh.com",
				"aes128-ctr",
				"aes192-ctr",
				"aes256-ctr",
				"aes128-gcm@openssh.com",
				"aes256-gcm@openssh.com"}...),
		},
		Timeout: 20 * time.Second,
	}, nil
}

// HostKeyCallback is called during the cryptographic handshake to validate the server's host key.
// The client configuration must supply this callback for the connection to succeed.
// The functions InsecureIgnoreHostKey or FixedHostKey can be used for simplistic host key checks.
func hostKeyCallback(hostanme string, remote net.Addr, key ssh.PublicKey) error {
	user, err := user.Current()
	if err != nil {
		log.Fatalf(err.Error())
	}

	filepath := filepath.Join(user.HomeDir, ".ssh", "known_hosts")

	callbackFunc, err := knownhosts.New(filepath)
	if err != nil {
		log.Fatal(err.Error())
	}

	err = callbackFunc(hostanme, remote, key)

	if err != nil {
		keyError := new(knownhosts.KeyError)

		// Если добавлять все ключи самостоятельно в known_host, код ниже можно пропустить.
		// Развертываем цепочку ошибок в keyError см. knownhost.go.
		if errors.As(err, &keyError) {

			stdin := bufio.NewReader(os.Stdin)

			switch len(keyError.Want) {
			case 0:
				fmt.Printf("Host key is not trusted.\nAre you sure you want to continue connecting?\nHost key will automatically added to known_host file. (yes/no)")

				for {
					answer, err := stdin.ReadBytes('\n')
					if err != nil {
						log.Fatal(err)
					}

					answer = answer[:len(answer)-1]

					if string(answer) == "no" {
						os.Exit(0)
					}

					if string(answer) == "yes" {
						file, err := os.OpenFile(filepath, os.O_APPEND|os.O_WRONLY, 0600)
						if err != nil {
							return err
						}
						defer file.Close()

						knownHosts := knownhosts.Normalize(remote.String())
						_, err = file.WriteString(knownhosts.Line([]string{"\n" + knownHosts}, key))
						if err != nil {
							log.Fatal(err.Error())
						}

						return nil
					}
				}
			default:
				return fmt.Errorf("%s key for %s mismatch", hostKeyString(key), hostanme)
			}
		}

		return err
	}

	return nil
}

// hostKeyString returns the publick key
func hostKeyString(k ssh.PublicKey) string {
	return k.Type() + " " + base64.StdEncoding.EncodeToString(k.Marshal())
}

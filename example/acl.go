package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/viktor077/gossh"
)

type netHost struct {
	ip   string
	port string
}

var (
	addr = flag.String("addr", "127.0.0.1", "ip address to connect. Сan be specify several ip addresses separated by a space or the path to the list")
	cmd  = flag.String("cmd", "", "commands to execute")
)

func main() {
	flag.Parse()

	hosts, err := handleAddrArg(*addr)
	if err != nil {
		log.Fatal(err)
	}

	var wg sync.WaitGroup

	for _, host := range hosts {
		wg.Add(1)

		go func(host *netHost) {
			sw := gossh.NewClient()
			sw.Config(&gossh.Config{
				InputPrompt: []string{`\b\w+@[\w\d-]+:.*\$`},
			})

			err := sw.ConnectWithPassword(host.ip, host.port, "molinero", "124810")
			if err != nil {
				log.Fatal(err.Error())
			}

			defer sw.Disconnect()

			for _, command := range strings.Split(*cmd, "\n") {
				r, err := sw.Exec(command)
				if err != nil {
					log.Fatal(err.Error())
				}

				fmt.Println(r)
			}

			wg.Done()
		}(&host)
	}

	wg.Wait()

}

func handleAddrArg(addr string) ([]netHost, error) {
	result := new([]netHost)
	for _, ip := range strings.Split(addr, " ") {
		if h, ok := matchIpAddress(ip); ok {
			*result = append(*result, *h)
		}
	}

	var err error

	if len(*result) < 1 {
		*result, err = handleAsFilePath(addr)
	}

	return *result, err
}

func handleAsFilePath(path string) ([]netHost, error) {
	result := new([]netHost)
	file, err := os.ReadFile(path) //, os.O_RDONLY, 0600)
	if err != nil {
		log.Fatal(err.Error())
	}

	for _, ip := range strings.Split(string(file), "\n") {
		if h, ok := matchIpAddress(ip); ok {
			*result = append(*result, *h)
		}
	}

	return *result, err
}

func matchIpAddress(ip string) (*netHost, bool) {
	patternIpAddress := regexp.MustCompile(`\b((?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(?:\.)){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]))\b(?::(\d{1,4}))*`)
	matches := patternIpAddress.FindStringSubmatch(ip)

	if len(matches) > 0 {
		port := "22"
		if matches[2] != "" {
			port = matches[2]
		}
		return &netHost{matches[1], port}, true
	}

	return nil, false
}

# gossh

Wrapper over the standard go library for working with ssh.
The main feature is the work in one session in Shell mode (after executing a remote command, the session is not closed).

You can connect with a password and a private key.
```
client := gossh.NewClient()
err = client.ConnectWithPrivateKey("127.0.0.1", "22", "viktor077", key, "12345")
if err != nil {
	log.Fatal(err.Error())
}
```

You can add missing encryption methods before connecting
```
client.Config(&gossh.Config{
	KeyExchanges: []string{
		"diffie-hellman-group-exchange-sha1",
	},
	Ciphers: []string{
		"aes128-ctr",
	},
	HostKeyAlgorithms: []string{
		"ecdsa-sha2-nistp256",
	},
})
```
There are two methods for executing remote commands **Exec** and **Run**

**Exec** sends a command and always waits for a response.
```
uname, _ := client.Exec("uname -a")
fmt.Println(uname)
```    
**Run** you need to specify whether to wait for a response.
```
client.Send([]byte("uname -a"), false)
uname,_:=client.Send([]byte{KB_Enter}, true)
fmt.Println(uname)
```
You should wait for a response only if a response should come after sending. Otherwise, the receive channel will be blocked.
```
client.Send([]byte("uname -a"), true) // execution will block the channel
uname,_:=client.Send([]byte{KB_Enter}, true)
fmt.Println(string(uname))
```

Command execution is determined by searching for an input prompt using regular expressions. Two regular expressions are predefined.
```
`^(?:<|\[)[\w\d\_\-\.\|\/]+(?:>|])$`, //huawei switch
`^.*[\w\d@-]+:[\/\w\d-_~]+\s*\$\s*`,  //bash
```    
You can change the regular expression in the same way as the encryption methods.
```
client.Config(&gossh.Config{
	InputPrompt: []string{"^viktor077@laptop:.*\$"},
})
```

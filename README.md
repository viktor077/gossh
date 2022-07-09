# gossh

Обертка над стандартной go билиотекой для работы с ssh.
Основная особенность - это работа в одной сессии в режиме Shell (после выполнения удаленной команды, сессия не закрывается).

Подключиться можно с паролем и приватным клчом.
```
client := gossh.NewClient()
err = client.ConnectWithPrivateKey("127.0.0.1", "22", "viktor077", key, "12345")
if err != nil {
	log.Fatal(err.Error())
}
```

Перед подключением можно добавить недостающие методы шифрования 
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
Для выполнения удаленных команд есть два метода **Exec** и **Run**

**Exec** отправляет команду и всегда ждет ответ.
```
uname, _ := client.Exec("uname -a")
fmt.Println(uname)
```    
**Run** необходимо указать ждать ли ответа.
```
client.Send([]byte("uname -a"), false)
uname,_:=client.Send([]byte{KB_Enter}, true)
fmt.Println(uname)
```
Ждать ответа следует только в случае, если после отправки должен прийти ответ. В противном случае канал приема будет заблокирован.
```
client.Send([]byte("uname -a"), true) // выполнение приведет к блокировке канала
uname,_:=client.Send([]byte{KB_Enter}, true)
fmt.Println(string(uname))
```

Исполнение команды определяется поиском приглашения к вводу с помощью регулярных выражений. Два регулярных выражения предопределены:
```
`^(?:<|\[)[\w\d\_\-\.\|\/]+(?:>|])$`, //huawei switch
`^.*[\w\d@-]+:[\/\w\d-_~]+\s*\$\s*`,  //bash
```    
Изменить регулярное выражение можно так же как и методы шифрования.
```
client.Config(&gossh.Config{
	InputPrompt: []string{"^viktor077@laptop:.*\$"},
})
```

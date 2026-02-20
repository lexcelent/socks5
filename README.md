# SOCKS5 proxy server

Here is the implementation of SOCKS5 proxy server using Go

wiki: https://en.wikipedia.org/wiki/SOCKS


You can find example in `example` folder

```
package main

import (
	"log"

	"github.com/lexcelent/socks5"
)

func main() {
	s := socks5.Server{}
	if err := s.ListenAndServe("tcp", ":1080"); err != nil {
		log.Fatalf("error: %s\n", err)
	}
}
```

# TODO

- authorization
- logger

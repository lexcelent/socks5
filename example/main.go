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

package main

import (
	"os"
	"relay/service"

	_ "github.com/joho/godotenv/autoload"
)

func main() {
	keyPath := os.Getenv("KEY_PATH")
	certPath := os.Getenv("CERT_PATH")
	relay := service.New(keyPath, certPath)
	panic(relay.Start())
}

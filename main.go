package main

import (
	"os"
	"relay/service"

	_ "github.com/joho/godotenv/autoload"
)

func main() {
	keyPath := os.Getenv("KEY_PATH")
	certPath := os.Getenv("CERT_PATH")
	mongoURI := os.Getenv("MONGO_URI")
	relay := service.New(keyPath, certPath, mongoURI)
	panic(relay.Start())
}

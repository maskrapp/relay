package main

import (
	"os"
	"relay/service"

	_ "github.com/joho/godotenv/autoload"
)

func main() {
	keyPath := os.Getenv("KEY_PATH")
	certPath := os.Getenv("CERT_PATH")
	postgresURI := os.Getenv("POSTGRES_URI")
	token := os.Getenv("MAIL_TOKEN")
	production := os.Getenv("PRODUCTION") == "true"
	relay := service.New(production, keyPath, certPath, postgresURI, token)
	relay.Start()
}

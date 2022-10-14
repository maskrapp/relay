package main

import (
	"os"
	"os/signal"
	"syscall"

	_ "github.com/joho/godotenv/autoload"
	"github.com/maskrapp/relay/service"
)

func main() {
	dbUser := os.Getenv("POSTGRES_USER")
	dbPassword := os.Getenv("POSTGRES_PASSWORD")
	dbHost := os.Getenv("POSTGRES_HOST")
	dbDatabase := os.Getenv("POSTGRES_DATABASE")
	token := os.Getenv("MAIL_TOKEN")
	production := os.Getenv("PRODUCTION") == "true"
	certificate := os.Getenv("CERTIFICATE")
	privateKey := os.Getenv("PRIVATE_KEY")
	relay := service.New(production, dbUser, dbPassword, dbHost, dbDatabase, token, certificate, privateKey)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	relay.Start()
	<-sigChan
	relay.Shutdown()
}

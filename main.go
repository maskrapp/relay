package main

import (
	"os"

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
	relay := service.New(production, dbUser, dbPassword, dbHost, dbDatabase, token)
	relay.Start()
}

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/joho/godotenv/autoload"
	"github.com/maskrapp/relay/internal/config"
	"github.com/maskrapp/relay/internal/global"
	"github.com/maskrapp/relay/internal/mailer"
	"github.com/maskrapp/relay/internal/service"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {

	cfg := config.New()

	ll, err := logrus.ParseLevel(cfg.Logger.LogLevel)
	if err != nil {
		ll = logrus.DebugLevel
	}
	logrus.SetLevel(ll)

	uri := fmt.Sprintf("postgres://%v:%v@%v/%v", cfg.Database.Username, cfg.Database.Password, cfg.Database.Host, cfg.Database.Database)

	db, err := gorm.Open(postgres.Open(uri), &gorm.Config{})
	if err != nil {
		logrus.Panic(err)
	}

	instances := &global.Instances{
		Gorm:   db,
		Mailer: mailer.New(cfg.ZeptoMail.EmailToken),
	}

	globalContext := global.NewContext(context.Background(), instances, cfg)

	service := service.New(globalContext)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go service.Start()
	<-sigChan
	service.Shutdown()
}

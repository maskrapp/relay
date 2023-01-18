package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/joho/godotenv/autoload"
	"github.com/maskrapp/relay/internal/config"
	"github.com/maskrapp/relay/internal/global"
	backend "github.com/maskrapp/relay/internal/pb/backend/v1"
	"github.com/maskrapp/relay/internal/service"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {

	cfg := config.New()

	ll, err := logrus.ParseLevel(cfg.Logger.LogLevel)
	if err != nil {
		ll = logrus.DebugLevel
	}
	logrus.SetLevel(ll)
	conn, err := grpc.Dial(
		cfg.GRPC.BackendHost,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		logrus.Panicf("grpc error: %s", err)
	}

	instances := &global.Instances{
		BackendClient: backend.NewBackendServiceClient(conn),
	}

	globalContext := global.NewContext(context.Background(), instances, cfg)

	service := service.New(globalContext)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go service.Start()
	<-sigChan
	service.Shutdown()
}

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/joho/godotenv/autoload"
	"github.com/maskrapp/relay/internal/config"
	"github.com/maskrapp/relay/internal/global"
	main_api "github.com/maskrapp/relay/internal/pb/main_api/v1"
	"github.com/maskrapp/relay/internal/smtp"
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
		cfg.GRPC.MainAPIHost,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		logrus.Panicf("grpc error: %s", err)
	}

	instances := &global.Instances{
		GrpcClient: main_api.NewMainAPIServiceClient(conn),
	}

	globalContext := global.NewContext(context.Background(), instances, cfg)

	server := smtp.New(globalContext)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go server.ListenAndServe()
	<-sigChan
	server.Shutdown(globalContext)
}

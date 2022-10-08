package logger

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Logger struct {
	mongoClient *mongo.Client
	collection  *mongo.Collection
	logger      *logrus.Logger
}

func New(uri string) *Logger {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		panic(err)
	}
	db := client.Database("logs")
	return &Logger{mongoClient: client, collection: db.Collection("email_data"), logger: logrus.New()}
}

func (l *Logger) Log(data map[string]interface{}) {
	_, err := l.collection.InsertOne(context.Background(), data)
	if err != nil {
		l.logger.Error("error inserting log %v", err)
	}
	l.logger.Info("received email:", data)
}

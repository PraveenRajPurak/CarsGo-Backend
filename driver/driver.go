package driver

import (
	"context"
	"time"

	"github.com/PraveenRajPurak/CarsGo-Backend/modules/config"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func Connection(URI string, app config.GoAppTools) *mongo.Client {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(URI))

	if err != nil {
		app.ErrorLogger.Fatal(err)
	}

	err = client.Ping(ctx, nil)

	if err != nil {
		app.ErrorLogger.Fatal(err)
	}

	app.InfoLogger.Println("Connected to MongoDB!")

	return client
}

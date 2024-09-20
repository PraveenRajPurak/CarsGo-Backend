package query

import "go.mongodb.org/mongo-driver/mongo"

func User(client *mongo.Client, collection string) *mongo.Collection {

	collection_db := client.Database("CarsGo").Collection(collection)
	return collection_db
}

func Product(client *mongo.Client, collection string) *mongo.Collection {

	collection_db := client.Database("CarsGo").Collection(collection)
	return collection_db
}

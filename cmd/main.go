package main

import (
	"encoding/gob"
	"fmt"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/PraveenRajPurak/CarsGo-Backend/driver"
	"github.com/PraveenRajPurak/CarsGo-Backend/handler"
	"github.com/PraveenRajPurak/CarsGo-Backend/modules/config"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/joho/godotenv"
)

var app config.GoAppTools
var validate *validator.Validate
var Client *mongo.Client

func main() {

	gob.Register(map[string]interface{}{})
	gob.Register(primitive.NewObjectID())

	InfoLogger := log.New(os.Stdout, " ", log.LstdFlags|log.Lshortfile)
	ErrorLogger := log.New(os.Stdout, " ", log.LstdFlags|log.Lshortfile)

	app.InfoLogger = InfoLogger
	app.ErrorLogger = ErrorLogger

	validate = validator.New()

	app.Validate = validate

	fmt.Println("Welcome to Ecommerce App!")

	err := godotenv.Load()
	if err != nil {
		app.ErrorLogger.Fatal("No .env file available")
	}
	URI := os.Getenv("MONGODB_URI")
	fmt.Println("MongoDB URI : ", URI)

	Client = driver.Connection(URI, app)

	if Client != nil {

		fmt.Println("Connected to MongoDB!")
	}

	webserver := gin.New()

	webserver.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "Admin_Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	GoApp := handler.NewGoApp(&app, Client)

	Routes(webserver, GoApp)

	webserver.Run(":10010")
}

package auth

import (
	"net/http"
	"os"
	"time"

	"github.com/PraveenRajPurak/CarsGo-Backend/modules/config"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var app config.GoAppTools

type GoAppClaims struct {
	jwt.RegisteredClaims
	Email string
	ID    primitive.ObjectID
	Name  string
}

var secretKey = os.Getenv("ACCESS_TOKEN_SECRET")

func Generate(email string, id primitive.ObjectID, name string) (string, string, error) {

	goAppClaims := GoAppClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "ecommerceApp",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
		},
		Email: email,
		ID:    id,
		Name:  name,
	}

	newGoAppClaims := &jwt.RegisteredClaims{
		Issuer:    "ecommerceApp",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 48)),
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, goAppClaims).SignedString([]byte(secretKey))
	if err != nil {
		return "", "", err
	}
	newToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, newGoAppClaims).SignedString([]byte(secretKey))
	if err != nil {
		return "", "", err
	}
	return token, newToken, nil
}

func Parse(tokenString string) (*GoAppClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &GoAppClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	if err != nil {
		app.ErrorLogger.Fatalf("error while parsing token with it claims %v", err)
	}
	claims, ok := token.Claims.(*GoAppClaims)
	if !ok {
		app.ErrorLogger.Fatalf("error %v controller not authorized access", http.StatusUnauthorized)
	}
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		app.ErrorLogger.Fatalf("error %v token has expired", http.StatusUnauthorized)
	}
	return claims, nil
}

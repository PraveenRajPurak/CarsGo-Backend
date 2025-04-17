package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/PraveenRajPurak/CarsGo-Backend/modules/auth"
	"github.com/PraveenRajPurak/CarsGo-Backend/modules/database/query"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func Authorisation() gin.HandlerFunc {

	fmt.Println("Authorisation middleware")

	return func(ctx *gin.Context) {

		cookieData := sessions.Default(ctx)

		fmt.Println("Inside Authorisation middleware. Cookie Data : ", cookieData)

		token_from_header := ctx.GetHeader("Authorization")

		fmt.Println("Inside Authorisation middleware. Token from header : ", token_from_header)

		token_from_header1 := strings.Replace(token_from_header, "Bearer ", "", 1)

		accessToken := token_from_header1

		if accessToken == "" {

			_ = ctx.AbortWithError(http.StatusUnauthorized, errors.New("unauthorized user"))
			return
		}

		fmt.Println("Inside Authorisation middleware. Access Token : ", accessToken)

		claims, err := auth.Parse(accessToken)

		fmt.Println("Inside Authorisation middleware. Claims : ", claims)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusUnauthorized, gin.Error{
				Err: err})
		}

		contex, cancel := context.WithTimeout(context.Background(), 100*time.Second)

		defer cancel()

		var res bson.M

		filter := bson.D{{Key: "email", Value: claims.Email}}

		if Client == nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{
				Err: err})
			return
		}

		ins_err := query.User(Client, "user").FindOne(contex, filter).Decode(&res)

		if ins_err != nil {
			if ins_err == mongo.ErrNoDocuments {
				_ = ctx.AbortWithError(http.StatusUnauthorized, errors.New("unauthorized user"))
				return
			}
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{
				Err: ins_err,
			})
		}

		ctx.Set("pass", accessToken)
		ctx.Set("Email", claims.Email)
		ctx.Set("UID", claims.ID)
		ctx.Set("Name", claims.Name)

		fmt.Println("Coming out of Authorisation middleware")
		ctx.Next()
	}
}
func Admin_Authorisation() gin.HandlerFunc {

	fmt.Println("Admin Authorisation middleware")

	return func(ctx *gin.Context) {

		cookieData := sessions.Default(ctx)

		fmt.Println("Inside Admin Authorisation middleware. Cookie Data : ", cookieData)

		token_from_header := ctx.GetHeader("Admin_Authorization")

		fmt.Println("Inside Admin Authorisation middleware. Token from header : ", token_from_header)

		token_from_header1 := strings.Replace(token_from_header, "Bearer ", "", 1)

		accessToken := token_from_header1

		if accessToken == "" {

			_ = ctx.AbortWithError(http.StatusUnauthorized, errors.New("unauthorized admin access"))
			return
		}

		fmt.Println("Inside Authorisation middleware. Access Token : ", accessToken)

		claims, err := auth.Parse(accessToken)

		fmt.Println("Inside Authorisation middleware. Claims : ", claims)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusUnauthorized, gin.Error{
				Err: err})
		}

		contex, cancel := context.WithTimeout(context.Background(), 100*time.Second)

		defer cancel()

		var res bson.M

		filter := bson.D{{Key: "email", Value: claims.Email}}

		if Client == nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{
				Err: err})
			return
		}

		ins_err := query.User(Client, "admin").FindOne(contex, filter).Decode(&res)

		if ins_err != nil {
			if ins_err == mongo.ErrNoDocuments {
				_ = ctx.AbortWithError(http.StatusUnauthorized, errors.New("unauthorized admin"))
				return
			}
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{
				Err: ins_err,
			})
		}

		ctx.Set("pass", accessToken)
		ctx.Set("Email", claims.Email)
		ctx.Set("UID", claims.ID)
		ctx.Set("Name", claims.Name)

		fmt.Println("Coming out of Authorisation middleware")
		ctx.Next()
	}
}

// In middlewares.go
func CSE_Authorisation() gin.HandlerFunc {
	fmt.Println("CSE Authorisation middleware")

	return func(ctx *gin.Context) {
		cookieData := sessions.Default(ctx)

		fmt.Println("Inside CSE Authorisation middleware. Cookie Data : ", cookieData)

		token_from_header := ctx.GetHeader("CSE_Authorization")

		fmt.Println("Inside CSE Authorisation middleware. Token from header : ", token_from_header)

		token_from_header1 := strings.Replace(token_from_header, "Bearer ", "", 1)

		accessToken := token_from_header1

		if accessToken == "" {
			_ = ctx.AbortWithError(http.StatusUnauthorized, errors.New("unauthorized CSE access"))
			return
		}

		fmt.Println("Inside CSE Authorisation middleware. Access Token : ", accessToken)

		claims, err := auth.Parse(accessToken)

		fmt.Println("Inside CSE Authorisation middleware. Claims : ", claims)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusUnauthorized, gin.Error{
				Err: err})
		}

		contex, cancel := context.WithTimeout(context.Background(), 100*time.Second)

		defer cancel()

		var res bson.M

		filter := bson.D{{Key: "email", Value: claims.Email}}

		if Client == nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{
				Err: err})
			return
		}

		ins_err := query.User(Client, "cses").FindOne(contex, filter).Decode(&res)

		if ins_err != nil {
			if ins_err == mongo.ErrNoDocuments {
				_ = ctx.AbortWithError(http.StatusUnauthorized, errors.New("unauthorized CSE"))
				return
			}
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{
				Err: ins_err,
			})
		}

		ctx.Set("pass", accessToken)
		ctx.Set("UID", claims.ID)
		ctx.Set("Name", claims.Name)
		ctx.Set("Email", claims.Email)

		fmt.Println("Coming out of CSE Authorisation middleware")
		ctx.Next()
	}
}

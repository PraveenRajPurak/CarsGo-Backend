package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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

		accessToken := cookieData.Get("token").(string)

		if accessToken == "" {

			_ = ctx.AbortWithError(http.StatusUnauthorized, errors.New("unauthorized user"))
			return
		}

		claims, err := auth.Parse(accessToken)

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

		accessToken, exists := cookieData.Get("admin_token").(string)

		if !exists || accessToken == "" {

			_ = ctx.AbortWithError(http.StatusUnauthorized, errors.New("unauthorized admin"))
			return
		}

		claims, err := auth.Parse(accessToken)

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

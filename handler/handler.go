package handler

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/PraveenRajPurak/CarsGo-Backend/modules/auth"
	"github.com/PraveenRajPurak/CarsGo-Backend/modules/config"
	"github.com/PraveenRajPurak/CarsGo-Backend/modules/database"
	"github.com/PraveenRajPurak/CarsGo-Backend/modules/database/query"
	"github.com/PraveenRajPurak/CarsGo-Backend/modules/encrypt"
	"github.com/PraveenRajPurak/CarsGo-Backend/modules/model"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type GoApp struct {
	App *config.GoAppTools
	DB  database.DBRepo
}

func NewGoApp(app *config.GoAppTools, db *mongo.Client) *GoApp {
	return &GoApp{
		App: app,
		DB:  query.NewGoAppDB(app, db),
	}
}

func (ga *GoApp) Home() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{
			"message": "Welcome to the home page of Ecommerce App!",
		})
	}
}

func (ga *GoApp) Sign_Up() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var user *model.User

		err := ctx.ShouldBindJSON(&user)
		if err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{
				Err: err,
			})
		}

		user.CreatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.UpdatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		user.Password, _ = encrypt.Hash(user.Password)

		user.Addresses = []model.Address{}
		user.Cart = []model.CartItems{}
		user.Orders = []primitive.ObjectID{}
		user.Payments = []primitive.ObjectID{}
		user.Shipments = []primitive.ObjectID{}
		user.Wishlist = []primitive.ObjectID{}

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if err := ga.App.Validate.Struct(&user); err != nil {
			if _, ok := err.(*validator.InvalidValidationError); !ok {
				_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
				ga.App.InfoLogger.Println(err)
				return
			}
		}

		ok, status, err := ga.DB.InsertUser(user)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, errors.New("error while adding new user"))
			ctx.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			return
		}

		if !ok {
			_ = ctx.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		switch status {
		case 1:
			{
				ctx.JSON(http.StatusCreated, gin.H{"message": "User created successfully"})
			}
		case 2:
			{
				ctx.JSON(http.StatusConflict, gin.H{"message": "User already exists"})
			}
		}
	}
}

func (ga *GoApp) Sign_In() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		var user *model.User
		if err := ctx.ShouldBindJSON(&user); err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}

		regMail := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
		ok := regMail.MatchString(user.Email)

		if ok {

			res, err := ga.DB.VerifyUser(user.Email)
			if err != nil {
				_ = ctx.AbortWithError(http.StatusInternalServerError, err)
				ctx.JSON(http.StatusUnauthorized, gin.H{"message": "unregistered user"})
				return
			}

			id := res["_id"].(primitive.ObjectID)
			password := res["password"].(string)

			verified, err := encrypt.VerifyPassword(user.Password, password)
			if err != nil {
				_ = ctx.AbortWithError(http.StatusInternalServerError, err)
				ctx.JSON(http.StatusUnauthorized, gin.H{"message": "unregistered user detected using wrong password"})
				return
			}

			if verified {

				cookieData := sessions.Default(ctx)

				userInfo := map[string]interface{}{
					"ID":    id,
					"Email": user.Email,
					"Name":  res["name"],
				}

				cookieData.Options(sessions.Options{
					Path:     "/",
					HttpOnly: true,
					Secure:   false,
					SameSite: http.SameSiteNoneMode,
				})

				cookieData.Set("userInfo", userInfo)
				if err := cookieData.Save(); err != nil {
					_ = ctx.AbortWithError(http.StatusInternalServerError, err)
					ctx.JSON(http.StatusInternalServerError, gin.H{"message": "error while saving cookie"})
					return
				}

				t1, t2, err := auth.Generate(user.Email, id, res["name"].(string))

				if err != nil {
					_ = ctx.AbortWithError(http.StatusInternalServerError, err)
					ctx.JSON(http.StatusInternalServerError, gin.H{"message": "error while generating tokens"})
					return
				}

				cookieData.Set("token", t1)

				ctx.SetCookie("user_session", t1, 3600, "/", "localhost", false, true)

				if err := cookieData.Save(); err != nil {
					_ = ctx.AbortWithError(http.StatusInternalServerError, err)
					ctx.JSON(http.StatusInternalServerError, gin.H{"message": "error while saving cookie"})
					return
				}

				fmt.Println("We are here to check if token is actually set in cookie!")

				token_set_in_cookie := cookieData.Get("token").(string)
				if token_set_in_cookie != "" {
					fmt.Println("Token set in cookie : ", token_set_in_cookie)
				}

				cookieData.Set("new_token", t2)

				if err := cookieData.Save(); err != nil {
					_ = ctx.AbortWithError(http.StatusInternalServerError, err)
					ctx.JSON(http.StatusInternalServerError, gin.H{"message": "error while saving cookie"})
					return
				}

				fmt.Println("The check is complete and you can make your mind how to proceed further.")

				tk := map[string]string{
					"token":    t1,
					"newToken": t2,
				}

				updated, err := ga.DB.UpdateUser(id, tk)

				if err != nil {
					_ = ctx.AbortWithError(http.StatusInternalServerError, err)
					ctx.JSON(http.StatusInternalServerError, gin.H{"message": "error while updating tokens"})
					return
				}

				if !updated {
					_ = ctx.AbortWithError(http.StatusInternalServerError, err)
					ctx.JSON(http.StatusInternalServerError, gin.H{"message": "error while updating tokens"})
					return
				}

				ctx.JSON(http.StatusOK, gin.H{
					"message":       "Successfully Logged in",
					"email":         user.Email,
					"id":            id,
					"name":          res["name"],
					"session_token": t1,
				})
			} else {
				ctx.JSON(http.StatusUnauthorized, gin.H{"message": "unregistered user detected using wrong credentials"})
				return
			}
		}
	}
}

func (ga *GoApp) ForgotPasswordUser() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		email, _ := ctx.Get("Email")

		var user *model.User

		if err := ctx.ShouldBindJSON(&user); err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}

		user.Email = email.(string)

		updated, err := ga.DB.CreateNewPassword(user.Email, user.Password)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, err)
		}

		if !updated {
			_ = ctx.AbortWithError(http.StatusInternalServerError, err)
		}

		ctx.JSON(http.StatusOK, gin.H{"message": "password changed successfully"})
	}
}

func (ga *GoApp) ForgotPasswordAdmin() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		email, _ := ctx.Get("Email")

		var admin *model.Admin

		if err := ctx.ShouldBindJSON(&admin); err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}

		admin.Email = email.(string)

		updated, err := ga.DB.CreateNewPassword(admin.Email, admin.Password)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, err)
		}

		if !updated {
			_ = ctx.AbortWithError(http.StatusInternalServerError, err)
		}

		ctx.JSON(http.StatusOK, gin.H{"message": "admin's password changed successfully"})
	}
}

func (ga *GoApp) Update_Email_User() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		current_email := ctx.MustGet("Email").(string)

		var Input struct {
			New_Email string `json:"new_email"`
		}

		if err := ctx.ShouldBindJSON(&Input); err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}

		regMail := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
		ok := regMail.MatchString(Input.New_Email)

		if !ok {
			ctx.JSON(http.StatusBadRequest, gin.H{"message": "invalid email"})
			return
		}

		updated, err := ga.DB.UpdateEmailUser(current_email, Input.New_Email)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if !updated {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		cookieData := sessions.Default(ctx)
		cookieData.Set("Email", Input.New_Email)
		if err := cookieData.Save(); err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ctx.Set("Email", Input.New_Email)

		ctx.JSON(http.StatusOK, gin.H{"message": "email updated successfully"})

	}
}

func (ga *GoApp) Update_Email_Admin() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		current_email := ctx.MustGet("Email").(string)

		var Input struct {
			New_Email string `json:"new_email"`
		}

		if err := ctx.ShouldBindJSON(&Input); err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}

		regMail := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
		ok := regMail.MatchString(Input.New_Email)

		if !ok {
			ctx.JSON(http.StatusBadRequest, gin.H{"message": "invalid email"})
			return
		}

		updated, err := ga.DB.UpdateEmailAdmin(current_email, Input.New_Email)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if !updated {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		cookieData := sessions.Default(ctx)
		cookieData.Set("Email", Input.New_Email)
		if err := cookieData.Save(); err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ctx.Set("Email", Input.New_Email)

		ctx.JSON(http.StatusOK, gin.H{"message": "Admin's email updated successfully"})

	}
}
func (ga *GoApp) Update_Name_User() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		email := ctx.MustGet("Email").(string)

		var Input struct {
			New_Name string `json:"new_name"`
		}

		if err := ctx.ShouldBindJSON(&Input); err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}

		updated, err := ga.DB.UpdateNameUser(email, Input.New_Name)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if !updated {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		cookieData := sessions.Default(ctx)
		cookieData.Set("Name", Input.New_Name)
		if err := cookieData.Save(); err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ctx.Set("Name", Input.New_Name)

		ctx.JSON(http.StatusOK, gin.H{"message": "name updated successfully"})

	}
}

func (ga *GoApp) Update_Name_Admin() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		email := ctx.MustGet("Email").(string)

		var Input struct {
			New_Name string `json:"new_name"`
		}

		if err := ctx.ShouldBindJSON(&Input); err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}

		updated, err := ga.DB.UpdateNameAdmin(email, Input.New_Name)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if !updated {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		cookieData := sessions.Default(ctx)
		cookieData.Set("Name", Input.New_Name)
		if err := cookieData.Save(); err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ctx.Set("Name", Input.New_Name)

		ctx.JSON(http.StatusOK, gin.H{"message": "user's name updated successfully"})

	}
}

func (ga *GoApp) Update_Phone_User() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		email := ctx.MustGet("Email").(string)

		var Input struct {
			New_Phone string `json:"new_phone"`
		}

		if err := ctx.ShouldBindJSON(&Input); err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}

		updated, err := ga.DB.UpdatePhoneUser(email, Input.New_Phone)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if !updated {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ctx.JSON(http.StatusOK, gin.H{"message": "phone updated successfully"})

	}
}

func (ga *GoApp) Update_Phone_Admin() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		email := ctx.MustGet("Email").(string)

		var Input struct {
			New_Phone string `json:"new_phone"`
		}

		if err := ctx.ShouldBindJSON(&Input); err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}

		updated, err := ga.DB.UpdatePhoneAdmin(email, Input.New_Phone)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if !updated {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ctx.JSON(http.StatusOK, gin.H{"message": "phone updated successfully"})

	}
}

func (ga *GoApp) SignOutUser() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		userID := ctx.MustGet("UID").(primitive.ObjectID)

		status, err := ga.DB.SignOutUser(userID)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if !status {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		cookieData := sessions.Default(ctx)
		cookieData.Clear()

		if err := cookieData.Save(); err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ctx.Set("UID", nil)
		ctx.Set("Email", nil)
		ctx.Set("Name", nil)

		ctx.JSON(http.StatusOK, gin.H{"message": "signed out the user successfully"})

	}
}
func (ga *GoApp) SignOutAdmin() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		adminID := ctx.MustGet("UID").(primitive.ObjectID)

		status, err := ga.DB.SignOutAdmin(adminID)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if !status {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		cookieData := sessions.Default(ctx)
		cookieData.Clear()

		if err := cookieData.Save(); err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ctx.Set("UID", nil)
		ctx.Set("Email", nil)
		ctx.Set("Name", nil)

		ctx.JSON(http.StatusOK, gin.H{"message": "signed out the admin successfully"})

	}
}

func (g *GoApp) InsertProducts() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		var product *model.Product

		if err := ctx.ShouldBindJSON(&product); err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}
		product.CreatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		product.UpdatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		if err := g.App.Validate.Struct(&product); err != nil {
			if _, ok := err.(*validator.InvalidValidationError); !ok {
				_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
				g.App.InfoLogger.Println(err)
				return
			}
		}

		ok, status, err := g.DB.InsertProduct(product)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
			ctx.JSON(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if !ok {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
			ctx.JSON(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if status == 1 {

			ctx.JSON(http.StatusOK, gin.H{"message": "Product created successfully"})
		}

		if status == 2 {

			ctx.JSON(http.StatusOK, gin.H{"message": "Product already exists"})
		}

	}
}

func (g *GoApp) InsertMultipleProducts() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var products []*model.Product

		if err := ctx.ShouldBindJSON(&products); err != nil {
			ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Process each product
		currentTime, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		for i := range products {
			products[i].CreatedAt = currentTime
			products[i].UpdatedAt = currentTime

			// Validate each product
			if err := g.App.Validate.Struct(products[i]); err != nil {
				if _, ok := err.(*validator.InvalidValidationError); !ok {
					ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
					ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					g.App.InfoLogger.Println(err)
					return
				}
			}
		}

		// Insert all products
		insertedCount, existingCount, err := g.DB.InsertMultipleProductsBulk(products)

		if err != nil {
			ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{
			"message":  "Products processed",
			"inserted": insertedCount,
			"existing": existingCount,
		})
	}
}

func (g *GoApp) ViewProducts() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		var res []primitive.M

		res, err := g.DB.ViewProducts()

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
			ctx.JSON(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ctx.JSON(http.StatusOK, gin.H{"data": res})
	}
}

func (ga *GoApp) Change_Stock() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		var Input struct {
			ProductID primitive.ObjectID `json:"product_id"`
			New_Stock int                `json:"new_stock"`
		}

		if err := ctx.ShouldBindJSON(&Input); err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}

		ok, err := ga.DB.Update_Stock(Input.ProductID, Input.New_Stock)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if !ok {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ctx.JSON(http.StatusOK, gin.H{"message": "stock updated successfully"})

	}
}

func (ga *GoApp) Sign_Up_Admin() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var admin *model.Admin

		err := ctx.ShouldBindJSON(&admin)
		if err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{
				Err: err,
			})
		}

		admin.CreatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		admin.UpdatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		admin.Password, _ = encrypt.Hash(admin.Password)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if err := ga.App.Validate.Struct(&admin); err != nil {
			if _, ok := err.(*validator.InvalidValidationError); !ok {
				_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
				ga.App.InfoLogger.Println(err)
				return
			}
		}

		ok, status, err := ga.DB.SignUpAdmin(admin)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, errors.New("error while adding new admin"))
			ctx.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			return
		}

		if !ok {
			_ = ctx.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		switch status {
		case 1:
			{
				ctx.JSON(http.StatusCreated, gin.H{"message": "Admin created successfully"})
			}
		case 2:
			{
				ctx.JSON(http.StatusConflict, gin.H{"message": "Admin already exists"})
			}
		}
	}
}

func (ga *GoApp) Sign_In_Admin() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		var admin *model.Admin
		if err := ctx.ShouldBindJSON(&admin); err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}

		regMail := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
		ok := regMail.MatchString(admin.Email)

		if ok {

			res, err := ga.DB.VerifyAdmin(admin.Email)
			if err != nil {
				_ = ctx.AbortWithError(http.StatusInternalServerError, err)
				ctx.JSON(http.StatusUnauthorized, gin.H{"message": "unregistered user"})
				return
			}

			id := res["_id"].(primitive.ObjectID)
			password := res["password"].(string)

			verified, err := encrypt.VerifyPassword(admin.Password, password)
			if err != nil {
				_ = ctx.AbortWithError(http.StatusInternalServerError, err)
				ctx.JSON(http.StatusUnauthorized, gin.H{"message": "unregistered user detected using wrong password"})
				return
			}

			if verified {

				cookieData := sessions.Default(ctx)

				adminInfo := map[string]interface{}{
					"ID":    id,
					"Email": admin.Email,
					"Name":  res["name"],
				}

				cookieData.Set("adminInfo", adminInfo)

				if err := cookieData.Save(); err != nil {
					_ = ctx.AbortWithError(http.StatusInternalServerError, err)
					ctx.JSON(http.StatusInternalServerError, gin.H{"message": "error while saving cookie"})
					return
				}

				t1, t2, err := auth.Generate(admin.Email, id, res["name"].(string))

				if err != nil {
					_ = ctx.AbortWithError(http.StatusInternalServerError, err)
					ctx.JSON(http.StatusInternalServerError, gin.H{"message": "error while generating tokens"})
					return
				}

				cookieData.Set("admin_token", t1)

				if err := cookieData.Save(); err != nil {
					_ = ctx.AbortWithError(http.StatusInternalServerError, err)
					ctx.JSON(http.StatusInternalServerError, gin.H{"message": "error while saving cookie"})
					return
				}

				cookieData.Set("new_admin_token", t2)

				if err := cookieData.Save(); err != nil {
					_ = ctx.AbortWithError(http.StatusInternalServerError, err)
					ctx.JSON(http.StatusInternalServerError, gin.H{"message": "error while saving cookie"})
					return
				}

				tk := map[string]string{
					"token":    t1,
					"newToken": t2,
				}

				updated, err := ga.DB.UpdateAdmin(id, tk)

				if err != nil {
					_ = ctx.AbortWithError(http.StatusInternalServerError, err)
					ctx.JSON(http.StatusInternalServerError, gin.H{"message": "error while updating tokens"})
					return
				}

				if !updated {
					_ = ctx.AbortWithError(http.StatusInternalServerError, err)
					ctx.JSON(http.StatusInternalServerError, gin.H{"message": "error while updating tokens"})
					return
				}

				ctx.JSON(http.StatusOK, gin.H{
					"message":       "Successfully Logged in",
					"email":         admin.Email,
					"id":            id,
					"name":          res["name"],
					"session_token": t1,
				})
			} else {
				ctx.JSON(http.StatusUnauthorized, gin.H{"message": "unregistered admin detected using wrong credentials"})
				return
			}
		}
	}
}

func (ga *GoApp) CreateCategory() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		var category *model.Category
		if err := ctx.ShouldBindJSON(&category); err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}

		category.CreatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		category.UpdatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		if err := ga.App.Validate.Struct(&category); err != nil {
			if _, ok := err.(*validator.InvalidValidationError); !ok {
				_ = ctx.AbortWithError(http.StatusBadRequest, err)
				ga.App.ErrorLogger.Println(err)
				return
			}
		}

		ok, status, err := ga.DB.CreateCategory(category)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, errors.New("error while adding new category"))
			ctx.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			return
		}

		if !ok {
			_ = ctx.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		switch status {
		case 1:
			{
				ctx.JSON(http.StatusCreated, gin.H{"message": "Category created successfully"})
			}
		case 2:
			{
				ctx.JSON(http.StatusConflict, gin.H{"message": "Category already exists"})
			}
		}
	}
}

func (ga *GoApp) UpdateProduct() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		var product *model.Product

		if err := ctx.ShouldBindJSON(&product); err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}

		ok, err := ga.DB.UpdateProduct(product)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if !ok {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ga.App.InfoLogger.Println("Product updated successfully")

		ctx.JSON(http.StatusOK, gin.H{"message": "Product updated successfully"})

	}
}

func (ga *GoApp) ToggleStock() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		var Input struct {
			ProductID primitive.ObjectID `json:"product_id"`
		}

		if err := ctx.ShouldBindJSON(&Input); err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}

		ok, err := ga.DB.Toggle_Stock(Input.ProductID)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if !ok {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ga.App.InfoLogger.Println("Stock toggled successfully")

		ctx.JSON(http.StatusOK, gin.H{"message": "Stock toggled successfully"})

	}
}

func (ga *GoApp) AddToWishList() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		user_id := ctx.MustGet("UID").(primitive.ObjectID)

		var Input struct {
			ProductID primitive.ObjectID `json:"product_id"`
		}

		if err := ctx.ShouldBindJSON(&Input); err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}

		ok, err := ga.DB.AddProductToWishlist(Input.ProductID, user_id)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if !ok {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ga.App.InfoLogger.Println("Product added to wishlist successfully")

		ctx.JSON(http.StatusOK, gin.H{"message": "Product added to wishlist successfully"})

	}
}

func (ga *GoApp) RemoveFromWishList() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		user_id := ctx.MustGet("UID").(primitive.ObjectID)

		var Input struct {
			ProductID primitive.ObjectID `json:"product_id"`
		}

		if err := ctx.ShouldBindJSON(&Input); err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}

		ok, err := ga.DB.RemoveProductFromWishlist(Input.ProductID, user_id)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if !ok {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ga.App.InfoLogger.Println("Product removed from wishlist successfully")

		ctx.JSON(http.StatusOK, gin.H{"message": "Product removed from wishlist successfully"})
	}
}

func (ga *GoApp) Get_Single_Product() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		var Input struct {
			ProductID primitive.ObjectID `json:"product_id"`
		}

		if err := ctx.ShouldBindJSON(&Input); err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}

		product, err := ga.DB.GetSingleProduct(Input.ProductID)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if product == nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ctx.JSON(http.StatusOK, gin.H{"data": product, "message": "Product fetched successfully"})
	}
}

func (ga *GoApp) Add_To_Cart() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		user_id := ctx.MustGet("UID").(primitive.ObjectID)

		var cartitem *model.CartItems

		if err := ctx.ShouldBindJSON(&cartitem); err != nil {
			ga.App.ErrorLogger.Println("There is some problem in binding json : ", err)
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}

		productID := cartitem.ProductID
		prdID, err := primitive.ObjectIDFromHex(productID.Hex())

		if err != nil {
			ga.App.ErrorLogger.Println("There is some problem in getting product id : ", err)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}
		cartitem.ProductID = prdID

		ok, err := ga.DB.AddToCart(user_id, cartitem)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if !ok {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ga.App.InfoLogger.Println("Product added to cart successfully")

		ctx.JSON(http.StatusOK, gin.H{"message": "Product added to cart successfully"})

	}
}

func (ga *GoApp) Empty_Cart() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		user_id := ctx.MustGet("UID").(primitive.ObjectID)

		ok, err := ga.DB.Empty_the_Cart(user_id)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if !ok {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ga.App.InfoLogger.Println("Cart emptied successfully")

		ctx.JSON(http.StatusOK, gin.H{"message": "Cart emptied successfully"})
	}
}

func (ga *GoApp) Remove_From_Cart() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		user_id := ctx.MustGet("UID").(primitive.ObjectID)

		var Input struct {
			ProductID primitive.ObjectID `json:"product_id"`
		}

		if err := ctx.ShouldBindJSON(&Input); err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}

		ok, err := ga.DB.RemoveFromCart(user_id, Input.ProductID)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if !ok {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ga.App.InfoLogger.Println("Product Removed from cart successfully")

		ctx.JSON(http.StatusOK, gin.H{"message": "Product Removed from cart successfully"})

	}
}

func (ga *GoApp) Get_User_By_Id() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		user_id := ctx.MustGet("UID").(primitive.ObjectID)

		fmt.Println("User id : ", user_id)

		user, err := ga.DB.GetUserByID(user_id)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if user == nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ga.App.InfoLogger.Println("User fetched successfully : ", user)

		ctx.JSON(http.StatusOK, gin.H{"data": user, "message": "User fetched successfully"})
	}
}

func (ga *GoApp) Get_All_Users() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		users, err := ga.DB.GetAllUsers()

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if users == nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ctx.JSON(http.StatusOK, gin.H{"data": users, "message": "Users fetched successfully"})
	}
}

func (ga *GoApp) Get_All_Categories() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		categories, err := ga.DB.GetAllCategories()

		fmt.Println("Categories : ", categories)

		if err != nil {
			fmt.Println("We have reached here!")
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if categories == nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ctx.JSON(http.StatusOK, gin.H{"data": categories, "message": "Categories fetched successfully"})
	}
}

func (ga *GoApp) Initialize_User() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		userId := ctx.MustGet("UID").(primitive.ObjectID)

		status, er := ga.DB.InitializeUser(userId)

		if er != nil {
			ga.App.ErrorLogger.Println("There is some problem in initializing user : ", er)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: er})
		}

		if !status {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: er})
		}

		ga.App.InfoLogger.Println("User initialized successfully")

	}
}

func (ga *GoApp) FetchDetailsfromMail() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var Input struct {
			Email string `json:"email"`
		}

		if err := ctx.ShouldBindJSON(&Input); err != nil {
			ga.App.ErrorLogger.Println("There is some problem in binding json : ", err)
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}

		data, err := ga.DB.FindUserWithEmail(Input.Email)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if data == nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ctx.JSON(http.StatusOK, gin.H{"data": data, "message": "User fetched successfully"})
	}
}

func (ga *GoApp) Create_Order() gin.HandlerFunc {

	return func(ctx *gin.Context) {

		var order *model.Order

		if err := ctx.ShouldBindJSON(&order); err != nil {
			ga.App.ErrorLogger.Println("There is some problem in binding json : ", err)
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}

		order.CreatedAt = time.Now()
		order.UpdatedAt = time.Now()

		order.ID = primitive.NewObjectID()

		check, err := ga.DB.InsertOrdertoUser(order.CustomerID, order.ID)

		if err != nil {
			ga.App.ErrorLogger.Println("There is some problem in creating order : ", err)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if !check {
			ga.App.ErrorLogger.Println("There is some problem in creating order : ", err)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ga.App.InfoLogger.Println("Order added to user's order list successfully")

		res, err := ga.DB.CreateOrder(order)

		if err != nil {
			ga.App.ErrorLogger.Println("There is some problem in creating order : ", err)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if res == nil {
			ga.App.ErrorLogger.Println("There is some problem in creating order : ", err)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ga.App.InfoLogger.Println("Order created successfully", res)

		txn_Id := res["transaction_id"].(primitive.ObjectID)

		ok, err := ga.DB.UpdatePaymentToIncludeOrderId(txn_Id, order.ID)

		if err != nil {
			ga.App.ErrorLogger.Println("There is some problem in creating order : ", err)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if !ok {
			ga.App.ErrorLogger.Println("There is some problem in creating order : ", err)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ctx.JSON(http.StatusOK, gin.H{"message": "Order created successfully", "data": res})
	}
}

func (ga *GoApp) Get_User_Orders() gin.HandlerFunc {

	return func(ctx *gin.Context) {

		userId := ctx.MustGet("UID").(primitive.ObjectID)

		if userId == primitive.NilObjectID {
			ga.App.ErrorLogger.Println("There is some problem in getting user id from the param")
		}

		fmt.Println("User id : ", userId)

		orders, err := ga.DB.GetUserOrders(userId)

		if err != nil {
			ga.App.ErrorLogger.Println("There is some problem in getting user orders : ", err)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if orders == nil {
			ga.App.ErrorLogger.Println("There is some problem in getting user orders as orders are nil : ", err)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ga.App.InfoLogger.Println("Orders fetched successfully : ", orders)

		ctx.JSON(http.StatusOK, gin.H{"data": orders, "message": "Orders fetched successfully"})
	}
}

func (ga *GoApp) Get_All_Orders() gin.HandlerFunc {

	return func(ctx *gin.Context) {

		orders, err := ga.DB.GetAllOrders()

		if err != nil {
			ga.App.ErrorLogger.Println("There is some problem in getting user orders : ", err)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if orders == nil {
			ga.App.ErrorLogger.Println("There is some problem in getting user orders as orders are nil : ", err)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ga.App.InfoLogger.Println("Orders fetched successfully : ", orders)

		ctx.JSON(http.StatusOK, gin.H{"data": orders, "message": "Orders fetched successfully"})
	}
}

func (ga *GoApp) DeleteProduct() gin.HandlerFunc {

	return func(ctx *gin.Context) {

		id := ctx.Param("id")

		if id == "" {

			ga.App.ErrorLogger.Println("There is some problem in getting product id from the param")
			return
		}

		idObj, _ := primitive.ObjectIDFromHex(id)
		ok, err := ga.DB.DeleteProduct(idObj)

		if err != nil {
			ga.App.ErrorLogger.Println("There is some problem in deleting product : ", err)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if !ok {
			ga.App.ErrorLogger.Println("There is some problem in deleting product : ", err)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ctx.JSON(http.StatusOK, gin.H{"message": "Product deleted successfully"})
	}
}

func (ga *GoApp) DeleteOrder() gin.HandlerFunc {

	return func(ctx *gin.Context) {

		id := ctx.Param("id")

		if id == "" {

			ga.App.ErrorLogger.Println("There is some problem in getting order id from the param")
			return
		}

		idObj, _ := primitive.ObjectIDFromHex(id)
		ok, err := ga.DB.DeleteOrder(idObj)

		if err != nil {
			ga.App.ErrorLogger.Println("There is some problem in deleting order : ", err)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if !ok {
			ga.App.ErrorLogger.Println("There is some problem in deleting order : ", err)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ctx.JSON(http.StatusOK, gin.H{"message": "Order deleted successfully"})
	}
}

func (ga *GoApp) Payment_Creation() gin.HandlerFunc {

	return func(ctx *gin.Context) {

		var payment *model.Payment

		if err := ctx.ShouldBindJSON(&payment); err != nil {
			ga.App.ErrorLogger.Println("There is some problem in binding json : ", err)
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}

		payment.ID = primitive.NewObjectID()
		payment.CreatedAt = time.Now()
		payment.UpdatedAt = time.Now()

		payment_details, err := ga.DB.PaymentCreation(payment)

		if err != nil {
			ga.App.ErrorLogger.Println("There is some problem in creating payment : ", err)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if payment_details == nil {
			ga.App.ErrorLogger.Println("There is some problem in creating payment : ", err)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ctx.JSON(http.StatusOK, gin.H{"message": "Payment created successfully", "data": payment_details})
	}
}

func (ga *GoApp) Shipment_Creation() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		var shipment *model.Shipment
		if err := ctx.ShouldBindJSON(&shipment); err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}

		shipment.ID = primitive.NewObjectID()

		shipment.CreatedAt = time.Now()
		shipment.UpdatedAt = time.Now()
		shipment.Shipment_Date = time.Now()

		shipment_details, err := ga.DB.ShipmentCreation(shipment)

		if err != nil {
			ga.App.ErrorLogger.Println("There is some problem in creating shipment : ", err)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if shipment_details == nil {
			ga.App.ErrorLogger.Println("There is some problem in creating shipment : ", err)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ctx.JSON(http.StatusOK, gin.H{"message": "Shipment created successfully", "data": shipment_details})
	}
}

func (ga *GoApp) Add_Address() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		var Input struct {
			UserId  primitive.ObjectID `json:"user_id"`
			Address *model.Address     `json:"address"`
		}

		if err := ctx.ShouldBindJSON(&Input); err != nil {
			ga.App.ErrorLogger.Println("There is some problem in binding json : ", err)
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}

		ok, err := ga.DB.AddAddress(Input.UserId, Input.Address)

		if err != nil {
			ga.App.ErrorLogger.Println("There is some problem in adding address : ", err)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if !ok {
			ga.App.ErrorLogger.Println("There is some problem in adding address : ", err)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ctx.JSON(http.StatusOK, gin.H{"message": "Address added successfully"})
	}
}

func (ga *GoApp) Get_All_Payments() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		payments, err := ga.DB.GetAllPayments()

		if err != nil {
			ga.App.ErrorLogger.Println("There is some problem in getting all payments : ", err)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if payments == nil {
			ga.App.ErrorLogger.Println("There is some problem in getting all payments : ", err)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		ctx.JSON(http.StatusOK, gin.H{"message": "All payments fetched successfully", "data": payments})
	}
}

func (ga *GoApp) CreateCSE() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Parse the request body
		var cse *model.CSE

		err := ctx.ShouldBindJSON(&cse)
		if err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{
				Err: err,
			})
		}
		// Set up the CSE object with initial values		cse.Password = hashedPassword
		cse.CreatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		cse.UpdatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		cse.Password, _ = encrypt.Hash(cse.Password)
		cse.Status = "offline"
		cse.ActiveChats = []primitive.ObjectID{}
		cse.PendingChats = []primitive.ObjectID{}
		cse.ClosedChats = []primitive.ObjectID{}
		cse.ActiveChatsCount = 0
		cse.PendingChatsCount = 0

		// Insert into database

		fmt.Printf("Inserting CSE: %v\n", cse)

		fmt.Printf("Information sent :- ")
		fmt.Printf("ID: %v\n", cse.ID)
		fmt.Printf("Name: %v\n", cse.Name)
		fmt.Printf("Email: %v\n", cse.Email)
		fmt.Printf("Password: %v\n", cse.Password)
		fmt.Printf("Phone: %v\n", cse.PhoneNumber)
		fmt.Printf("Status: %v\n", cse.Status)
		fmt.Printf("ActiveChats: %v\n", cse.ActiveChats)
		fmt.Printf("PendingChats: %v\n", cse.PendingChats)
		fmt.Printf("ClosedChats: %v\n", cse.ClosedChats)
		fmt.Printf("ActiveChatsCount: %v\n", cse.ActiveChatsCount)
		fmt.Printf("PendingChatsCount: %v\n", cse.PendingChatsCount)
		fmt.Printf("CreatedAt: %v\n", cse.CreatedAt)
		fmt.Printf("UpdatedAt: %v\n", cse.UpdatedAt)

		fmt.Printf("CSE Object:- \nCSE_ID: %v\nPassword: %v\nName: %v\nPhone_Number: %v\nEmail: %v\n", cse.CseID, cse.Password, cse.Name, cse.PhoneNumber, cse.Email)
		// Insert CSE into database
		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if err := ga.App.Validate.Struct(&cse); err != nil {
			if _, ok := err.(*validator.InvalidValidationError); !ok {
				_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
				ga.App.InfoLogger.Println(err)
				return
			}
		}

		ok, status, err := ga.DB.InsertCSE(cse)

		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, errors.New("error while adding new CSE"))
			ctx.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			return
		}

		if !ok {
			_ = ctx.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		switch status {
		case 1:
			{
				ctx.JSON(http.StatusCreated, gin.H{"message": "CSE created successfully"})
			}
		case 2:
			{
				ctx.JSON(http.StatusConflict, gin.H{"message": "CSE already exists"})
			}
		}
	}
}

func (ga *GoApp) GetAllCSEData() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		cses, err := ga.DB.GetAllCSEs()
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get CSEs"})
			ga.App.ErrorLogger.Printf("Error getting CSEs: %v", err)
			return
		}
		ctx.JSON(http.StatusOK, gin.H{
			"message": "CSEs fetched successfully",
			"data":    cses,
		})
	}
}

func (ga *GoApp) CSELogin() gin.HandlerFunc {
	return func(ctx *gin.Context) {

		var cse *model.CSE
		if err := ctx.ShouldBindJSON(&cse); err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{Err: err})
		}

		// Get CSE from database
		res, err := ga.DB.GetCSEByCredentials(cse.CseID)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		fmt.Print("cse from DB : ", res)

		id := res["_id"].(primitive.ObjectID)
		password := res["password"].(string)

		fmt.Printf("ID: %v\n", id)
		fmt.Printf("Password: %v\n", password)

		verified, err := encrypt.VerifyPassword(cse.Password, password)
		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, err)
			ctx.JSON(http.StatusUnauthorized, gin.H{"message": "unregistered cse detected using wrong password"})
			return
		}

		if verified {

			cookieData := sessions.Default(ctx)

			cseInfo := map[string]interface{}{
				"ID":    id,
				"Email": cse.Email,
				"Name":  res["name"],
			}

			cookieData.Set("cseInfo", cseInfo)

			if err := cookieData.Save(); err != nil {
				_ = ctx.AbortWithError(http.StatusInternalServerError, err)
				ctx.JSON(http.StatusInternalServerError, gin.H{"message": "error while saving cookie"})
				return
			}

			t1, t2, err := auth.Generate(res["email"].(string), id, res["name"].(string))

			if err != nil {
				_ = ctx.AbortWithError(http.StatusInternalServerError, err)
				ctx.JSON(http.StatusInternalServerError, gin.H{"message": "error while generating tokens"})
				return
			}

			cookieData.Set("cse_token", t1)

			if err := cookieData.Save(); err != nil {
				_ = ctx.AbortWithError(http.StatusInternalServerError, err)
				ctx.JSON(http.StatusInternalServerError, gin.H{"message": "error while saving cookie"})
				return
			}

			cookieData.Set("new_cse_token", t2)

			if err := cookieData.Save(); err != nil {
				_ = ctx.AbortWithError(http.StatusInternalServerError, err)
				ctx.JSON(http.StatusInternalServerError, gin.H{"message": "error while saving cookie"})
				return
			}

			err = ga.DB.UpdateCSEStatus(id, "online")
			if err != nil {
				ga.App.ErrorLogger.Printf("Error updating CSE status: %v", err)
				// Continue anyway, as login was successful
			}

			ctx.JSON(http.StatusOK, gin.H{
				"message":       "Successfully Logged in",
				"email":         res["email"],
				"id":            id,
				"name":          res["name"],
				"session_token": t1,
				"cse_id":        cse.CseID,
				"phone_number":  res["phone_number"],
			})
		} else {
			ctx.JSON(http.StatusUnauthorized, gin.H{"message": "unregistered admin detected using wrong credentials"})
			return
		}
	}
}

// Also add a logout handler
func (ga *GoApp) CSELogout() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Get CSE ID from context (set by middleware)
		uidInterface, exists := ctx.Get("UID")
		if !exists {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		fmt.Print("uidInterface : ", uidInterface)

		uid := uidInterface.(primitive.ObjectID)
		// Update CSE status to offline
		err := ga.DB.UpdateCSEStatus(uid, "offline")
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update status"})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
	}
}

func (ga *GoApp) CreateChat() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Parse request body
		var chat *model.Chat

		err := ctx.ShouldBindJSON(&chat)
		if err != nil {
			_ = ctx.AbortWithError(http.StatusBadRequest, gin.Error{
				Err: err,
			})
		}

		fmt.Print("Chat in phase 1(input): ", chat)

		chat.DateCreated, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		chat.LastMessageTime, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		chat.Messages = []primitive.ObjectID{}
		chat.Status = "waiting"
		// Create the chat
		chatID, err := ga.DB.CreateChat(chat)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create chat"})
			return
		}
		// Return success response
		ctx.JSON(http.StatusCreated, gin.H{
			"message": "Chat created successfully",
			"chat_id": chatID.Hex(),
		})

		go ga.AssignChatToCSE(chatID)

		// Start a goroutine to find an available CSE (we'll implement this later// go ga.assignChatToCSE(chatID)
	}
}

func (ga *GoApp) Get_All_The_Orders() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		orders, err := ga.DB.GetAllTheOrders()
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get orders"})
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"orders": orders})
	}
}

// Add this function to your GoApp struct
func (ga *GoApp) AssignChatToCSE(chatID primitive.ObjectID) {
	// Create a ticker that ticks every 5 seconds
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Set a timeout of 1 hour (in case no CSE becomes available)
	timeout := time.After(1 * time.Hour)

	for {
		select {
		case <-ticker.C:
			// Check if the chat is still in waiting status
			chat, err := ga.DB.GetChatByID(chatID)
			if err != nil {
				ga.App.ErrorLogger.Printf("Error getting chat %s: %v", chatID.Hex(), err)
				return
			}

			// If chat is no longer waiting, exit the goroutine
			if chat.Status != "waiting" {
				return
			}

			// Get all available CSEs
			cses, err := ga.DB.GetAvailableCSEs()
			if err != nil {
				ga.App.ErrorLogger.Printf("Error getting available CSEs: %v", err)
				continue
			}

			if len(cses) == 0 {
				ga.App.InfoLogger.Println("No CSEs available, will try again later")
				continue
			}

			// Find the most available CSE
			assigned := false
			for _, cse := range cses {
				if cse.ActiveChatsCount < 5 {
					// Assign to active chats
					err = ga.DB.AssignChatToCSE(chatID, cse.ID, true)
					if err == nil {
						ga.App.InfoLogger.Printf("Chat %s assigned to CSE %s as active", chatID.Hex(), cse.ID.Hex())
						assigned = true
						break
					}
				} else if cse.PendingChatsCount < 10 {
					// Assign to pending chats
					err = ga.DB.AssignChatToCSE(chatID, cse.ID, false)
					if err == nil {
						ga.App.InfoLogger.Printf("Chat %s assigned to CSE %s as pending", chatID.Hex(), cse.ID.Hex())
						assigned = true
						break
					}
				}
			}

			if assigned {
				return
			}

		case <-timeout:
			// If we've been trying for an hour with no success, log and exit
			ga.App.ErrorLogger.Printf("Timeout reached for chat %s, no CSE available after 1 hour", chatID.Hex())
			return
		}
	}
}

// Send a message (can be used by both user and CSE)
func (ga *GoApp) SendMessageAsUser() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Get user ID from context (set by middleware)
		// Parse request body
		var input struct {
			ChatID     string `json:"chat_id" binding:"required"`
			Text       string `json:"text" binding:"required"`
			ReceiverID string `json:"receiver_id" binding:"required"`
			SenderID   string `json:"sender_id" binding:"required"`
		}

		if err := ctx.ShouldBindJSON(&input); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		fmt.Print("Chat in phase 1(input): ", input)

		chatID, err := primitive.ObjectIDFromHex(input.ChatID)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid chat ID format"})
			return
		}

		receiverID, err := primitive.ObjectIDFromHex(input.ReceiverID)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid receiver ID format"})
			return
		}

		senderID, err := primitive.ObjectIDFromHex(input.SenderID)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid sender ID format"})
			return
		}

		fmt.Print("Chat in phase 2(input): ", input)
		// Get chat to verify access
		chat, err := ga.DB.GetChatByID(chatID)
		if err != nil {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "Chat not found"})
			return
		}

		fmt.Print("Chat in phase 3(input): ", input)

		// Verify that the user has access to this chat
		if chat.UserID != senderID {
			ctx.JSON(http.StatusForbidden, gin.H{"error": "You don't have access to this chat"})
			return
		}
		// Verify chat status
		if chat.Status == "closed" {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Cannot send messages to a closed chat"})
			return
		}
		// If chat is pending and CSE is sending a message, move it to activ
		// Create and add the message
		message := &model.Message{
			Text:       input.Text,
			ChatID:     chatID,
			SenderID:   senderID,
			ReceiverID: receiverID,
		}

		fmt.Print("Chat in phase 4(input): ", input)

		messageID, err := ga.DB.AddMessage(message)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send message"})
			return
		}

		fmt.Print("Chat in phase 5(input): ", input)

		ctx.JSON(http.StatusCreated, gin.H{
			"message":    "Message sent successfully",
			"message_id": messageID.Hex(),
		})
	}
}
func (ga *GoApp) SendMessageAsCSE() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Get user ID from context (set by middleware)
		// Parse request body
		var input struct {
			ChatID     string `json:"chat_id" binding:"required"`
			Text       string `json:"text" binding:"required"`
			ReceiverID string `json:"receiver_id" binding:"required"`
			SenderID   string `json:"sender_id" binding:"required"`
		}

		if err := ctx.ShouldBindJSON(&input); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		fmt.Print("Chat in phase 1(input): ", input)

		chatID, err := primitive.ObjectIDFromHex(input.ChatID)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid chat ID format"})
			return
		}

		receiverID, err := primitive.ObjectIDFromHex(input.ReceiverID)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid receiver ID format"})
			return
		}

		senderID, err := primitive.ObjectIDFromHex(input.SenderID)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid sender ID format"})
			return
		}

		fmt.Print("Chat in phase 2: ", chatID, receiverID, senderID)

		// Get chat to verify access
		chat, err := ga.DB.GetChatByID(chatID)
		if err != nil {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "Chat not found"})
			return
		}

		fmt.Print("Chat in phase 3: ", chat)

		// Verify that the user has access to this chat
		if chat.CseID != senderID {
			ctx.JSON(http.StatusForbidden, gin.H{"error": "You don't have access to this chat"})
			return
		}
		// Verify chat status
		if chat.Status == "closed" || chat.Status == "pending" {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Cannot send messages to a closed or pending chat"})
			return
		}
		// If chat is pending and CSE is sending a message, move it to activ
		// Create and add the message
		message := &model.Message{
			Text:       input.Text,
			ChatID:     chatID,
			SenderID:   senderID,
			ReceiverID: receiverID,
		}

		fmt.Print("Chat in phase 4: ", message)

		messageID, err := ga.DB.AddMessage(message)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send message"})
			return
		}

		fmt.Print("Chat in phase 5: ", messageID)

		ctx.JSON(http.StatusCreated, gin.H{
			"message":    "Message sent successfully",
			"message_id": messageID.Hex(),
		})
	}
}

// Get chat history
func (ga *GoApp) GetChatHistory() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Get user ID from context (set by middleware)// Get chat ID from URL parameter
		chatID, err := primitive.ObjectIDFromHex(ctx.Param("id"))
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid chat ID format"})
			return
		}

		fmt.Print("Chat in phase 1: ", chatID)
		// Get chat to verify access
		chat, err := ga.DB.GetChatByID(chatID)
		if err != nil {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "Chat not found"})
			return
		}

		// Verify that the user has access to this chat
		fmt.Print("Chat in phase 2: ", chat)
		// Get messages for this chat
		messages, err := ga.DB.GetMessagesByChat(chatID)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve chat history"})
			return
		}

		fmt.Print("Chat in phase 3: ", messages)

		ctx.JSON(http.StatusOK, gin.H{
			"chat_id":  chatID.Hex(),
			"status":   chat.Status,
			"messages": messages,
		})
	}
}

package handler

import (
	"errors"
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

				if err := cookieData.Save(); err != nil {
					_ = ctx.AbortWithError(http.StatusInternalServerError, err)
					ctx.JSON(http.StatusInternalServerError, gin.H{"message": "error while saving cookie"})
					return
				}

				cookieData.Set("new_token", t2)

				if err := cookieData.Save(); err != nil {
					_ = ctx.AbortWithError(http.StatusInternalServerError, err)
					ctx.JSON(http.StatusInternalServerError, gin.H{"message": "error while saving cookie"})
					return
				}

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
				ctx.JSON(http.StatusUnauthorized, gin.H{"message": "unregistered user detected using wrong credentials"})
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

		ok, err := ga.DB.UpdatePaymentToIncludeOrderId(order.TransactionID, order.ID)

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

func (ga *GoApp) Get_All_Orders() gin.HandlerFunc {

	return func(ctx *gin.Context) {

		orders, err := ga.DB.GetAllOrders()

		if err != nil {
			ga.App.ErrorLogger.Println("There is some problem in getting all orders : ", err)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

		if orders == nil {
			ga.App.ErrorLogger.Println("There is some problem in getting all orders as orders are nil : ", err)
			_ = ctx.AbortWithError(http.StatusInternalServerError, gin.Error{Err: err})
		}

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

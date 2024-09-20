package main

import (
	"github.com/PraveenRajPurak/CarsGo-Backend/handler"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func Routes(r *gin.Engine, g *handler.GoApp) {
	router := r.Use(gin.Logger(), gin.Recovery())

	userCookieStore := cookie.NewStore([]byte("user_cookie"))
	adminCookieStore := cookie.NewStore([]byte("admin_cookie"))
	router.Use(sessions.Sessions("user_session", userCookieStore))

	router.GET("/", g.Home())

	router.POST("/sign-up", g.Sign_Up())
	router.POST("/sign-in", g.Sign_In())
	router.POST("/get-single-product", g.Get_Single_Product())
	router.GET("/get-all-users", g.Get_All_Users())

	router.POST("/sign-up-admin", g.Sign_Up_Admin())
	router.POST("/sign-in-admin", sessions.Sessions("admin_session", adminCookieStore), g.Sign_In_Admin())

	protectedUsers := r.Group("/users")
	protectedUsers.Use(Authorisation())

	protectedUsers.POST("/forgot-password", g.ForgotPasswordUser())
	protectedUsers.GET("/view-products", g.ViewProducts())
	protectedUsers.POST("update-email", g.Update_Email_User())
	protectedUsers.POST("update-name", g.Update_Name_User())
	protectedUsers.POST("update-phone", g.Update_Phone_User())
	protectedUsers.POST("sign-out", g.SignOutUser())
	protectedUsers.POST("add-to-wishlist", g.AddToWishList())
	protectedUsers.POST("remove-from-wishlist", g.RemoveFromWishList())
	protectedUsers.POST("add-to-cart", g.Add_To_Cart())
	protectedUsers.POST("remove-from-cart", g.Remove_From_Cart())
	protectedUsers.POST("initialize-user", g.Initialize_User())
	protectedUsers.POST("place-order", g.Create_Order())
	protectedUsers.POST("payment-creation", g.Payment_Creation())
	protectedUsers.POST("shipment-creation", g.Shipment_Creation())

	protectedAdmin := r.Group("/admin")
	protectedAdmin.Use(sessions.Sessions("admin_session", adminCookieStore))
	protectedAdmin.Use(Admin_Authorisation())
	protectedAdmin.POST("forgot-password", g.ForgotPasswordAdmin())
	protectedAdmin.POST("create-category", g.CreateCategory())
	protectedAdmin.POST("create-product", g.InsertProducts())
	protectedAdmin.GET("view-products", g.ViewProducts())
	protectedAdmin.POST("update-product", g.UpdateProduct())
	protectedAdmin.POST("toggle-stock", g.ToggleStock())
	protectedAdmin.POST("update-email", g.Update_Email_Admin())
	protectedAdmin.POST("update-name", g.Update_Name_Admin())
	protectedAdmin.POST("update-phone", g.Update_Phone_Admin())
	protectedAdmin.POST("sign-out", g.SignOutAdmin())
	protectedAdmin.POST("place-order", g.Create_Order())
	protectedAdmin.GET("view-orders", g.Get_All_Orders())
	protectedAdmin.DELETE("delete-product/:id", g.DeleteProduct())
	protectedAdmin.POST("payment-creation", g.Payment_Creation())
	protectedAdmin.DELETE("delete-order/:id", g.DeleteOrder())

}
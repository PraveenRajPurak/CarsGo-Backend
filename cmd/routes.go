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
	cseCookieStore := cookie.NewStore([]byte("cse_cookie"))
	router.Use(sessions.Sessions("user_session", userCookieStore))

	router.GET("/", g.Home())

	router.POST("/sign-up", g.Sign_Up())
	router.POST("/sign-in", g.Sign_In())
	router.POST("/cse_login", g.CSELogin())
	router.POST("/get-single-product", g.Get_Single_Product())
	router.GET("/get-all-users", g.Get_All_Users())
	router.GET("/get-all-payments", g.Get_All_Payments())
	router.GET("/get-all-categories", g.Get_All_Categories())
	router.GET("/view-all-products", g.ViewProducts())
	router.GET("/get-cses", g.GetAllCSES())

	router.POST("/sign-up-admin", g.Sign_Up_Admin())
	router.POST("/sign-in-admin", sessions.Sessions("admin_session", adminCookieStore), g.Sign_In_Admin())

	protectedUsers := r.Group("/users")
	protectedUsers.Use(Authorisation())

	protectedUsers.POST("/forgot-password", g.ForgotPasswordUser())
	protectedUsers.POST("update-email", g.Update_Email_User())
	protectedUsers.POST("update-name", g.Update_Name_User())
	protectedUsers.POST("update-phone", g.Update_Phone_User())
	protectedUsers.POST("sign-out", g.SignOutUser())
	protectedUsers.POST("add-to-wishlist", g.AddToWishList())
	protectedUsers.POST("remove-from-wishlist", g.RemoveFromWishList())
	protectedUsers.POST("add-to-cart", g.Add_To_Cart())
	protectedUsers.POST("empty-cart", g.Empty_Cart())
	protectedUsers.POST("remove-from-cart", g.Remove_From_Cart())
	protectedUsers.POST("add-address", g.Add_Address())
	protectedUsers.POST("initialize-user", g.Initialize_User())
	protectedUsers.POST("place-order", g.Create_Order())
	protectedUsers.POST("payment-creation", g.Payment_Creation())
	protectedUsers.POST("shipment-creation", g.Shipment_Creation())
	protectedUsers.GET("get-user-by-id", g.Get_User_By_Id())
	protectedUsers.GET("get-user-orders", g.Get_User_Orders())

	protectedAdmin := r.Group("/admin")
	protectedAdmin.Use(sessions.Sessions("admin_session", adminCookieStore))
	protectedAdmin.Use(Admin_Authorisation())
	protectedAdmin.POST("forgot-password", g.ForgotPasswordAdmin())
	protectedAdmin.POST("create-category", g.CreateCategory())
	protectedAdmin.POST("create-product", g.InsertProducts())
	protectedAdmin.POST("create-products", g.InsertMultipleProducts())
	protectedAdmin.POST("change-stock", g.Change_Stock())
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
	protectedAdmin.POST("/create-cse", g.CreateCSE())

	protectedCSE := r.Group("/cse")
	protectedCSE.Use(sessions.Sessions("cse_session", cseCookieStore))
	protectedCSE.Use(CSE_Authorisation())
	protectedCSE.POST("/logout", g.CSELogout())
}

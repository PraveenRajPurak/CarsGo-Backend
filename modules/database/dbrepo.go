package database

import (
	"github.com/PraveenRajPurak/CarsGo-Backend/modules/model"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type DBRepo interface {
	InsertUser(user *model.User) (bool, int, error)
	VerifyUser(email string) (primitive.M, error)
	UpdateUser(userID primitive.ObjectID, tk map[string]string) (bool, error)
	CreateNewPassword(email string, password string) (bool, error)
	InsertProduct(product *model.Product) (bool, int, error)
	Update_Stock(id primitive.ObjectID, new_stock int) (bool, error)
	ViewProducts() ([]primitive.M, error)
	CreateCategory(category *model.Category) (bool, int, error)
	SignUpAdmin(admin *model.Admin) (bool, int, error)
	VerifyAdmin(email string) (primitive.M, error)
	UpdateAdmin(userID primitive.ObjectID, tk map[string]string) (bool, error)
	SignOutAdmin(adminID primitive.ObjectID) (bool, error)
	SignOutUser(userID primitive.ObjectID) (bool, error)
	CreateNewPasswordAdmin(email string, password string) (bool, error)
	UpdateEmailUser(current_email string, new_email string) (bool, error)
	UpdateEmailAdmin(current_email string, new_email string) (bool, error)
	UpdateNameUser(email string, new_name string) (bool, error)
	UpdateNameAdmin(email string, new_name string) (bool, error)
	UpdatePhoneUser(email string, new_phone string) (bool, error)
	UpdatePhoneAdmin(email string, new_phone string) (bool, error)
	UpdateProduct(product *model.Product) (bool, error)
	Toggle_Stock(productID primitive.ObjectID) (bool, error)
	AddProductToWishlist(Product_Id primitive.ObjectID, User_Id primitive.ObjectID) (bool, error)
	RemoveProductFromWishlist(Product_Id primitive.ObjectID, User_Id primitive.ObjectID) (bool, error)
	GetSingleProduct(Id primitive.ObjectID) (primitive.M, error)
	AddToCart(userID primitive.ObjectID, cartItems *model.CartItems) (bool, error)
	Empty_the_Cart(userID primitive.ObjectID) (bool, error)
	RemoveFromCart(userID primitive.ObjectID, productID primitive.ObjectID) (bool, error)
	GetAllUsers() ([]primitive.M, error)
	InitializeUser(userId primitive.ObjectID) (bool, error)
	CreateOrder(order *model.Order) (primitive.M, error)
	FindUserWithEmail(name string) (primitive.M, error)
	GetAllOrders() ([]primitive.M, error)
	DeleteProduct(id primitive.ObjectID) (bool, error)
	DeleteOrder(id primitive.ObjectID) (bool, error)
	InsertOrdertoUser(userID primitive.ObjectID, OrderId primitive.ObjectID) (bool, error)
	ShipmentCreation(shipment *model.Shipment) (primitive.M, error)
	PaymentCreation(payment *model.Payment) (primitive.M, error)
	GetAllShipments() ([]primitive.M, error)
	UpdatePaymentToIncludeOrderId(paymentId primitive.ObjectID, orderId primitive.ObjectID) (bool, error)
	AddAddress(userId primitive.ObjectID, address *model.Address) (bool, error)
	GetAllPayments() ([]primitive.M, error)
	GetAllCategories() ([]primitive.M, error)
	GetUserByID(userId primitive.ObjectID) (primitive.M, error)
	GetUserOrders(userId primitive.ObjectID) ([]primitive.M, error)
	InsertMultipleProductsBulk(products []*model.Product) (int, int, error)
	InsertCSE(cse *model.CSE) (bool, int, error)
	GetAllCSEs() ([]primitive.M, error)
	GetCSEByCredentials(cseID string) (primitive.M, error)
	UpdateCSEStatus(id primitive.ObjectID, status string) error
	CreateChat(chat *model.Chat) (primitive.ObjectID, error)
	UpdateOrderWithChatID(orderID primitive.ObjectID, chatID primitive.ObjectID) error
	GetAllTheOrders() ([]primitive.M, error)
	GetAvailableCSEs() ([]model.CSE, error)
	AssignChatToCSE(chatID, cseID primitive.ObjectID, isActive bool) error
	GetChatByID(chatID primitive.ObjectID) (model.Chat, error)
	UpdateChatStatus(chatID primitive.ObjectID, status string) error
	AddMessage(message *model.Message) (primitive.ObjectID, error)
	GetMessagesByChat(chatID primitive.ObjectID) ([]model.Message, error)
	UpdateChatLastMessageTime(chatID primitive.ObjectID) error
	MoveChatFromPendingToActive(chatID, cseID primitive.ObjectID) error
	CloseChat(chatID primitive.ObjectID) error
	ReopenChat(chatID, userID primitive.ObjectID) error
	CloseIdleChats() error
	CreateReview(review *model.Review) (*model.Review, error)
	UpdateProductWithReview(productID primitive.ObjectID, review *model.Review) error
	GetReviewsByProductID(productID primitive.ObjectID) ([]model.Review, error)
	GetReviewsByCustomerID(customerID primitive.ObjectID) ([]model.Review, error)
	UpdateOrderWithRated(orderID primitive.ObjectID) error
	//DeleteReview(reviewID primitive.ObjectID) error
	UpdateProductSummarizedReview(productID primitive.ObjectID, summarizedReview string) error
}

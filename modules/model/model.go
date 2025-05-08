package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Address struct {
	AddressField string `json:"address_field"`
	City         string `json:"city"`
	State        string `json:"state"`
	Country      string `json:"country"`
	Pincode      string `json:"pincode"`
}

type User struct {
	ID        primitive.ObjectID   `json:"_id" bson:"_id"`
	Name      string               `json:"name" Usage:"required"`
	Email     string               `json:"email" Usage:"required"`
	Password  string               `json:"password" Usage:"required"`
	Token     string               `json:"token"`
	New_Token string               `json:"new_token"`
	Cart      []CartItems          `json:"cart"`
	Orders    []primitive.ObjectID `json:"orders"`
	Phone     string               `json:"phone"`
	Addresses []Address            `json:"addresses"`
	Payments  []primitive.ObjectID `json:"payments"`
	Shipments []primitive.ObjectID `json:"shipments"`
	Wishlist  []primitive.ObjectID `json:"wishlist"`
	CreatedAt time.Time            `json:"created_At"`
	UpdatedAt time.Time            `json:"updated_At"`
}

type CartItems struct {
	ProductID primitive.ObjectID `json:"product_id"`
	Quantity  int                `json:"quantity"`
}

type Category struct {
	ID                  primitive.ObjectID `json:"_id" bson:"_id"`
	Name                string             `json:"name" Usage:"required"`
	General_Description string             `json:"general_description" Usage:"required"`
	CategoryImage       string             `json:"category_image" Usage:"required"`
	CreatedAt           time.Time          `json:"created_At"`
	UpdatedAt           time.Time          `json:"updated_At"`
}

type Dimensions struct {
	Length string `json:"length"`
	Width  string `json:"width"`
	Height string `json:"height"`
}

type ProductDesc struct {
	FuelType        string     `json:"fuel_type"`
	Mileage         string     `json:"mileage"`
	Engine          string     `json:"engine"`
	PowerOutput     string     `json:"power_output"`
	SeatingCapacity string     `json:"seating_capacity"`
	Tyre            string     `json:"tyre"`
	TopSpeed        string     `json:"top_speed"`
	Dimension       Dimensions `json:"dimensions"`
	Weight          int        `json:"weight"`
}

type Review struct {
	ID         primitive.ObjectID `json:"_id" bson:"_id"`
	ProductID  primitive.ObjectID `json:"product_id"`
	Review     string             `json:"review"`
	Rating     int                `json:"rating"`
	CustomerID primitive.ObjectID `json:"customer_id"`
	CreatedAt  time.Time          `json:"created_At"`
}

type Product struct {
	ID                primitive.ObjectID `json:"_id" bson:"_id"`
	Name              string             `json:"name" Usage:"required"`
	Description       ProductDesc        `json:"description" Usage:"required"`
	Category          string             `json:"category" Usage:"required"`
	Company_Name      string             `json:"company_name" Usage:"required"`
	Model_Name        string             `json:"model_name" Usage:"required"`
	RegularPrice      int                `json:"regular_price" Usage:"required"`
	SalePrice         int                `json:"sale_price"`
	SaleStarts        time.Time          `json:"sale_starts"`
	SaleEnds          time.Time          `json:"sale_ends"`
	InStock           bool               `json:"in_stock" Usage:"required"`
	Stock             int                `json:"stock" Usage:"required"`
	SKU               string             `json:"sku" Usage:"required"`
	Images            []string           `json:"images" Usage:"required"`
	Reviews           []Review           `json:"reviews"`
	Overall_Rating    float32            `json:"rating"`
	Summarized_Review string             `json:"summarized_review"`
	CreatedAt         time.Time          `json:"created_At"`
	UpdatedAt         time.Time          `json:"updated_At"`
}

type OrderItem struct {
	ProductID primitive.ObjectID `json:"product_id"`
	Quantity  int                `json:"quantity"`
}

type OrderItems struct {
	OrderItems []OrderItem `json:"order_items"`
}

type Order struct {
	ID            primitive.ObjectID `json:"_id" bson:"_id"`
	OrderItems    OrderItems         `json:"order_items" bson:"order_items"`
	OrderAmount   int                `json:"order_amount" bson:"order_amount"`
	OrderDate     time.Time          `json:"order_date" bson:"order_date"`
	TransactionID primitive.ObjectID `json:"transaction_id" bson:"transaction_id"`
	OrderStatus   string             `json:"order_status" bson:"order_status"`
	CustomerID    primitive.ObjectID `json:"customer_id" bson:"customer_id"`
	ChatID        primitive.ObjectID `json:"chat_id" bson:"chat_id"`
	Rated         bool               `json:"rated" bson:"rated"`
	CreatedAt     time.Time          `json:"created_At"`
	UpdatedAt     time.Time          `json:"updated_At"`
}

type Shipment struct {
	ID                   primitive.ObjectID `json:"_id" bson:"_id"`
	OrderID              primitive.ObjectID `json:"order_id" bson:"order_id"`
	CustomerID           primitive.ObjectID `json:"customer_id" bson:"customer_id"`
	Phone                string             `json:"phone" bson:"phone"`
	Shipment_Company     string             `json:"shipment_company" bson:"shipment_company"`
	Source_Location      Address            `json:"source_location" bson:"source_location"`
	Destination_Location Address            `json:"destination_location" bson:"destination_location"`
	Shipment_Status      string             `json:"shipment_status" bson:"shipment_status"`
	Shipment_Date        time.Time          `json:"shipment_date" bson:"shipment_date"`
	CreatedAt            time.Time          `json:"created_At"`
	UpdatedAt            time.Time          `json:"updated_At"`
}

type Payment struct {
	ID           primitive.ObjectID `json:"_id" bson:"_id"`
	OrderID      primitive.ObjectID `json:"order_id" bson:"order_id"`
	PaidBy       primitive.ObjectID `json:"paid_by" bson:"paid_by"`
	Payment_Mode string             `json:"payment_type" bson:"payment_type"`
	Paid_Amount  int                `json:"paid_amount" bson:"paid_amount"`
	Paid_Date    time.Time          `json:"paid_date" bson:"paid_date"`
	CreatedAt    time.Time          `json:"created_At"`
	UpdatedAt    time.Time          `json:"updated_At"`
}

type Admin struct {
	ID        primitive.ObjectID `json:"_id" bson:"_id"`
	Name      string             `json:"name" Usage:"required"`
	Password  string             `json:"password" Usage:"required"`
	Address   Address            `json:"address" Usage:"required"`
	Website   string             `json:"website" Usage:"required"`
	Token     string             `json:"token" Usage:"required"`
	New_Token string             `json:"new_token" Usage:"required"`
	Email     string             `json:"email" Usage:"required"`
	Phone     string             `json:"phone" Usage:"required"`
	CreatedAt time.Time          `json:"created_At"`
	UpdatedAt time.Time          `json:"updated_At"`
}

type Ticket struct {
	ID           primitive.ObjectID `json:"_id" bson:"_id"`
	Generated_By primitive.ObjectID `json:"generated_by" bson:"generated_by"`
	Status       string             `json:"status" bson:"status"`
	Description  string             `json:"description" bson:"description"`
	CreatedAt    time.Time          `json:"created_At"`
	UpdatedAt    time.Time          `json:"updated_At"`
}

type CSE struct {
	ID                primitive.ObjectID   `json:"_id" bson:"_id"`
	CseID             string               `bson:"cse_id" json:"cse_id"`
	Password          string               `json:"password" Usage:"required"`
	Name              string               `bson:"name" json:"name"`
	PhoneNumber       string               `bson:"phone_number" json:"phone_number"`
	Email             string               `bson:"email" json:"email"`
	Status            string               `bson:"status" json:"status"` // "online" or "offline"
	ActiveChats       []primitive.ObjectID `bson:"active_chats" json:"active_chats"`
	PendingChats      []primitive.ObjectID `bson:"pending_chats" json:"pending_chats"`
	ClosedChats       []primitive.ObjectID `bson:"closed_chats" json:"closed_chats"`
	ActiveChatsCount  int                  `bson:"active_chats_count" json:"active_chats_count"`
	PendingChatsCount int                  `bson:"pending_chats_count" json:"pending_chats_count"`
	CreatedAt         time.Time            `bson:"created_at" json:"created_at"`
	UpdatedAt         time.Time            `bson:"updated_at" json:"updated_at"`
}

type Chat struct {
	ID              primitive.ObjectID   `bson:"_id,omitempty" json:"_id,omitempty"`
	DateCreated     time.Time            `bson:"date_created" json:"date_created"`
	DateClosed      time.Time            `bson:"date_closed,omitempty" json:"date_closed,omitempty"`
	LastMessageTime time.Time            `bson:"last_message_time" json:"last_message_time"`
	OrderID         primitive.ObjectID   `bson:"order_id" json:"order_id"`
	UserID          primitive.ObjectID   `bson:"user_id" json:"user_id"`
	CseID           primitive.ObjectID   `bson:"cse_id,omitempty" json:"cse_id,omitempty"`
	Messages        []primitive.ObjectID `bson:"messages" json:"messages"`
	Status          string               `bson:"status" json:"status"` // "active", "pending", "waiting", "closed"
}

type Message struct {
	ID         primitive.ObjectID `bson:"_id,omitempty" json:"_id,omitempty"`
	Text       string             `bson:"text" json:"text"`
	ChatID     primitive.ObjectID `bson:"chat_id" json:"chat_id"`
	SenderID   primitive.ObjectID `bson:"sender_id" json:"sender_id"`
	ReceiverID primitive.ObjectID `bson:"receiver_id" json:"receiver_id"`
	Timestamp  time.Time          `bson:"timestamp" json:"timestamp"`
}

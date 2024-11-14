package query

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/PraveenRajPurak/CarsGo-Backend/modules/config"
	"github.com/PraveenRajPurak/CarsGo-Backend/modules/encrypt"
	"github.com/PraveenRajPurak/CarsGo-Backend/modules/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type GoAppDB struct {
	App *config.GoAppTools
	DB  *mongo.Client
}

func NewGoAppDB(app *config.GoAppTools, db *mongo.Client) *GoAppDB {
	return &GoAppDB{
		App: app,
		DB:  db,
	}
}

func (g *GoAppDB) InsertUser(user *model.User) (bool, int, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

	defer cancel()

	regMail := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

	if !regMail.MatchString(user.Email) {

		g.App.ErrorLogger.Println("invalid registered details - email")
		return false, 0, errors.New("invalid registered details - email")

	}

	filter := bson.D{{Key: "email", Value: user.Email}}

	var res bson.M
	err := User(g.DB, "user").FindOne(ctx, filter).Decode(&res)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			user.ID = primitive.NewObjectID()
			_, insertErr := User(g.DB, "user").InsertOne(ctx, user)
			if insertErr != nil {
				g.App.ErrorLogger.Fatalf("cannot add user to the database : %v ", insertErr)
			}
			return true, 1, nil
		}
		g.App.ErrorLogger.Fatal(err)
	}
	return true, 2, nil
}

func (g *GoAppDB) VerifyUser(email string) (primitive.M, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	var res bson.M

	filter := bson.D{{Key: "email", Value: email}}
	err := User(g.DB, "user").FindOne(ctx, filter).Decode(&res)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			g.App.ErrorLogger.Println("no document found for this query")
			return nil, err
		}
		g.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
	}

	return res, nil
}

func (g *GoAppDB) UpdateUser(userID primitive.ObjectID, tk map[string]string) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

	defer cancel()

	filter := bson.D{{Key: "_id", Value: userID}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "token", Value: tk["t1"]}, {Key: "new_token", Value: tk["t2"]}}}}

	_, err := User(g.DB, "user").UpdateOne(ctx, filter, update)
	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot update user's tokens in the database : %v ", err)
		return false, err
	}
	return true, nil
}

func (g *GoAppDB) SignUpAdmin(admin *model.Admin) (bool, int, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

	defer cancel()

	filter := bson.D{{Key: "email", Value: admin.Email}}
	var res primitive.M

	err := User(g.DB, "admin").FindOne(ctx, filter).Decode(&res)

	if err != nil {

		if err == mongo.ErrNoDocuments {

			admin.ID = primitive.NewObjectID()
			_, insertErr := User(g.DB, "admin").InsertOne(ctx, admin)
			if insertErr != nil {
				g.App.ErrorLogger.Fatalf("cannot add admin to the database : %v ", insertErr)
			}

			return true, 1, nil
		}

		g.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
	}

	return true, 2, nil
}

func (g *GoAppDB) VerifyAdmin(email string) (primitive.M, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	var res bson.M

	filter := bson.D{{Key: "email", Value: email}}
	err := User(g.DB, "admin").FindOne(ctx, filter).Decode(&res)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			g.App.ErrorLogger.Println("no document found for this query")
			return nil, err
		}
		g.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
	}

	return res, nil
}

func (g *GoAppDB) UpdateAdmin(userID primitive.ObjectID, tk map[string]string) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

	defer cancel()

	filter := bson.D{{Key: "_id", Value: userID}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "token", Value: tk["t1"]}, {Key: "new_token", Value: tk["t2"]}}}}

	_, err := User(g.DB, "admin").UpdateOne(ctx, filter, update)
	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot update user's tokens in the database : %v ", err)
		return false, err
	}
	return true, nil
}

func (g *GoAppDB) SignOutUser(userID primitive.ObjectID) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	filter := bson.D{{Key: "_id", Value: userID}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "token", Value: ""}, {Key: "new_token", Value: ""}}}}

	_, err := User(g.DB, "user").UpdateOne(ctx, filter, update)
	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot update user's tokens in the database : %v ", err)
		return false, err
	}
	return true, nil

}

func (g *GoAppDB) SignOutAdmin(adminID primitive.ObjectID) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	filter := bson.D{{Key: "_id", Value: adminID}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "token", Value: ""}, {Key: "new_token", Value: ""}}}}

	_, err := User(g.DB, "admin").UpdateOne(ctx, filter, update)
	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot update user's tokens in the database : %v ", err)
		return false, err
	}
	return true, nil

}

func (g *GoAppDB) InsertProduct(product *model.Product) (bool, int, error) {

	fmt.Println("Inserting product...")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

	defer cancel()

	filter := bson.D{{Key: "name", Value: product.Name}}

	var res bson.M

	err := Product(g.DB, "product").FindOne(ctx, filter).Decode(&res)

	if err != nil {

		if err == mongo.ErrNoDocuments {

			product.ID = primitive.NewObjectID()
			_, insertErr := Product(g.DB, "product").InsertOne(ctx, product)
			if insertErr != nil {
				g.App.ErrorLogger.Fatalf("cannot add product to the database : %v ", insertErr)
			}

			return true, 1, nil
		}

		g.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
	}

	return true, 2, nil

}

func (g *GoAppDB) Update_Stock(id primitive.ObjectID, new_stock int) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

	defer cancel()

	filter := bson.D{{Key: "id", Value: id}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "stock", Value: new_stock}}}}

	updateResult, err := User(g.DB, "product").UpdateOne(ctx, filter, update)

	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot update product's stock in the database : %v ", err)
		return false, err
	}

	g.App.InfoLogger.Printf("Matched %v documents and updated %v documents.\n", updateResult.MatchedCount, updateResult.ModifiedCount)

	return true, nil
}

func (g *GoAppDB) CreateNewPassword(email string, password string) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

	hashed_Password, err := encrypt.Hash(password)

	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot hash password : %v ", err)
		return false, err
	}

	defer cancel()

	filter := bson.D{{Key: "email", Value: email}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "password", Value: hashed_Password}}}}

	_, err = User(g.DB, "user").UpdateOne(ctx, filter, update)
	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot update user's password in the database : %v ", err)
		return false, err
	}

	fmt.Println("Creating new password...")
	return true, nil
}

func (ga *GoAppDB) CreateNewPasswordAdmin(email string, password string) (bool, error) {

	fmt.Println("Creating new password...")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	hashed_Password, err := encrypt.Hash(password)

	if err != nil {
		ga.App.ErrorLogger.Fatalf("cannot hash password : %v ", err)
		return false, err
	}

	filter := bson.D{{Key: "email", Value: email}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "password", Value: hashed_Password}}}}

	_, err = User(ga.DB, "admin").UpdateOne(ctx, filter, update)
	if err != nil {
		ga.App.ErrorLogger.Fatalf("cannot update user's password in the database : %v ", err)
		return false, err
	}

	fmt.Println("Created new password...")

	return true, nil
}

func (g *GoAppDB) UpdateEmailUser(current_email string, new_email string) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

	defer cancel()

	filter := bson.D{{Key: "email", Value: current_email}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "email", Value: new_email}}}}

	_, err := User(g.DB, "user").UpdateOne(ctx, filter, update)
	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot update user's email in the database : %v ", err)
		return false, err
	}
	return true, nil
}

func (g *GoAppDB) UpdateEmailAdmin(current_email string, new_email string) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

	defer cancel()

	filter := bson.D{{Key: "email", Value: current_email}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "email", Value: new_email}}}}

	_, err := User(g.DB, "admin").UpdateOne(ctx, filter, update)
	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot update user's email in the database : %v ", err)
		return false, err
	}
	return true, nil
}

func (g *GoAppDB) UpdateNameUser(email string, new_name string) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

	defer cancel()

	filter := bson.D{{Key: "email", Value: email}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "name", Value: new_name}}}}

	_, err := User(g.DB, "user").UpdateOne(ctx, filter, update)
	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot update user's name in the database : %v ", err)
		return false, err
	}
	return true, nil
}
func (g *GoAppDB) UpdateNameAdmin(email string, new_name string) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

	defer cancel()

	filter := bson.D{{Key: "email", Value: email}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "name", Value: new_name}}}}

	_, err := User(g.DB, "admin").UpdateOne(ctx, filter, update)
	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot update user's name in the database : %v ", err)
		return false, err
	}
	return true, nil
}
func (g *GoAppDB) UpdatePhoneUser(email string, new_phone string) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

	defer cancel()

	filter := bson.D{{Key: "email", Value: email}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "phone", Value: new_phone}}}}

	_, err := User(g.DB, "user").UpdateOne(ctx, filter, update)
	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot update user's phone in the database : %v ", err)
		return false, err
	}
	return true, nil
}
func (g *GoAppDB) UpdatePhoneAdmin(email string, new_phone string) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

	defer cancel()

	filter := bson.D{{Key: "email", Value: email}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "phone", Value: new_phone}}}}

	_, err := User(g.DB, "admin").UpdateOne(ctx, filter, update)
	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot update user's phone in the database : %v ", err)
		return false, err
	}
	return true, nil
}
func (g *GoAppDB) ViewProducts() ([]primitive.M, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	var res []primitive.M
	cursor, err := Product(g.DB, "product").Find(ctx, bson.D{})
	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
		return nil, err
	}

	if err = cursor.All(ctx, &res); err != nil {
		g.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
		return nil, err
	}

	return res, nil
}

func (g *GoAppDB) CreateCategory(category *model.Category) (bool, int, error) {
	fmt.Println("Inserting category...")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	filter := bson.D{{Key: "name", Value: category.Name}}

	var res bson.M

	err := User(g.DB, "category").FindOne(ctx, filter).Decode(&res)

	if err != nil {

		if err == mongo.ErrNoDocuments {

			category.ID = primitive.NewObjectID()
			_, insertErr := User(g.DB, "category").InsertOne(ctx, category)

			if insertErr != nil {
				g.App.ErrorLogger.Fatalf("cannot add category to the database : %v ", insertErr)
			}

			return true, 1, nil
		}

		g.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)

	}

	return true, 2, nil
}

func (g *GoAppDB) UpdateProduct(product *model.Product) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	filter := bson.D{{Key: "_id", Value: product.ID}}
	update := bson.D{
		{Key: "$set", Value: bson.D{
			{Key: "name", Value: product.Name},
			{Key: "description", Value: product.Description},
			{Key: "description.dimension", Value: product.Description.Dimension},

			{Key: "category", Value: product.Category},
			{Key: "company_name", Value: product.Company_Name},
			{Key: "model_name", Value: product.Model_Name},
			{Key: "regularprice", Value: product.RegularPrice},
			{Key: "saleprice", Value: product.SalePrice},
			{Key: "salestarts", Value: product.SaleStarts},
			{Key: "saleends", Value: product.SaleEnds},
			{Key: "instock", Value: product.InStock},
			{Key: "sku", Value: product.SKU},
			{Key: "createdat", Value: product.CreatedAt},
			{Key: "updatedat", Value: time.Now()},
		}},
		{Key: "$push", Value: bson.D{
			{Key: "images", Value: bson.D{
				{Key: "$each", Value: product.Images},
			}},
		}},
	}

	updateDetails, err := Product(g.DB, "product").UpdateOne(ctx, filter, update)
	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot update product in the database : %v ", err)
		return false, err
	}

	g.App.InfoLogger.Printf("Matched %v documents and updated %v documents.\n", updateDetails.MatchedCount, updateDetails.ModifiedCount)
	return true, nil
}

func (g *GoAppDB) Toggle_Stock(Id primitive.ObjectID) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	filter := bson.D{{Key: "_id", Value: Id}}

	var res bson.M

	err := Product(g.DB, "product").FindOne(ctx, filter).Decode(&res)

	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
		return false, err
	}

	in_stock := res["in_stock"].(bool)

	update := bson.D{{Key: "$set", Value: bson.D{{Key: "in_stock", Value: !in_stock}}}}

	updateDetails, err := Product(g.DB, "product").UpdateOne(ctx, filter, update)
	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot update product in the database : %v ", err)
		return false, err
	}

	g.App.InfoLogger.Printf("Matched %v documents and updated %v documents.\n", updateDetails.MatchedCount, updateDetails.ModifiedCount)
	return true, nil
}

func (g *GoAppDB) AddProductToWishlist(Product_Id primitive.ObjectID, User_Id primitive.ObjectID) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

	defer cancel()

	filter := bson.D{{Key: "_id", Value: User_Id}}

	update := bson.D{{Key: "$push", Value: bson.D{{Key: "wishlist", Value: Product_Id}}}}

	updateDetails, err := User(g.DB, "user").UpdateOne(ctx, filter, update)

	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot update product in the database : %v ", err)
		return false, err
	}

	g.App.InfoLogger.Printf("Matched %v documents and updated %v documents.\n", updateDetails.MatchedCount, updateDetails.ModifiedCount)

	return true, nil
}

func (g *GoAppDB) RemoveProductFromWishlist(Product_Id primitive.ObjectID, User_Id primitive.ObjectID) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

	defer cancel()

	filter := bson.D{{Key: "_id", Value: User_Id}}

	update := bson.D{{Key: "$pull", Value: bson.D{{Key: "wishlist", Value: Product_Id}}}}

	updateDetails, err := User(g.DB, "user").UpdateOne(ctx, filter, update)

	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot update product in the database : %v ", err)
		return false, err
	}

	g.App.InfoLogger.Printf("Matched %v documents and updated %v documents.\n", updateDetails.MatchedCount, updateDetails.ModifiedCount)

	return true, nil
}

func (g *GoAppDB) GetSingleProduct(Id primitive.ObjectID) (primitive.M, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	filter := bson.D{{Key: "_id", Value: Id}}

	var res bson.M

	err := Product(g.DB, "product").FindOne(ctx, filter).Decode(&res)

	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
		return nil, err
	}

	return res, nil
}

func (g *GoAppDB) AddToCart(userID primitive.ObjectID, cartItems *model.CartItems) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

	defer cancel()

	filter := bson.D{{Key: "_id", Value: userID}}

	update := bson.D{{Key: "$push", Value: bson.D{{Key: "cart", Value: cartItems}}}}

	updateDetails, err := User(g.DB, "user").UpdateOne(ctx, filter, update)

	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot update product in the database : %v ", err)
		return false, err
	}

	g.App.InfoLogger.Printf("Matched %v documents and updated %v documents.\n", updateDetails.MatchedCount, updateDetails.ModifiedCount)

	return true, nil
}

func (g *GoAppDB) Empty_the_Cart(userID primitive.ObjectID) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

	defer cancel()

	filter := bson.D{{Key: "_id", Value: userID}}

	update := bson.D{{Key: "$set", Value: bson.D{{Key: "cart", Value: bson.A{}}}}}

	updateDetails, err := User(g.DB, "user").UpdateOne(ctx, filter, update)

	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot update product in the database : %v ", err)
		return false, err
	}

	g.App.InfoLogger.Printf("Matched %v documents and updated %v documents.\n", updateDetails.MatchedCount, updateDetails.ModifiedCount)

	return true, nil

}

func (g *GoAppDB) RemoveFromCart(userID primitive.ObjectID, productID primitive.ObjectID) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

	defer cancel()

	filter := bson.D{{Key: "_id", Value: userID}}

	update := bson.D{{Key: "$pull", Value: bson.D{{Key: "cart", Value: bson.M{"product_id": productID}}}}}

	updateDetails, err := User(g.DB, "user").UpdateOne(ctx, filter, update)

	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot update product in the database : %v ", err)
		return false, err
	}

	g.App.InfoLogger.Printf("Matched %v documents and updated %v documents.\n", updateDetails.MatchedCount, updateDetails.ModifiedCount)

	return true, nil
}

func (g *GoAppDB) GetAllUsers() ([]bson.M, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	var res []bson.M

	cursor, err := User(g.DB, "user").Find(ctx, bson.D{})

	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
		return nil, err
	}

	if err = cursor.All(ctx, &res); err != nil {
		g.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
		return nil, err
	}

	return res, nil

}

func (g *GoAppDB) GetAllCategories() ([]bson.M, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	var res []bson.M

	cursor, err := User(g.DB, "category").Find(ctx, bson.D{})

	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
		return nil, err
	}

	if err = cursor.All(ctx, &res); err != nil {
		g.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
		return nil, err
	}

	fmt.Println("res : ", res)

	return res, nil
}

func (g *GoAppDB) InitializeUser(userId primitive.ObjectID) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	filter := bson.D{{Key: "_id", Value: userId}}

	update := bson.D{{Key: "$set", Value: bson.D{{Key: "cart", Value: bson.A{}},
		{Key: "addresses", Value: bson.A{}}, {Key: "orders", Value: bson.A{}},
		{Key: "payments", Value: bson.A{}}, {Key: "shipments", Value: bson.A{}},
	}}}

	_, err := User(g.DB, "user").UpdateOne(ctx, filter, update)

	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot update product in the database : %v ", err)
		return false, err
	}

	return true, nil

}

func (g *GoAppDB) GetUserByID(userId primitive.ObjectID) (primitive.M, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	filter := bson.D{{Key: "_id", Value: userId}}

	var res primitive.M

	err := User(g.DB, "user").FindOne(ctx, filter).Decode(&res)

	if err != nil {
		g.App.ErrorLogger.Fatalf("could not fetch the user from the database : %v ", err)
		return nil, err
	}

	return res, nil

}

func (g *GoAppDB) CreateOrder(order *model.Order) (primitive.M, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	cr, err := User(g.DB, "orders").InsertOne(ctx, order)
	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot insert order in the database : %v ", err)
		return nil, err
	}

	g.App.InfoLogger.Printf("Inserted order with id : %v", cr.InsertedID)

	filter := bson.D{{Key: "_id", Value: cr.InsertedID}}

	var res primitive.M

	err = User(g.DB, "orders").FindOne(ctx, filter).Decode(&res)

	if err != nil {
		g.App.ErrorLogger.Fatalf("could not fetch the user from the database : %v ", err)
		return nil, err
	}
	return res, nil
}

func (g *GoAppDB) InsertOrdertoUser(userID primitive.ObjectID, OrderId primitive.ObjectID) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	filter := bson.D{{Key: "_id", Value: userID}}

	update := bson.D{{Key: "$push", Value: bson.D{{Key: "orders", Value: OrderId}}}}

	_, err := User(g.DB, "user").UpdateOne(ctx, filter, update)

	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot insert order in the database : %v ", err)
		return false, err
	}
	return true, nil
}

func (g *GoAppDB) UpdatePaymentToIncludeOrderId(paymentId primitive.ObjectID, orderId primitive.ObjectID) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

	defer cancel()

	filter := bson.D{{Key: "_id", Value: paymentId}}

	update := bson.D{{Key: "$set", Value: bson.D{{Key: "order_id", Value: orderId}}}}

	updateDetails, err := User(g.DB, "payment").UpdateOne(ctx, filter, update)

	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot update the payment to include the order : %v ", err)
		return false, err
	}

	if updateDetails.MatchedCount == 0 {
		g.App.ErrorLogger.Fatalf("No matching payment could be found. Recheck your Payload")
		return false, err
	} else if updateDetails.ModifiedCount == 0 {
		g.App.ErrorLogger.Fatalf("No matching payment could be found. Recheck your Payload")
		return false, err
	}

	return true, err
}

func (ga *GoAppDB) FindUserWithEmail(email string) (primitive.M, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	var res primitive.M

	filter := bson.D{{Key: "email", Value: email}}

	err := User(ga.DB, "user").FindOne(ctx, filter).Decode(&res)

	if err != nil {
		ga.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
		return nil, err
	}

	return res, nil

}

func (ga *GoAppDB) GetAllOrders() ([]primitive.M, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	var res []primitive.M

	cursor, err := User(ga.DB, "orders").Find(ctx, bson.D{})

	if err != nil {
		ga.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
		return nil, err
	}

	if err = cursor.All(ctx, &res); err != nil {
		ga.App.ErrorLogger.Fatalf("cannot execute the database query perfectly. There is some problem in cursor : %v ", err)
		return nil, err
	}

	return res, nil
}

func (ga *GoAppDB) DeleteProduct(id primitive.ObjectID) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	filter := bson.D{{Key: "_id", Value: id}}

	_, err := Product(ga.DB, "product").DeleteOne(ctx, filter)

	if err != nil {
		ga.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
		return false, err
	}

	return true, nil
}

func (ga *GoAppDB) DeleteOrder(id primitive.ObjectID) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	filter := bson.D{{Key: "_id", Value: id}}

	var res primitive.M

	err := User(ga.DB, "orders").FindOne(ctx, filter).Decode(&res)

	if err != nil {
		ga.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
		return false, err
	}

	filter = bson.D{{Key: "_id", Value: res["customer_id"]}}

	update := bson.D{{Key: "$pull", Value: bson.D{{Key: "orders", Value: id}}}}

	updateInformation, err := User(ga.DB, "user").UpdateOne(ctx, filter, update)

	if err != nil {
		ga.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
		return false, err
	}

	ga.App.InfoLogger.Printf("Matched %v documents and updated %v documents.\n", updateInformation.MatchedCount, updateInformation.ModifiedCount)

	_, err = User(ga.DB, "orders").DeleteOne(ctx, filter)

	if err != nil {
		ga.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
		return false, err
	}

	return true, nil
}

func (ga *GoAppDB) ShipmentCreation(shipment *model.Shipment) (primitive.M, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	cr, err := User(ga.DB, "shipment").InsertOne(ctx, shipment)
	if err != nil {
		ga.App.ErrorLogger.Fatalf("cannot insert shipment in the database : %v ", err)
		return nil, err
	}

	filter1 := bson.D{{Key: "_id", Value: shipment.CustomerID}}

	update := bson.D{{Key: "$push", Value: bson.D{{Key: "shipments", Value: cr.InsertedID}}}}

	updateDetails, err := User(ga.DB, "user").UpdateOne(ctx, filter1, update)
	if err != nil {
		ga.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
		return nil, err
	}

	ga.App.InfoLogger.Printf("Matched %v documents and updated %v documents.\n", updateDetails.MatchedCount, updateDetails.ModifiedCount)
	if updateDetails.MatchedCount == 0 {
		ga.App.ErrorLogger.Fatalf("cannot execute the database query perfectly as matched count is 0: %v ", err)
		return nil, err
	} else if updateDetails.ModifiedCount == 0 {
		ga.App.ErrorLogger.Fatalf("cannot execute the database query perfectly as modified count is 0: %v ", err)
		return nil, err
	}

	var res primitive.M

	filter := bson.D{{Key: "_id", Value: cr.InsertedID}}

	err = User(ga.DB, "shipment").FindOne(ctx, filter).Decode(&res)

	if err != nil {
		ga.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
		return nil, err
	}

	return res, nil
}

func (ga *GoAppDB) PaymentCreation(payment *model.Payment) (primitive.M, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	cr, err := User(ga.DB, "payment").InsertOne(ctx, payment)
	if err != nil {
		ga.App.ErrorLogger.Fatalf("cannot insert payment in the database : %v ", err)
		return nil, err
	}
	fmt.Println(cr)

	userFilter := bson.D{{Key: "_id", Value: payment.PaidBy}}

	update := bson.D{{Key: "$push", Value: bson.D{{Key: "payments", Value: cr.InsertedID}}}}

	updateDetails, err := User(ga.DB, "user").UpdateOne(ctx, userFilter, update)
	if err != nil {
		ga.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
		return nil, err
	}

	ga.App.InfoLogger.Printf("Matched %v documents and updated %v documents.\n", updateDetails.MatchedCount, updateDetails.ModifiedCount)
	if updateDetails.MatchedCount == 0 {
		ga.App.ErrorLogger.Fatalf("cannot execute the database query perfectly as matched count is 0: %v ", err)
		return nil, err
	} else if updateDetails.ModifiedCount == 0 {
		ga.App.ErrorLogger.Fatalf("cannot execute the database query perfectly as modified count is 0: %v ", err)
		return nil, err
	}

	filter := bson.D{{Key: "_id", Value: cr.InsertedID}}

	var res primitive.M

	err = User(ga.DB, "payment").FindOne(ctx, filter).Decode(&res)

	if err != nil {
		ga.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
		return nil, err
	}

	return res, nil
}

func (ga *GoAppDB) GetAllShipments() ([]primitive.M, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	var res []primitive.M

	cursor, err := User(ga.DB, "shipment").Find(ctx, bson.D{})

	if err != nil {
		ga.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
		return nil, err
	}

	if err = cursor.All(ctx, &res); err != nil {
		ga.App.ErrorLogger.Fatalf("cannot execute the database query perfectly. There is some problem in cursor : %v ", err)
		return nil, err
	}

	return res, nil
}

func (ga *GoAppDB) AddAddress(userId primitive.ObjectID, address *model.Address) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	filter := bson.D{{Key: "_id", Value: userId}}

	update := bson.D{{Key: "$push", Value: bson.D{{Key: "addresses", Value: address}}}}

	updateDetails, err := User(ga.DB, "user").UpdateOne(ctx, filter, update)
	if err != nil {
		ga.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
		return false, err
	}

	ga.App.InfoLogger.Printf("Matched %v documents and updated %v documents.\n", updateDetails.MatchedCount, updateDetails.ModifiedCount)
	if updateDetails.MatchedCount == 0 {
		ga.App.ErrorLogger.Fatalf("cannot execute the database query perfectly as matched count is 0: %v ", err)
		return false, err
	} else if updateDetails.ModifiedCount == 0 {
		ga.App.ErrorLogger.Fatalf("cannot execute the database query perfectly as modified count is 0: %v ", err)
		return false, err
	}

	return true, nil
}

func (ga *GoAppDB) GetAllPayments() ([]primitive.M, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	var res []primitive.M

	cursor, err := User(ga.DB, "payment").Find(ctx, bson.D{})

	if err != nil {
		ga.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
		return nil, err
	}

	if err = cursor.All(ctx, &res); err != nil {
		ga.App.ErrorLogger.Fatalf("cannot execute the database query perfectly. There is some problem in cursor : %v ", err)
		return nil, err
	}

	return res, nil
}

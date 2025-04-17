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
	"go.mongodb.org/mongo-driver/mongo/options"
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

func (g *GoAppDB) InsertMultipleProductsBulk(products []*model.Product) (int, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	// First check which products already exist
	var productNames []string
	for _, product := range products {
		productNames = append(productNames, product.Name)
	}

	filter := bson.M{"name": bson.M{"$in": productNames}}
	cursor, err := Product(g.DB, "product").Find(ctx, filter)
	if err != nil {
		g.App.ErrorLogger.Printf("Error querying existing products: %v", err)
		return 0, 0, err
	}

	// Create a map of existing product names
	existingProducts := make(map[string]bool)
	var results []bson.M
	if err = cursor.All(ctx, &results); err != nil {
		g.App.ErrorLogger.Printf("Error processing cursor: %v", err)
		return 0, 0, err
	}

	for _, result := range results {
		if name, ok := result["name"].(string); ok {
			existingProducts[name] = true
		}
	}

	// Prepare new products for insertion
	var newProducts []interface{}
	for _, product := range products {
		if _, exists := existingProducts[product.Name]; !exists {
			product.ID = primitive.NewObjectID()
			product.CreatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
			product.UpdatedAt = product.CreatedAt
			newProducts = append(newProducts, product)
		}
	}

	// Bulk insert new products
	if len(newProducts) > 0 {
		result, err := Product(g.DB, "product").InsertMany(ctx, newProducts)
		if err != nil {
			g.App.ErrorLogger.Printf("Error bulk inserting products: %v", err)
			return 0, len(existingProducts), err
		}
		return len(result.InsertedIDs), len(existingProducts), nil
	}

	return 0, len(existingProducts), nil
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

func (ga *GoAppDB) GetUserOrders(userId primitive.ObjectID) ([]primitive.M, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	pipeline := mongo.Pipeline{
		bson.D{{Key: "$match", Value: bson.D{{Key: "_id", Value: userId}}}},
		bson.D{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: "orders"},
			{Key: "localField", Value: "orders"},
			{Key: "foreignField", Value: "_id"},
			{Key: "as", Value: "userOrders"},
		}}},
		bson.D{{Key: "$unwind", Value: bson.D{{Key: "path", Value: "$userOrders"}, {Key: "preserveNullAndEmptyArrays", Value: true}}}},
		bson.D{{Key: "$unwind", Value: bson.D{{Key: "path", Value: "$userOrders.order_items.orderitems"}, {Key: "preserveNullAndEmptyArrays", Value: true}}}},
		bson.D{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: "product"},
			{Key: "localField", Value: "userOrders.order_items.orderitems.productid"},
			{Key: "foreignField", Value: "_id"},
			{Key: "as", Value: "productDetails"},
		}}},
		bson.D{{Key: "$unwind", Value: bson.D{{Key: "path", Value: "$productDetails"}, {Key: "preserveNullAndEmptyArrays", Value: true}}}},
		bson.D{{Key: "$project", Value: bson.D{
			{Key: "_id", Value: 0},
			{Key: "userID", Value: userId},
			{Key: "productID", Value: "$productDetails._id"},
			{Key: "productName", Value: "$productDetails.name"},
			{Key: "price", Value: "$productDetails.saleprice"},
			{Key: "quantity", Value: "$userOrders.order_items.orderitems.quantity"},
			{Key: "order_amount", Value: "$userOrders.order_amount"},
			{Key: "order_date", Value: "$userOrders.order_date"},
			{Key: "order_status", Value: "$userOrders.order_status"},
			{Key: "orderID", Value: "$userOrders._id"},
		}}},
	}

	cursor, err := User(ga.DB, "user").Aggregate(ctx, pipeline)

	if err != nil {
		ga.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
		return nil, err
	}

	defer cursor.Close(ctx)
	var res []primitive.M

	fmt.Printf("Pipeline execution result: %+v\n", res)

	if err := cursor.All(ctx, &res); err != nil {
		ga.App.ErrorLogger.Fatalf("cannot execute the database query perfectly. There is some problem in cursor : %v ", err)
		return nil, err
	}

	return res, nil

}

func (ga *GoAppDB) GetAllOrders() ([]primitive.M, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	pipeline := mongo.Pipeline{
		bson.D{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: "orders"},
			{Key: "localField", Value: "orders"},
			{Key: "foreignField", Value: "_id"},
			{Key: "as", Value: "userOrders"},
		}}},
		bson.D{{Key: "$unwind", Value: bson.D{{Key: "path", Value: "$userOrders"}, {Key: "preserveNullAndEmptyArrays", Value: true}}}},
		bson.D{{Key: "$unwind", Value: bson.D{{Key: "path", Value: "$userOrders.order_items.orderitems"}, {Key: "preserveNullAndEmptyArrays", Value: true}}}},
		bson.D{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: "product"},
			{Key: "localField", Value: "userOrders.order_items.orderitems.productid"},
			{Key: "foreignField", Value: "_id"},
			{Key: "as", Value: "productDetails"},
		}}},
		bson.D{{Key: "$unwind", Value: bson.D{{Key: "path", Value: "$productDetails"}, {Key: "preserveNullAndEmptyArrays", Value: true}}}},
		bson.D{{Key: "$project", Value: bson.D{
			{Key: "_id", Value: 0},
			{Key: "productID", Value: "$productDetails._id"},
			{Key: "productName", Value: "$productDetails.name"},
			{Key: "price", Value: "$productDetails.saleprice"},
			{Key: "quantity", Value: "$userOrders.order_items.orderitems.quantity"},
			{Key: "order_amount", Value: "$userOrders.order_amount"},
			{Key: "order_date", Value: "$userOrders.order_date"},
			{Key: "order_status", Value: "$userOrders.order_status"},
			{Key: "orderID", Value: "$userOrders._id"},
			{Key: "userID", Value: "$userOrders.customer_id"},
		}}},
	}

	cursor, err := User(ga.DB, "user").Aggregate(ctx, pipeline)

	if err != nil {
		ga.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
		return nil, err
	}

	defer cursor.Close(ctx)
	var res []primitive.M

	fmt.Printf("Pipeline execution result: %+v\n", res)

	if err := cursor.All(ctx, &res); err != nil {
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

func (ga *GoAppDB) InsertCSE(cse *model.CSE) (bool, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	regMail := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

	if !regMail.MatchString(cse.Email) {

		ga.App.ErrorLogger.Println("invalid registered details - email")
		return false, 0, errors.New("invalid registered details - email")

	}

	filter := bson.D{{Key: "email", Value: cse.Email}}

	var res bson.M
	err := User(ga.DB, "cses").FindOne(ctx, filter).Decode(&res)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			cse.ID = primitive.NewObjectID()
			_, insertErr := User(ga.DB, "cses").InsertOne(ctx, cse)
			if insertErr != nil {
				ga.App.ErrorLogger.Fatalf("cannot add user to the database : %v ", insertErr)
			}
			return true, 1, nil
		}
		ga.App.ErrorLogger.Fatal(err)
	}
	return true, 2, nil
}

func (ga *GoAppDB) GetAllCSEs() ([]primitive.M, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	var res []primitive.M

	cursor, err := User(ga.DB, "cses").Find(ctx, bson.D{})

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

func (g *GoAppDB) GetCSEByCredentials(cseID string) (primitive.M, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	var res bson.M

	filter := bson.D{{Key: "cse_id", Value: cseID}}

	err := User(g.DB, "cses").FindOne(ctx, filter).Decode(&res)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			g.App.ErrorLogger.Println("no document found for this query")
			return nil, err
		}
		g.App.ErrorLogger.Fatalf("cannot execute the database query perfectly : %v ", err)
	}

	return res, nil
}

func (g *GoAppDB) UpdateCSEStatus(id primitive.ObjectID, status string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	filter := bson.D{{Key: "_id", Value: id}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "status", Value: status}, {Key: "updated_at", Value: time.Now()}}}}

	_, err := User(g.DB, "cses").UpdateOne(ctx, filter, update)
	if err != nil {
		g.App.ErrorLogger.Printf("Error updating CSE status: %v", err)
		return err
	}

	return nil
}

func (g *GoAppDB) CreateChat(chat *model.Chat) (primitive.ObjectID, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	orderID := chat.OrderID

	fmt.Print("Order ID: ", chat.OrderID)
	fmt.Print("Order ID derived: ", orderID)

	filter := bson.D{{Key: "_id", Value: orderID}}

	var res bson.M
	err := User(g.DB, "orders").FindOne(ctx, filter).Decode(&res)

	if err != nil {
		g.App.ErrorLogger.Printf("Error creating order with chat ID due to order not found: %v", err)
		return primitive.NilObjectID, err
	}

	if res["chat_id"] != nil {
		g.App.ErrorLogger.Println("chat already exists for this order")
		return primitive.NilObjectID, errors.New("chat already exists for this order")
	}

	chat.ID = primitive.NewObjectID()

	_, err = User(g.DB, "chats").InsertOne(ctx, chat)
	if err != nil {
		g.App.ErrorLogger.Printf("Error creating chat: %v", err)
		return primitive.NilObjectID, err
	}

	err = g.UpdateOrderWithChatID(orderID, chat.ID)
	if err != nil {
		g.App.ErrorLogger.Printf("Error updating order with chat ID: %v", err)
		// We'll continue anyway since the chat was created successfully
	}

	return chat.ID, nil
}

func (g *GoAppDB) UpdateOrderWithChatID(orderID primitive.ObjectID, chatID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	filter := bson.D{{Key: "_id", Value: orderID}}
	update := bson.D{
		{Key: "$set", Value: bson.D{{Key: "chat_id", Value: chatID}, {Key: "updated_at", Value: time.Now()}}},
	}

	_, err := User(g.DB, "orders").UpdateOne(ctx, filter, update)
	if err != nil {
		g.App.ErrorLogger.Printf("Error updating order with chat ID: %v", err)
		return err
	}

	return nil
}

func (g *GoAppDB) GetAllTheOrders() ([]primitive.M, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	var res []primitive.M

	cursor, err := User(g.DB, "orders").Find(ctx, bson.D{})
	if err != nil {
		g.App.ErrorLogger.Fatalf("cannot execute the database query perfectly. There is some problem in cursor : %v ", err)
		return nil, err
	}

	if err = cursor.All(ctx, &res); err != nil {
		g.App.ErrorLogger.Fatalf("cannot execute the database query perfectly. There is some problem in cursor : %v ", err)
		return nil, err
	}

	return res, nil
}

func (g *GoAppDB) GetAvailableCSEs() ([]model.CSE, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	var cses []model.CSE

	// Find all CSEs with status "online"
	filter := bson.D{{Key: "status", Value: "online"}}

	cursor, err := User(g.DB, "cses").Find(ctx, filter)
	if err != nil {
		g.App.ErrorLogger.Printf("Error finding available CSEs: %v", err)
		return nil, err
	}
	defer cursor.Close(ctx)

	if err = cursor.All(ctx, &cses); err != nil {
		g.App.ErrorLogger.Printf("Error decoding CSEs: %v", err)
		return nil, err
	}

	return cses, nil
}

func (g *GoAppDB) AssignChatToCSE(chatID, cseID primitive.ObjectID, isActive bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	// Update chat with CSE ID and status
	chatStatus := "active"
	if !isActive {
		chatStatus = "pending"
	}

	chatFilter := bson.D{{Key: "_id", Value: chatID}}
	chatUpdate := bson.D{
		{Key: "$set", Value: bson.D{
			{Key: "cse_id", Value: cseID},
			{Key: "status", Value: chatStatus},
		}},
	}

	_, err := User(g.DB, "chats").UpdateOne(ctx, chatFilter, chatUpdate)
	if err != nil {
		g.App.ErrorLogger.Printf("Error updating chat with CSE ID: %v", err)
		return err
	}

	// Update CSE's chat lists and counts
	cseFilter := bson.D{{Key: "_id", Value: cseID}}
	var cseUpdate bson.D

	if isActive {
		cseUpdate = bson.D{
			{Key: "$push", Value: bson.D{{Key: "active_chats", Value: chatID}}},
			{Key: "$inc", Value: bson.D{{Key: "active_chats_count", Value: 1}}},
		}
	} else {
		cseUpdate = bson.D{
			{Key: "$push", Value: bson.D{{Key: "pending_chats", Value: chatID}}},
			{Key: "$inc", Value: bson.D{{Key: "pending_chats_count", Value: 1}}},
		}
	}

	_, err = User(g.DB, "cses").UpdateOne(ctx, cseFilter, cseUpdate)
	if err != nil {
		g.App.ErrorLogger.Printf("Error updating CSE with chat: %v", err)
		return err
	}

	return nil
}

func (g *GoAppDB) GetChatByID(chatID primitive.ObjectID) (model.Chat, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	var chat model.Chat

	filter := bson.D{{Key: "_id", Value: chatID}}

	err := User(g.DB, "chats").FindOne(ctx, filter).Decode(&chat)
	if err != nil {
		g.App.ErrorLogger.Printf("Error finding chat: %v", err)
		return chat, err
	}

	return chat, nil
}

func (g *GoAppDB) UpdateChatStatus(chatID primitive.ObjectID, status string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	filter := bson.D{{Key: "_id", Value: chatID}}
	update := bson.D{
		{Key: "$set", Value: bson.D{{Key: "status", Value: status}}},
	}

	_, err := User(g.DB, "chats").UpdateOne(ctx, filter, update)
	if err != nil {
		g.App.ErrorLogger.Printf("Error updating chat status: %v", err)
		return err
	}

	return nil
}

func (g *GoAppDB) AddMessage(message *model.Message) (primitive.ObjectID, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	// Set message ID and timestamp
	message.ID = primitive.NewObjectID()
	message.Timestamp = time.Now()

	// Insert message into database
	_, err := User(g.DB, "messages").InsertOne(ctx, message)
	if err != nil {
		g.App.ErrorLogger.Printf("Error adding message: %v", err)
		return primitive.NilObjectID, err
	}

	// Update chat with message ID and last message time
	chatFilter := bson.D{{Key: "_id", Value: message.ChatID}}
	chatUpdate := bson.D{
		{Key: "$push", Value: bson.D{{Key: "messages", Value: message.ID}}},
		{Key: "$set", Value: bson.D{{Key: "last_message_time", Value: time.Now()}}},
	}

	_, err = User(g.DB, "chats").UpdateOne(ctx, chatFilter, chatUpdate)
	if err != nil {
		g.App.ErrorLogger.Printf("Error updating chat with message: %v", err)
		return message.ID, err // Return message ID anyway since message was created
	}

	return message.ID, nil
}

func (g *GoAppDB) GetMessagesByChat(chatID primitive.ObjectID) ([]model.Message, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	var messages []model.Message

	// Find all messages for this chat
	filter := bson.D{{Key: "chat_id", Value: chatID}}

	// Sort by timestamp to get messages in chronological order
	opts := options.Find().SetSort(bson.D{{Key: "timestamp", Value: 1}})

	cursor, err := User(g.DB, "messages").Find(ctx, filter, opts)
	if err != nil {
		g.App.ErrorLogger.Printf("Error finding messages: %v", err)
		return nil, err
	}
	defer cursor.Close(ctx)

	if err = cursor.All(ctx, &messages); err != nil {
		g.App.ErrorLogger.Printf("Error decoding messages: %v", err)
		return nil, err
	}

	return messages, nil
}

func (g *GoAppDB) UpdateChatLastMessageTime(chatID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	filter := bson.D{{Key: "_id", Value: chatID}}
	update := bson.D{
		{Key: "$set", Value: bson.D{{Key: "last_message_time", Value: time.Now()}}},
	}

	_, err := User(g.DB, "chats").UpdateOne(ctx, filter, update)
	if err != nil {
		g.App.ErrorLogger.Printf("Error updating chat last message time: %v", err)
		return err
	}

	return nil
}

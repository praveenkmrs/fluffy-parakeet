// MongoDB initialization script for shopping-cart database
db = db.getSiblingDB('shopping-cart');

// Create collections
db.createCollection('products');
db.createCollection('carts');
db.createCollection('orders');

// Insert sample data
db.products.insertMany([
    {
        _id: ObjectId(),
        name: "Laptop",
        description: "High-performance laptop",
        price: 999.99,
        category: "Electronics",
        stock: 50,
        createdAt: new Date()
    },
    {
        _id: ObjectId(),
        name: "Smartphone",
        description: "Latest smartphone model",
        price: 699.99,
        category: "Electronics",
        stock: 100,
        createdAt: new Date()
    },
    {
        _id: ObjectId(),
        name: "Coffee Mug",
        description: "Ceramic coffee mug",
        price: 15.99,
        category: "Home & Kitchen",
        stock: 200,
        createdAt: new Date()
    }
]);

print('Shopping cart database initialized successfully!');

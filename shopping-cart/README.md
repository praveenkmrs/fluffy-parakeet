# Shopping Cart Service

A modern Spring Boot microservice for managing shopping cart operations, built with Java 21, Spring Boot 3.5.3, and MongoDB. This service provides a robust, scalable, and Docker-ready solution for e-commerce applications.

## Table of Contents
- [Overview](#overview)
- [Technology Stack](#technology-stack)
- [Getting Started](#getting-started)
- [API Documentation](#api-documentation)
- [Configuration](#configuration)
- [Docker Setup](#docker-setup)
- [Development](#development)
- [Testing](#testing)
- [Monitoring](#monitoring)
- [Production Deployment](#production-deployment)
- [Contributing](#contributing)

## Overview

The Shopping Cart Service is a comprehensive e-commerce microservice built with a 3-phase architecture that provides:

### 🏗️ **Phase 1: Service Abstraction Layer**
- **Payment Gateway Integration** - Abstracted payment processing with multiple provider support
- **Notification Services** - Email, SMS, and push notification abstractions
- **Stub Implementations** - Development-ready mock services for testing
- **Configuration-Driven** - Switch between stub and real services via profiles

### 👤 **Phase 2: User Management & Authentication**
- **User Registration & Authentication** - Complete user account management
- **JWT Token Security** - Secure API access with token-based authentication
- **Password Encryption** - BCrypt hashing for secure password storage
- **Profile Management** - User profiles with addresses and preferences

### 🛒 **Phase 3: Shopping Cart Operations**
- **Product Catalog Management** - Complete product inventory with search and categories
- **Shopping Cart Operations** - Add, remove, update items with automatic calculations
- **Stock Management** - Real-time inventory tracking and validation
- **Cart Persistence** - MongoDB storage with expiration and cleanup

## Technology Stack

- **Java**: 21 (LTS)
- **Framework**: Spring Boot 3.5.3
- **Database**: MongoDB 7.0
- **Security**: Spring Security + JWT Authentication
- **Build Tool**: Maven 3.9+
- **Container**: Docker & Docker Compose
- **Monitoring**: Spring Boot Actuator
- **Utilities**: Lombok for boilerplate code reduction

### Dependencies
- Spring Boot Starter Web
- Spring Boot Starter Data MongoDB
- Spring Boot Starter Security
- Spring Boot Starter Validation
- Spring Boot Starter Actuator
- JWT Libraries (jjwt-api, jjwt-impl, jjwt-jackson)
- Lombok
- Spring Boot Starter Test
- OpenAPI/Swagger Documentation

## Getting Started

### Prerequisites
- Java 21 or higher
- Maven 3.9 or higher
- MongoDB 7.0 (or use Docker Compose)
- Docker & Docker Compose (optional, for containerized setup)

### Quick Start with Docker Compose (Recommended)

The easiest way to run the application with all dependencies:

```bash
# Clone the repository
git clone <repository-url>
cd shopping-cart

# Start the application and MongoDB
docker-compose up -d

# View logs
docker-compose logs -f shopping-cart-app

# Stop the application
docker-compose down
```

The application will be available at: http://localhost:8081

### Local Development Setup

1. **Start MongoDB** (if not using Docker):
   ```bash
   # Using MongoDB locally
   mongod --dbpath /path/to/your/data/directory
   ```

2. **Build the application**:
   ```bash
   mvn clean package
   ```

3. **Run the application**:
   ```bash
   # Run with local profile (recommended for development)
   SPRING_PROFILES_ACTIVE=local mvn spring-boot:run
   ```

   Or run with custom MongoDB configuration:
   ```bash
   mvn spring-boot:run -Dspring-boot.run.arguments="--spring.data.mongodb.host=localhost --spring.data.mongodb.port=27017"
   ```

4. **Initialize sample data** (optional):
   ```bash
   # Create sample products for testing
   curl -X POST http://localhost:8081/api/products/sample
   ```

## API Documentation

### Base URL
```
http://localhost:8081
```

### Security & Authentication

The application uses **JWT (JSON Web Token)** authentication for secure API access:

- **Development Environment**: Some endpoints are publicly accessible for testing
- **Production Environment**: All endpoints require proper authentication
- **Token Expiration**: JWT tokens expire after 24 hours
- **Password Security**: BCrypt encryption with 12-round strength
- **Logout Mechanism**: Server-side token blacklist for secure logout
- **Token Invalidation**: Blacklisted tokens are automatically cleaned up after expiration

### API Endpoints

#### 🔧 **System & Configuration**
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/actuator/health` | Application health status | No |
| `GET` | `/actuator/info` | Application information | No |
| `GET` | `/actuator/metrics` | Application metrics | No |
| `GET` | `/api/test/config` | Service configuration status | Dev: No |

#### 👤 **User Management** (`/api/users`)
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/users/register` | Register new user account | No |
| `POST` | `/api/users/login` | Authenticate user and get JWT token | No |
| `POST` | `/api/users/logout` | Logout user and invalidate JWT token | Yes |
| `GET` | `/api/users/check-username/{username}` | Check username availability | No |
| `GET` | `/api/users/check-email/{email}` | Check email availability | No |

#### 📦 **Product Catalog** (`/api/products`)
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/products` | List all available products | Dev: No |
| `GET` | `/api/products/{id}` | Get specific product details | Dev: No |
| `GET` | `/api/products/search?q={term}` | Search products by name/description | Dev: No |
| `GET` | `/api/products/category/{category}` | Get products by category | Dev: No |
| `POST` | `/api/products/sample` | Create sample products (testing) | Dev: No |

#### 🛒 **Shopping Cart** (`/api/cart`)
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/cart?userId={id}` | Get user's shopping cart | Dev: No |
| `POST` | `/api/cart/items?userId={id}` | Add item to cart | Dev: No |
| `PUT` | `/api/cart/items?userId={id}` | Update item quantity | Dev: No |
| `DELETE` | `/api/cart/items/{productId}?userId={id}` | Remove item from cart | Dev: No |
| `DELETE` | `/api/cart?userId={id}` | Clear entire cart | Dev: No |

### Request/Response Examples

#### User Registration
```bash
curl -X POST http://localhost:8081/api/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "email": "john@example.com",
    "password": "secure123",
    "firstName": "John",
    "lastName": "Doe"
  }'
```

**Response:**
```json
{
  "id": "60d5ecb54b24a62d3c5b2b8a",
  "username": "john_doe",
  "email": "john@example.com",
  "firstName": "John",
  "lastName": "Doe",
  "status": "ACTIVE",
  "role": "USER",
  "createdAt": "2024-07-24T10:30:00Z"
}
```

#### User Login
```bash
curl -X POST http://localhost:8081/api/users/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "password": "secure123"
  }'
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzUxMiJ9...",
  "type": "Bearer",
  "expiresIn": 86400000,
  "user": {
    "id": "60d5ecb54b24a62d3c5b2b8a",
    "username": "john_doe",
    "email": "john@example.com"
  }
}
```

#### User Logout
```bash
curl -X POST http://localhost:8081/api/users/logout \
  -H "Authorization: Bearer eyJhbGciOiJIUzUxMiJ9..."
```

**Response:**
```json
{
  "message": "Logout successful"
}
```

#### Add Item to Cart
```bash
curl -X POST "http://localhost:8081/api/cart/items?userId=60d5ecb54b24a62d3c5b2b8a" \
  -H "Content-Type: application/json" \
  -d '{
    "productId": "60d5ecb54b24a62d3c5b2b8b",
    "quantity": 2
  }'
```

**Response:**
```json
{
  "id": "60d5ecb54b24a62d3c5b2b8c",
  "userId": "60d5ecb54b24a62d3c5b2b8a",
  "items": [
    {
      "productId": "60d5ecb54b24a62d3c5b2b8b",
      "productName": "Gaming Laptop",
      "unitPrice": 1299.99,
      "quantity": 2,
      "totalPrice": 2599.98,
      "currency": "USD"
    }
  ],
  "totalItems": 2,
  "totalPrice": 2599.98,
  "currency": "USD",
  "isEmpty": false
}
```

### Complete API Journey Example

Here's a complete user journey from registration to checkout:

```bash
#!/bin/bash
# Complete E-commerce Journey Example

BASE_URL="http://localhost:8081"

echo "🚀 Starting E-commerce Journey"

# Step 1: Register a new user
echo "👤 Step 1: User Registration"
USER_RESPONSE=$(curl -s -X POST "$BASE_URL/api/users/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "shopping_user",
    "email": "user@shop.com",
    "password": "password123",
    "firstName": "Shopping",
    "lastName": "User"
  }')
echo "User created: $USER_RESPONSE"

# Extract user ID (you would parse JSON in real implementation)
USER_ID="60d5ecb54b24a62d3c5b2b8a"  # Example ID

# Step 2: Login to get JWT token
echo "🔐 Step 2: User Login"
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/api/users/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "shopping_user",
    "password": "password123"
  }')
echo "Login response: $LOGIN_RESPONSE"

# Extract JWT token (you would parse JSON in real implementation)
JWT_TOKEN="eyJhbGciOiJIUzUxMiJ9..."  # Example token

# Step 3: Browse products
echo "📦 Step 3: Browse Product Catalog"
curl -s "$BASE_URL/api/products" | jq '.'

# Step 4: Search for specific products
echo "🔍 Step 4: Search Products"
curl -s "$BASE_URL/api/products/search?q=laptop" | jq '.'

# Step 5: Add items to cart
echo "🛒 Step 5: Add Items to Cart"
curl -s -X POST "$BASE_URL/api/cart/items?userId=$USER_ID" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d '{
    "productId": "laptop-001",
    "quantity": 1
  }' | jq '.'

# Step 6: Add more items
echo "➕ Step 6: Add More Items"
curl -s -X POST "$BASE_URL/api/cart/items?userId=$USER_ID" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d '{
    "productId": "phone-001",
    "quantity": 2
  }' | jq '.'

# Step 7: View cart
echo "👀 Step 7: View Shopping Cart"
curl -s "$BASE_URL/api/cart?userId=$USER_ID" \
  -H "Authorization: Bearer $JWT_TOKEN" | jq '.'

# Step 8: Update item quantity
echo "✏️ Step 8: Update Item Quantity"
curl -s -X PUT "$BASE_URL/api/cart/items?userId=$USER_ID" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d '{
    "productId": "phone-001",
    "quantity": 1
  }' | jq '.'

# Step 9: Remove an item
echo "🗑️ Step 9: Remove Item from Cart"
curl -s -X DELETE "$BASE_URL/api/cart/items/laptop-001?userId=$USER_ID" \
  -H "Authorization: Bearer $JWT_TOKEN" | jq '.'

# Step 10: Final cart review
echo "📋 Step 10: Final Cart Review"
curl -s "$BASE_URL/api/cart?userId=$USER_ID" \
  -H "Authorization: Bearer $JWT_TOKEN" | jq '.'

echo "✅ E-commerce Journey Completed!"
```

### Error Handling

The API returns appropriate HTTP status codes and error messages:

- **200 OK** - Successful operation
- **201 Created** - Resource created successfully
- **400 Bad Request** - Invalid request data
- **401 Unauthorized** - Authentication required
- **403 Forbidden** - Access denied
- **404 Not Found** - Resource not found
- **409 Conflict** - Resource already exists (e.g., username taken)
- **500 Internal Server Error** - Server error

**Example Error Response:**
```json
{
  "timestamp": "2024-07-24T10:30:00Z",
  "status": 400,
  "error": "Bad Request",
  "message": "Validation failed for field 'email': must be a valid email address",
  "path": "/api/users/register"
}
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SPRING_PROFILES_ACTIVE` | - | Active profile (local, dev, prod) |
| `MONGO_HOST` | localhost | MongoDB host |
| `MONGO_PORT` | 27017 | MongoDB port |
| `MONGO_DATABASE` | shopping-cart-local | MongoDB database name |
| `JWT_SECRET` | (auto-generated) | JWT signing secret (512+ bits) |
| `JWT_EXPIRATION` | 86400000 | JWT token expiration in milliseconds |
| `JAVA_OPTS` | - | JVM options for container deployment |

### Profile-Based Configuration

#### Local Profile (`local`)
- Development-friendly settings
- Detailed logging enabled
- Some endpoints accessible without authentication
- Stub payment and notification services
- MongoDB: `shopping-cart-local` database

#### Development Profile (`dev`)
- Similar to local but with more realistic settings
- External service integrations for testing
- Enhanced security configurations

#### Production Profile (`prod`)
- Full authentication required
- Real payment and notification services
- Optimized logging and monitoring
- Production-grade security settings

### Application Properties

The application supports multiple configuration formats:

**application-local.yml:**
```yaml
spring:
  application:
    name: shopping-cart
  data:
    mongodb:
      host: localhost
      port: 27017
      database: shopping-cart-local
      
server:
  port: 8081

# Service configurations for local development
services:
  payment:
    type: stub
    config:
      success-rate: 85
      response-delay: 500
  notification:
    type: stub
    config:
      log-to-console: true

# JWT Configuration
jwt:
  secret: myVeryLongSecretKeyThatIsAtLeast512BitsForHS512Algorithm...
  expiration: 86400000 # 24 hours

# Actuator configuration
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics
  endpoint:
    health:
      show-details: always

# Logging configuration
logging:
  level:
    pk.ai.shopping_cart: DEBUG
    org.springframework.security: DEBUG
```

## Docker Setup

This application is fully Docker-ready with multi-stage builds and production optimizations.

### Building the Docker Image

#### Option 1: Using the build script
```bash
./build-docker.sh
```

#### Option 2: Manual Docker build
```bash
docker build -t shopping-cart:latest .
```

#### Option 3: Using Spring Boot buildpacks
```bash
mvn spring-boot:build-image
```

### Running with Docker

#### With Docker Compose (Recommended)
```bash
# Development environment
docker-compose up -d

# Production environment  
docker-compose -f docker-compose.prod.yml up -d
```

#### Standalone with external MongoDB
```bash
docker run -d \
  --name shopping-cart \
  -p 8081:8081 \
  -e SPRING_PROFILES_ACTIVE=prod \
  -e MONGO_HOST=your-mongo-host \
  -e MONGO_PORT=27017 \
  -e MONGO_DATABASE=shopping-cart \
  -e JWT_SECRET=your-production-jwt-secret \
  shopping-cart:latest
```

#### With Docker network and MongoDB container
```bash
# Create network
docker network create shopping-cart-network

# Run MongoDB
docker run -d \
  --name mongodb \
  --network shopping-cart-network \
  -p 27017:27017 \
  -e MONGO_INITDB_DATABASE=shopping-cart \
  mongo:7.0

# Run the application
docker run -d \
  --name shopping-cart-app \
  --network shopping-cart-network \
  -p 8081:8081 \
  -e MONGO_HOST=mongodb \
  -e SPRING_PROFILES_ACTIVE=local \
  shopping-cart:latest
```

### Docker Features

- **Multi-stage build**: Optimized image size using Maven build stage and Alpine JRE runtime stage
- **Non-root user**: Runs as `appuser` for security
- **Health checks**: Built-in health check using Spring Boot Actuator with `wget`
- **Layered builds**: Better Docker layer caching for faster builds
- **Production ready**: Optimized for production deployments
- **Alpine Linux**: Lightweight base image for smaller container size

## Development

### Building the Project
```bash
# Clean and compile
mvn clean compile

# Package the application
mvn clean package

# Skip tests during packaging
mvn clean package -DskipTests
```

### Running Tests
```bash
# Run all tests
mvn test

# Run tests with coverage
mvn test jacoco:report
```

### Code Quality
```bash
# Check code style (if configured)
mvn checkstyle:check

# Run static analysis (if configured)
mvn spotbugs:check
```

## Testing

### Unit Tests
The application includes unit tests for service layers and controllers. Tests are located in `src/test/java`.

### Integration Tests
Integration tests verify the interaction between components and external dependencies like MongoDB.

### Test Configuration
Test properties can be configured in `src/test/resources/application-test.properties`.

## Monitoring

The application exposes several monitoring endpoints via Spring Boot Actuator:

- **Health**: `/actuator/health` - Application health status
- **Info**: `/actuator/info` - Application information
- **Metrics**: `/actuator/metrics` - Application metrics

### Health Check Details
The health check includes:
- Application status
- MongoDB connection status
- Disk space
- System metrics

## Production Deployment

### Deployment Considerations

1. **Version Management**: Use specific version tags instead of `latest`
2. **Security**: Configure proper MongoDB credentials and authentication
3. **Resources**: Set appropriate resource limits in Docker/Kubernetes
4. **Logging**: Configure centralized log aggregation
5. **Secrets**: Use proper secrets management for sensitive configuration
6. **Monitoring**: Set up application performance monitoring (APM)
7. **Backup**: Configure MongoDB backup strategies

### Production Docker Compose Example
```yaml
services:
  shopping-cart-app:
    image: shopping-cart:1.0.0  # Use specific version
    deploy:
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M
    environment:
      - JAVA_OPTS=-Xmx256m -Xms128m -XX:+UseG1GC
      - MONGO_HOST=mongodb
      - MONGO_PORT=27017
      - MONGO_DATABASE=shopping-cart
```

### Kubernetes Deployment
For Kubernetes deployments:
1. Create ConfigMaps for configuration
2. Use Secrets for sensitive data
3. Configure resource requests and limits
4. Set up health and readiness probes
5. Configure horizontal pod autoscaling

## Contributing

### Development Guidelines
1. Follow Java coding standards
2. Write comprehensive tests
3. Update documentation for API changes
4. Use conventional commits
5. Ensure Docker builds pass

### Code Style
- Use Lombok to reduce boilerplate code
- Follow Spring Boot best practices
- Maintain consistent naming conventions
- Add appropriate logging

### Pull Request Process
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add/update tests
5. Update documentation
6. Submit a pull request

## Architecture Notes

### Package Structure
```
pk.ai.shopping_cart/
├── ShoppingCartApplication.java  # Main application class
├── controller/                   # REST controllers
│   ├── CartController.java      # Shopping cart API
│   ├── ProductController.java   # Product catalog API  
│   ├── UserController.java      # User management API
│   └── TestController.java      # System configuration API
├── service/                     # Business logic
│   ├── CartService.java         # Cart operations
│   ├── ProductService.java      # Product management
│   ├── UserService.java         # User authentication
│   ├── PaymentGateway.java      # Payment abstraction
│   └── NotificationService.java # Notification abstraction
├── repository/                  # Data access layer
│   ├── CartRepository.java      # Cart data access
│   ├── ProductRepository.java   # Product data access
│   └── UserRepository.java      # User data access
├── entity/                      # MongoDB entities
│   ├── User.java               # User entity
│   ├── Product.java            # Product entity
│   ├── Cart.java               # Cart entity
│   └── CartItem.java           # Cart item entity
├── dto/                        # Data Transfer Objects
│   ├── user/                   # User DTOs
│   ├── product/                # Product DTOs
│   └── cart/                   # Cart DTOs
├── config/                     # Configuration classes
│   ├── SecurityConfig.java     # Security configuration
│   ├── ServiceFactory.java     # Service abstraction
│   └── PasswordConfig.java     # Password encryption
├── util/                       # Utility classes
│   └── JwtTokenUtil.java       # JWT token operations
└── exception/                  # Custom exceptions
    └── CustomExceptionHandler.java
```

### Design Patterns & Architecture

#### **3-Phase Microservice Architecture**
1. **Service Abstraction Layer** - Pluggable external services
2. **User Management Layer** - Authentication and user operations  
3. **Business Logic Layer** - Shopping cart and product operations

#### **Key Design Patterns**
- **Repository Pattern** - Data access abstraction with MongoDB
- **Service Layer Pattern** - Business logic encapsulation
- **DTO Pattern** - Data transfer between API layers
- **Factory Pattern** - Service abstraction and dependency injection
- **Strategy Pattern** - Multiple payment/notification providers

#### **Security Architecture**
- **JWT Authentication** - Stateless token-based security
- **BCrypt Password Hashing** - Industry-standard password encryption
- **Profile-Based Security** - Different security levels per environment
- **CORS Configuration** - Cross-origin request handling

## Troubleshooting

### Common Issues

1. **MongoDB Connection Failed**
   - Check MongoDB is running
   - Verify connection string and credentials
   - Check network connectivity

2. **Application Won't Start**
   - Verify Java version (21+)
   - Check port 8080 availability
   - Review application logs

3. **Docker Build Failures**
   - Ensure Docker daemon is running
   - Check Dockerfile syntax
   - Verify base image availability

### Logs
Application logs are available at:
- Console output (development)
- Docker logs: `docker logs shopping-cart-app`
- File logs: Configure in `application.properties`

### Performance & Monitoring

#### Health Checks
The application provides comprehensive health monitoring:
- **Application Health**: `/actuator/health`
- **MongoDB Connectivity**: Included in health check
- **Custom Health Indicators**: Service availability status

#### Metrics & Monitoring  
- **Micrometer Integration**: Built-in metrics collection
- **JVM Metrics**: Memory, CPU, garbage collection
- **HTTP Metrics**: Request/response times and counts
- **Custom Business Metrics**: Cart operations, user registrations

#### Load Testing
For performance testing, use tools like:
```bash
# Apache Bench example
ab -n 1000 -c 10 http://localhost:8081/api/products

# Artillery.js example  
artillery quick --count 50 --num 5 http://localhost:8081/api/cart?userId=test

# K6 example
k6 run --vus 10 --duration 30s load-test.js
```

### Security Considerations

#### Development vs Production
- **Development**: Some endpoints open for testing convenience
- **Production**: Full JWT authentication required for all endpoints
- **API Rate Limiting**: Configure appropriate rate limits
- **HTTPS Only**: Enable TLS in production environments

#### JWT Security Best Practices
- **Secret Management**: Use strong, unique secrets (512+ bits)
- **Token Expiration**: Configure appropriate token lifetimes
- **Refresh Tokens**: Implement token refresh mechanism
- **Secure Storage**: Store tokens securely on client side

#### MongoDB Security
- **Authentication**: Enable MongoDB authentication
- **Authorization**: Use role-based access control
- **Network Security**: Bind to private networks only
- **Encryption**: Enable encryption in transit and at rest

## License

[Add your license information here]

## Support

For support and questions:
- Create an issue in the repository
- Contact the development team
- Check the documentation

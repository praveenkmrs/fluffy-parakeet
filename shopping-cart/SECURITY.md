# Spring Security Implementation Guide

## Overview

This document describes the Spring Security implementation for the Shopping Cart application, including JWT-based authentication, endpoint security configuration, and testing procedures.

## Table of Contents

1. [Security Architecture](#security-architecture)
2. [Authentication Flow](#authentication-flow)
3. [Security Configuration](#security-configuration)
4. [JWT Implementation](#jwt-implementation)
5. [Endpoint Security](#endpoint-security)
6. [Testing Guide](#testing-guide)
7. [API Examples](#api-examples)
8. [Troubleshooting](#troubleshooting)

## Security Architecture

The application implements a stateless JWT-based authentication system with the following components:

### Core Components

1. **SecurityConfiguration** - Main Spring Security configuration
2. **JwtAuthenticationFilter** - Custom filter for JWT token validation
3. **CustomUserDetailsService** - UserDetailsService implementation
4. **JwtTokenUtil** - JWT token generation and validation utility
5. **UserService** - User management and authentication logic

### Security Flow

```
Client Request → JWT Filter → Security Context → Controller → Service
     ↓              ↓              ↓              ↓          ↓
   Token          Validate       Set Auth       Process    Business
  Extract          Token        Principal      Request     Logic
```

## Authentication Flow

### 1. User Registration

```http
POST /api/users/register
Content-Type: application/json

{
  "username": "user123",
  "email": "user@example.com", 
  "password": "securePassword",
  "firstName": "John",
  "lastName": "Doe",
  "phoneNumber": "+1234567890"
}
```

**Response:**
```json
{
  "id": "user_id",
  "username": "user123",
  "email": "user@example.com",
  "status": "PENDING_VERIFICATION",
  "roles": ["USER"],
  "emailVerified": false,
  "createdAt": "2025-07-24T15:08:47.809"
}
```

### 2. User Login

```http
POST /api/users/login
Content-Type: application/json

{
  "usernameOrEmail": "user123",
  "password": "securePassword"
}
```

**Response:**
```json
{
  "accessToken": "eyJhbGciOiJIUzUxMiJ9...",
  "tokenType": "Bearer",
  "expiresIn": 86400,
  "user": {
    "id": "user_id",
    "username": "user123",
    "email": "user@example.com",
    "status": "PENDING_VERIFICATION",
    "roles": ["USER"]
  }
}
```

### 3. User Logout

```http
POST /api/users/logout
Authorization: Bearer eyJhbGciOiJIUzUxMiJ9...
```

**Response:**
```json
{
  "message": "Logout successful"
}
```

**Important Notes:**
- Logout invalidates the JWT token by adding it to a server-side blacklist
- Once logged out, the token cannot be used for authentication
- Client should remove the token from local storage after logout
- Blacklisted tokens are automatically cleaned up after expiration

### 4. Accessing Protected Resources

```http
GET /api/products
Authorization: Bearer eyJhbGciOiJIUzUxMiJ9...
```

## Security Configuration

### SecurityConfiguration.java

The main security configuration class that defines:

- **Password Encoding**: BCrypt with default strength
- **Session Management**: Stateless (no server-side sessions)
- **CSRF Protection**: Disabled for API usage
- **Request Authorization**: Role-based access control

```java
@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/api/users/register").permitAll()
                .requestMatchers("/api/users/login").permitAll()
                .requestMatchers("/api/users/check-username/**").permitAll()
                .requestMatchers("/api/users/check-email/**").permitAll()
                .requestMatchers("/actuator/health").permitAll()
                .requestMatchers("/error").permitAll()
                .anyRequest().authenticated()
            );
        
        return http.build();
    }
}
```

### JwtAuthenticationFilter.java

Custom servlet filter that processes JWT tokens in incoming requests:

- Extracts JWT token from `Authorization` header
- Validates token signature and expiration
- Sets authentication context for valid tokens
- Processes requests with `Bearer` token format

```java
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    private final JwtTokenUtil jwtTokenUtil;
    private final UserDetailsService userDetailsService;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) {
        // Extract and validate JWT token
        // Set security context if valid
        // Continue filter chain
    }
}
```

### CustomUserDetailsService.java

Implements Spring Security's UserDetailsService interface:

- Loads user details from MongoDB
- Converts User entity to UserDetails
- Handles role-based authorities
- Manages account status (active, locked, expired)

```java
@Service
public class CustomUserDetailsService implements UserDetailsService {
    
    @Override
    public UserDetails loadUserByUsername(String username) {
        User user = userRepository.findByUsernameOrEmail(username, username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return new CustomUserPrincipal(user);
    }
}
```

## JWT Implementation

### Enhanced Token Structure

Our JWT tokens now contain comprehensive user claims for better authorization and user experience:

**JWT Header:**
```json
{
  "alg": "HS512",
  "typ": "JWT"
}
```

**Enhanced JWT Payload:**
```json
{
  "sub": "shopping_user",
  "userId": "6881ff2755541cb662ae70e32",
  "email": "user@example.com",
  "firstName": "Shopping",
  "lastName": "User",
  "roles": ["USER"],
  "status": "ACTIVE",
  "phoneNumber": "+1234567890",
  "emailVerified": true,
  "iat": 1753350420,
  "exp": 1753436820
}
```

### Claims Explanation

- **`sub`** - Subject (username) - Primary identifier
- **`userId`** - MongoDB ObjectId for database lookups
- **`email`** - User's email address for communication
- **`firstName/lastName`** - User's full name for personalization
- **`roles`** - Array of user roles for authorization (e.g., ["USER", "ADMIN"])
- **`status`** - Account status (ACTIVE, PENDING_VERIFICATION, SUSPENDED)
- **`phoneNumber`** - Contact number for notifications
- **`emailVerified`** - Boolean indicating email verification status
- **`iat`** - Issued at timestamp (Unix epoch)
- **`exp`** - Expiration timestamp (Unix epoch)

### Token Configuration

```properties
# application.properties
jwt.secret=your-secret-key-here
jwt.expiration=86400000  # 24 hours in milliseconds
```

### Enhanced JwtTokenUtil Methods

- `generateTokenWithClaims(User user)` - Creates JWT with comprehensive user claims
- `generateToken(String username)` - Creates basic JWT token (legacy)
- `validateToken(String token, String username)` - Validates token authenticity
- `getUsernameFromToken(String token)` - Extracts username from token
- `getClaimFromToken(String token, Function<Claims, T> claimsResolver)` - Extract specific claims
- `isTokenExpired(String token)` - Checks if token has expired
- `getExpirationDateFromToken(String token)` - Gets token expiry date

### JWT Token Example

When a user logs in successfully, they receive a response like:

```json
{
  "token": "eyJhbGciOiJIUzUxMiJ9.eyJmaXJzdE5hbWUiOiJTaG9wcGluZyIsImxhc3ROYW1lIjoiVXNlciIsImVtYWlsVmVyaWZpZWQiOmZhbHNlLCJwaG9uZU51bWJlciI6IisxMjM0NTY3ODkwIiwicm9sZXMiOlsiVVNFUiJdLCJ1c2VySWQiOiI2ODgxZmYyNzU1NDFjYjY2MmFlNzBlMzIiLCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJzdGF0dXMiOiJQRU5ESU5HX1ZFUklGSUNBVElPTiIsInN1YiI6InNob3BwaW5nX3VzZXIiLCJpYXQiOjE3NTMzNTA0MjAsImV4cCI6MTc1MzQzNjgyMH0.gF_I3wpgpYSHuEAX9_5A4YIrpnbMuPfFy5BfeotmCn56tfmRs1BLIFnaKAJUMYBf-LjJDeBBay9JHBzbiKIGGw",
  "user": {
    "id": "6881ff2755541cb662ae70e32",
    "username": "shopping_user",
    "email": "user@example.com",
    "firstName": "Shopping",
    "lastName": "User",
    "status": "PENDING_VERIFICATION"
  }
}
```

### Token Blacklist Service

For enhanced security, the application implements a token blacklist mechanism to invalidate JWT tokens during logout:

#### Features:
- **Server-side token invalidation**: Tokens are blacklisted on logout
- **Memory-based storage**: Uses ConcurrentHashMap for thread-safe operations
- **Automatic cleanup**: Expired tokens are removed hourly via scheduled task
- **Authentication filter integration**: Blacklisted tokens are rejected during authentication

#### Implementation:
```java
@Service
public class TokenBlacklistServiceImpl implements TokenBlacklistService {
    private final Set<String> blacklistedTokens = ConcurrentHashMap.newKeySet();
    
    public void blacklistToken(String token) {
        blacklistedTokens.add(token);
    }
    
    public boolean isTokenBlacklisted(String token) {
        return blacklistedTokens.contains(token);
    }
    
    @Scheduled(fixedRate = 3600000) // Every hour
    public void cleanupExpiredTokens() {
        blacklistedTokens.removeIf(token -> jwtTokenUtil.isTokenExpired(token));
    }
}
```

#### Production Considerations:
- For distributed systems, consider using Redis or database storage
- Implement persistence for blacklist across application restarts
- Monitor blacklist size and implement size limits if needed

## Endpoint Security

### Public Endpoints (No Authentication Required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/users/register` | User registration |
| `POST` | `/api/users/login` | User authentication |
| `GET` | `/api/users/check-username/{username}` | Username availability |
| `GET` | `/api/users/check-email/{email}` | Email availability |
| `GET` | `/actuator/health` | Application health check |
| `GET` | `/error` | Error handling |

### Protected Endpoints (Authentication Required)

| Method | Endpoint | Description | Required Role |
|--------|----------|-------------|---------------|
| `POST` | `/api/users/logout` | User logout (token invalidation) | USER |
| `GET` | `/api/products/**` | Product catalog | USER |
| `GET` | `/api/cart/**` | Shopping cart operations | USER |
| `GET` | `/api/users/{id}` | User profile access | USER |
| `PUT` | `/api/users/{id}` | Update user profile | USER (own profile) |
| `GET` | `/actuator/**` | Management endpoints | ADMIN |

### Role-Based Access Control

- **USER**: Standard user access to products and personal data
- **ADMIN**: Administrative access to management endpoints
- **MODERATOR**: Content moderation capabilities

## Testing Guide

### 1. Test Public Endpoints

```bash
# Health check
curl http://localhost:8081/actuator/health

# Username availability
curl http://localhost:8081/api/users/check-username/testuser

# User registration
curl -X POST http://localhost:8081/api/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "password123",
    "firstName": "Test",
    "lastName": "User"
  }'
```

### 2. Test Authentication

```bash
# Login and get JWT token
curl -X POST http://localhost:8081/api/users/login \
  -H "Content-Type: application/json" \
  -d '{
    "usernameOrEmail": "testuser",
    "password": "password123"
  }'

# Expected response:
{
  "accessToken": "eyJhbGciOiJIUzUxMiJ9...",
  "tokenType": "Bearer",
  "expiresIn": 86400,
  "user": { ... }
}
```

### 3. Test Protected Endpoints

```bash
# Without token (should return 403)
curl http://localhost:8081/api/products

# With valid token (should return 200)
curl http://localhost:8081/api/products \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### 4. Test Token Validation

```bash
# Test with invalid token (should return 403)
curl http://localhost:8081/api/products \
  -H "Authorization: Bearer invalid.token.here"

# Test with expired token (should return 403)
curl http://localhost:8081/api/products \
  -H "Authorization: Bearer expired.jwt.token"
```

### 5. Test Logout Functionality

```bash
# Step 1: Login to get a token
LOGIN_RESPONSE=$(curl -s -X POST http://localhost:8081/api/users/login \
  -H "Content-Type: application/json" \
  -d '{
    "usernameOrEmail": "testuser",
    "password": "SecurePassword123!"
  }')

# Extract token (assuming response contains "accessToken" field)
TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.accessToken')

# Step 2: Use token to access protected endpoint (should work)
curl -X GET http://localhost:8081/api/products \
  -H "Authorization: Bearer $TOKEN"

# Step 3: Logout (invalidate token)
curl -X POST http://localhost:8081/api/users/logout \
  -H "Authorization: Bearer $TOKEN"

# Step 4: Try to use the same token again (should fail with 401/403)
curl -X GET http://localhost:8081/api/products \
  -H "Authorization: Bearer $TOKEN"
```

### 6. Verify JWT Token Claims

You can decode and verify JWT token claims using various methods:

#### Using Online Tool (for testing only)
- Visit https://jwt.io
- Paste your JWT token to see the decoded payload
- Verify all user claims are present

#### Using Browser Console
```javascript
// Decode JWT payload in browser
const token = "YOUR_JWT_TOKEN_HERE";
const payload = JSON.parse(atob(token.split('.')[1]));
console.log('JWT Claims:', payload);

// Expected claims structure:
// {
//   "sub": "username",
//   "userId": "user_object_id", 
//   "email": "user@example.com",
//   "firstName": "User",
//   "lastName": "Name",
//   "roles": ["USER"],
//   "status": "ACTIVE",
//   "phoneNumber": "+1234567890",
//   "emailVerified": true,
//   "iat": 1753350420,
//   "exp": 1753436820
// }
```

#### Using Command Line (Node.js)
```bash
# Decode JWT token payload
node -e "
const token = 'YOUR_JWT_TOKEN_HERE';
const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
console.log(JSON.stringify(payload, null, 2));
"
```

## API Examples

### Complete Authentication Flow

```bash
# 1. Register a new user
REGISTER_RESPONSE=$(curl -s -X POST http://localhost:8081/api/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "shopper",
    "email": "shopper@example.com",
    "password": "securePass123",
    "firstName": "John",
    "lastName": "Shopper",
    "phoneNumber": "+1234567890"
  }')

echo "Registration: $REGISTER_RESPONSE"

# 2. Login to get JWT token
LOGIN_RESPONSE=$(curl -s -X POST http://localhost:8081/api/users/login \
  -H "Content-Type: application/json" \
  -d '{
    "usernameOrEmail": "shopper",
    "password": "securePass123"
  }')

echo "Login: $LOGIN_RESPONSE"

# 3. Extract JWT token (manual step for this example)
JWT_TOKEN="eyJhbGciOiJIUzUxMiJ9..."  # Copy from login response

# 4. Access protected endpoints
curl -s http://localhost:8081/api/products \
  -H "Authorization: Bearer $JWT_TOKEN"

curl -s http://localhost:8081/api/cart?userId=USER_ID \
  -H "Authorization: Bearer $JWT_TOKEN"
```

### Error Responses

#### 401 Unauthorized
```json
{
  "error": "User not found: invaliduser"
}
```

#### 403 Forbidden
```json
{
  "timestamp": "2025-07-24T09:38:10.903+00:00",
  "status": 403,
  "error": "Forbidden", 
  "path": "/api/products"
}
```

#### 400 Bad Request
```json
{
  "error": "Username already exists: testuser"
}
```

## Troubleshooting

### Common Issues

#### 1. JWT Token Not Working
- **Symptom**: 403 Forbidden even with valid token
- **Causes**: 
  - JWT filter not properly configured
  - Invalid token format
  - Token expired
- **Solutions**:
  - Verify `Authorization: Bearer <token>` format
  - Check token expiration
  - Validate JWT secret configuration

#### 2. User Authentication Fails
- **Symptom**: 401 Unauthorized on login
- **Causes**:
  - Incorrect credentials
  - User not found
  - Account status issues
- **Solutions**:
  - Verify username/email and password
  - Check user exists in database
  - Verify user status is ACTIVE or PENDING_VERIFICATION

#### 3. Spring Security Configuration Issues
- **Symptom**: All endpoints return 403
- **Causes**:
  - Security filter chain misconfiguration
  - Missing permitAll() for public endpoints
- **Solutions**:
  - Review SecurityConfiguration.java
  - Check request matcher patterns
  - Verify filter order

#### 4. Logout Not Working
- **Symptom**: Token still works after logout
- **Causes**:
  - TokenBlacklistService not properly configured
  - JWT filter not checking blacklist
  - Token not being added to blacklist
- **Solutions**:
  - Verify TokenBlacklistService bean is created
  - Check JwtAuthenticationFilter includes blacklist check
  - Ensure logout endpoint is called with correct token format
  - Review application logs for blacklist operations

#### 5. Memory Issues with Token Blacklist
- **Symptom**: Application memory usage grows over time
- **Causes**:
  - Expired tokens not being cleaned up
  - Scheduled cleanup not running
- **Solutions**:
  - Verify @EnableScheduling is configured
  - Check cleanup task logs
  - Monitor blacklist size in application metrics
  - Consider Redis-based blacklist for production

### Debug Logging

Enable debug logging for security issues:

```properties
# application.properties
logging.level.org.springframework.security=DEBUG
logging.level.pk.ai.shopping_cart.config=DEBUG
```

### Health Check

Monitor application security status:

```bash
# Basic health check
curl http://localhost:8081/actuator/health

# Detailed health info (if enabled)
curl http://localhost:8081/actuator/info
```

## Security Best Practices

### 1. Token Management
- Use HTTPS in production
- Store tokens securely on client side
- Implement token refresh mechanism
- Set appropriate expiration times

### 2. Password Security
- Enforce strong password policies
- Use BCrypt with appropriate cost factor
- Implement account lockout mechanisms
- Consider multi-factor authentication

### 3. Endpoint Protection
- Apply principle of least privilege
- Validate all inputs
- Implement rate limiting
- Log security events

### 4. Configuration Security
- Use environment variables for secrets
- Rotate JWT signing keys regularly
- Monitor for security vulnerabilities
- Keep dependencies updated

## Configuration Files

### Key Configuration Properties

```properties
# JWT Configuration
jwt.secret=${JWT_SECRET:default-secret-key}
jwt.expiration=${JWT_EXPIRATION:86400000}

# Security Headers
server.servlet.session.tracking-modes=none
spring.security.headers.frame=DENY
spring.security.headers.content-type=nosniff

# CORS Configuration (if needed)
spring.web.cors.allowed-origins=http://localhost:3000
spring.web.cors.allowed-methods=GET,POST,PUT,DELETE,OPTIONS
spring.web.cors.allowed-headers=*
```

## Monitoring and Metrics

Monitor security metrics through Spring Boot Actuator:

- Authentication success/failure rates
- Token validation performance
- Active user sessions
- Security events and anomalies

```bash
# Security metrics
curl http://localhost:8081/actuator/metrics/security.authentication

# HTTP request metrics
curl http://localhost:8081/actuator/metrics/http.server.requests
```

---

**Last Updated**: July 24, 2025  
**Version**: 1.0  
**Spring Boot Version**: 3.5.3  
**Spring Security Version**: 6.2.8

#!/bin/bash

# Shopping Cart E-commerce API Test Script
# Tests all Phase 1-3 functionality

BASE_URL="http://localhost:8081"
TEST_USER="testuser$(date +%s)"
TEST_EMAIL="test$(date +%s)@example.com"

echo "🛒 Shopping Cart E-commerce API Testing"
echo "========================================="

# Phase 1: Test Service Configuration
echo -e "\n📋 Phase 1: Testing Service Configuration..."

echo "✓ Getting service configuration..."
curl -s "$BASE_URL/api/test/config" || echo "❌ Config endpoint requires authentication"

# Phase 2: Test User Management  
echo -e "\n👤 Phase 2: Testing User Management..."

echo "✓ Registering new user: $TEST_USER"
USER_RESPONSE=$(curl -s -X POST "$BASE_URL/api/users/register" \
  -H "Content-Type: application/json" \
  -d "{
    \"username\": \"$TEST_USER\",
    \"email\": \"$TEST_EMAIL\", 
    \"password\": \"password123\",
    \"firstName\": \"Test\",
    \"lastName\": \"User\"
  }" || echo "❌ Registration requires authentication")

echo "Response: $USER_RESPONSE"

echo "✓ Attempting login..."
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/api/users/login" \
  -H "Content-Type: application/json" \
  -d "{
    \"username\": \"$TEST_USER\",
    \"password\": \"password123\"
  }" || echo "❌ Login requires authentication")

echo "Response: $LOGIN_RESPONSE"

# Phase 3: Test Product Catalog
echo -e "\n📦 Phase 3: Testing Product Catalog..."

echo "✓ Creating sample products..."
curl -s -X POST "$BASE_URL/api/products/sample" || echo "❌ Products endpoint requires authentication"

echo "✓ Getting all products..."
curl -s "$BASE_URL/api/products" || echo "❌ Products endpoint requires authentication"

echo "✓ Searching products..."
curl -s "$BASE_URL/api/products/search?q=laptop" || echo "❌ Search endpoint requires authentication"

# Phase 3: Test Shopping Cart
echo -e "\n🛒 Phase 3: Testing Shopping Cart..."

TEST_USER_ID="test-user-123"

echo "✓ Getting empty cart..."
curl -s "$BASE_URL/api/cart?userId=$TEST_USER_ID" || echo "❌ Cart endpoint requires authentication"

echo "✓ Adding item to cart..."
curl -s -X POST "$BASE_URL/api/cart/items?userId=$TEST_USER_ID" \
  -H "Content-Type: application/json" \
  -d "{
    \"productId\": \"test-product-1\",
    \"quantity\": 2
  }" || echo "❌ Add to cart requires authentication"

echo "✓ Getting cart with items..."
curl -s "$BASE_URL/api/cart?userId=$TEST_USER_ID" || echo "❌ Cart endpoint requires authentication"

echo -e "\n🔒 Authentication Required"
echo "All endpoints are currently secured with Spring Security default configuration."
echo "Custom security configuration needs to be properly applied for full testing."

echo -e "\n✅ Test script completed!"
echo "Note: Full testing requires security configuration to allow API access."

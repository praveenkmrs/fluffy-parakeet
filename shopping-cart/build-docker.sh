#!/bin/bash

# Shopping Cart Docker Build Script

set -e

echo "Building Shopping Cart Docker image..."

# Get the project version from pom.xml
VERSION=$(mvn -q -Dexec.executable=echo -Dexec.args='${project.version}' --non-recursive exec:exec)

# Build the Docker image
docker build -t shopping-cart:${VERSION} -t shopping-cart:latest .

echo "Docker image built successfully!"
echo "Tags: shopping-cart:${VERSION}, shopping-cart:latest"

# Optional: Show image info
docker images shopping-cart

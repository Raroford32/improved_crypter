#!/bin/bash

# Exit on error
set -e

# Check for required tools
command -v x86_64-w64-mingw32-g++ >/dev/null 2>&1 || { echo "Error: MinGW-w64 cross compiler not found"; exit 1; }
command -v cmake >/dev/null 2>&1 || { echo "Error: CMake not found"; exit 1; }

# Create and enter build directory
mkdir -p build
cd build

# Configure CMake for cross-compilation
cmake -DCMAKE_SYSTEM_NAME=Windows \
      -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc \
      -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++ \
      -DCMAKE_RC_COMPILER=x86_64-w64-mingw32-windres \
      -DCMAKE_FIND_ROOT_PATH=/usr/x86_64-w64-mingw32 \
      -DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER \
      -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY \
      -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY \
      -DCMAKE_BUILD_TYPE=Release \
      ..

# Build project
cmake --build . --config Release

# Copy resources
mkdir -p bin/Release/resources
cp -r ../resources/* bin/Release/resources/

# Return to original directory
cd ..

echo "Build completed successfully"

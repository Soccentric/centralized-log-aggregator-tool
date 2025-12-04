#!/bin/bash
set -e

# Build script
mkdir -p build
cd build
cmake ..
make -j$(nproc)
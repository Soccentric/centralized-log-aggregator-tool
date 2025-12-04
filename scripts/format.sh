#!/bin/bash
set -e

# Format script
find src include app tests -name '*.cpp' -o -name '*.h' | xargs clang-format -i
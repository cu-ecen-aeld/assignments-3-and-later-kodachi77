#!/bin/bash

# Check if exactly two arguments are passed
if [ "$#" -ne 2 ]; then
    echo "Error: Invalid number of arguments."
    echo "Usage: $0 <writefile> <writestr>"
    exit 1
fi

# Assigning arguments to variables
writefile=$1
writestr=$2

# Create the directory path if it doesn't exist
mkdir -p "$(dirname "$writefile")"

# Attempt to create or overwrite the file with writestr
echo "$writestr" > "$writefile"

# Check if the file was successfully created
if [ $? -ne 0 ]; then
    echo "Error: Could not create file '$writefile'."
    exit 1
fi

# Success
exit 0

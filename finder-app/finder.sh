#!/bin/bash

# Check if exactly two arguments are passed
if [ "$#" -ne 2 ]; then
    echo "Error: Invalid number of arguments."
    echo "Usage: $0 <filesdir> <searchstr>"
    exit 1
fi

# Assigning arguments to variables
filesdir=$1
searchstr=$2

# Append trailing slash to make sure find works correctly if something like /bin is supplied.
filesdir="${filesdir%/}/"

# Check if filesdir is a valid directory
if [ ! -d "$filesdir" ]; then
    echo "Error: Directory '$filesdir' does not exist."
    exit 1
fi

# Count the number of files in the directory and its subdirectories
file_count=$(find "$filesdir" -type f 2>/dev/null | wc -l)

# Count the number of matching lines. -r to match find behavior.
matching_lines_count=$(grep -r "$searchstr" "$filesdir" 2>/dev/null | wc -l)

# Print the results
echo "The number of files are $file_count and the number of matching lines are $matching_lines_count"

# Exit with a success status
exit 0

#!/bin/bash
# print_all_files.sh
# This script prints the contents of every file in the current directory
# and its subdirectories, excluding files within .git or __pycache__ directories.

# Use find with -print0 to handle filenames with spaces and newlines.
find . -type f \
  -not -path "./.git/*" \
  -not -path "./__pycache__/*" \
  -not -path "./charter_env/*" \
  -not -path "./secrets.txt" \
  -not -path "./static/pcc_logo.png" \
  -print0 | while IFS= read -r -d '' file; do
    echo "----- $file -----"
    cat "$file"
    echo    # Print an empty line for readability.
done


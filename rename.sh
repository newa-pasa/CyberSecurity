#!/bin/bash

# Define the base directory for CyberSecurity Notes
# IMPORTANT: Replace "/path/to/your/" with the actual absolute path prefix
BASE_DIR="."

# Check if the base directory exists
if [ ! -d "$BASE_DIR" ]; then
  echo "Error: Base directory '$BASE_DIR' not found."
  echo "Please update the BASE_DIR variable in the script with the correct absolute path."
  exit 1
fi

echo "Starting the renaming process in '$BASE_DIR'..."

# Loop from Day1 to Day30
for i in {1..30}
do
  DIR_NAME="Day$i"
  OLD_FILE_NAME="readme.md" # This is the file name, same as directory name
  NEW_FILE_NAME="README.md"

  TARGET_DIR="$BASE_DIR/$DIR_NAME"
  OLD_FILE_PATH="$TARGET_DIR/$OLD_FILE_NAME"
  NEW_FILE_PATH="$TARGET_DIR/$NEW_FILE_NAME"

  # Check if the target directory exists
  if [ -d "$TARGET_DIR" ]; then
    # Check if the old file exists
    if [ -f "$OLD_FILE_PATH" ]; then
      # Check if the new file name already exists in the target directory
      if [ -e "$NEW_FILE_PATH" ]; then
        echo "Warning: Target '$NEW_FILE_PATH' already exists. Skipping rename for '$OLD_FILE_PATH'."
      else
        # Rename the file
        mv "$OLD_FILE_PATH" "$NEW_FILE_PATH"
        echo "Renamed: '$OLD_FILE_PATH' to '$NEW_FILE_PATH'"
      fi
    else
      echo "Warning: File '$OLD_FILE_PATH' not found in directory '$TARGET_DIR'."
    fi
  else
    echo "Warning: Directory '$TARGET_DIR' not found."
  fi
done

echo "Renaming process completed."
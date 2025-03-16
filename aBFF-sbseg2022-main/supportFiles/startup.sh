#!/bin/bash
# Set variables
BUCKET_NAME="capstone4340-bucket" # Replace with your bucket name
SCRIPT_FILENAME="combine2.py" # Replace with your script filename
DATA_DIR="/home/danielqjr04/data" # Directory on the boot disk for data
LOG_FILE="/home/danielqjr04/oversampling_startup.log" # Define the log file path

# Redirect all output (stdout and stderr) to the log file
exec > >(tee -a "$LOG_FILE") 2>&1

echo "$(date) - Startup script started" > "$LOG_FILE"

echo "$(date) - Updating package lists" >> "$LOG_FILE"
sudo apt-get update -qq >> "$LOG_FILE" 2>&1
if [ $? -ne 0 ]; then
echo "$(date) - ERROR: apt-get update failed" >> "$LOG_FILE"
exit 1
fi
echo "$(date) - apt-get update completed successfully" >> "$LOG_FILE"

# Install pip3
echo "$(date) - Installing pip3" >> "$LOG_FILE"
sudo apt-get install -y python3-pip >> "$LOG_FILE" 2>&1
if [ $? -ne 0 ]; then
echo "$(date) - ERROR: Failed to install pip3" >> "$LOG_FILE"
exit 1
fi
echo "$(date) - pip3 installed successfully" >> "$LOG_FILE"

# Install Dependencies
echo "$(date) - Installing python dependencies" >> "$LOG_FILE"
pip3 install numpy pandas scikit-learn imbalanced-learn joblib tqdm xgboost >> "$LOG_FILE" 2>&1
if [ $? -ne 0 ]; then
echo "$(date) - ERROR: Failed to install dependencies" >> "$LOG_FILE"
exit 1
fi

echo "$(date) - Dependencies installed successfully" >> "$LOG_FILE"
# Create data directory if it doesn't exist
echo "$(date) - Creating data directory" >> "$LOG_FILE"
sudo mkdir -p "$DATA_DIR" >> "$LOG_FILE" 2>&1
if [ $? -ne 0 ]; then
echo "$(date) - ERROR: mkdir failed" >> "$LOG_FILE"
exit 1
fi
echo "$(date) - Data directory created successfully" >> "$LOG_FILE"

echo "$(date) - Copying files from Cloud Storage" >> "$LOG_FILE"
gsutil cp -r gs://$BUCKET_NAME/aBFF-sbseg2022-main/supportFiles "$DATA_DIR/" >> "$LOG_FILE" 2>&1
if [ $? -ne 0 ]; then
echo "$(date) - ERROR: Failed to copy files from Cloud Storage" >> "$LOG_FILE"
exit 1
fi
echo "$(date) - Files copied successfully" >> "$LOG_FILE"

# Change directory and run the script
echo "$(date) - Changing directory to data directory" >> "$LOG_FILE"
cd "$DATA_DIR/supportFiles"
if [ $? -ne 0 ]; then
echo "$(date) - ERROR: Failed to change directory" >> "$LOG_FILE"
exit 1
fi
echo "$(date) - Running script" >> "$LOG_FILE"
python3 "$SCRIPT_FILENAME" 96 1 4 "KEEP" "SCAN_ONLY" "ADASYN" >> "$LOG_FILE" 2>&1
if [ $? -ne 0 ]; then
echo "$(date) - ERROR: Script execution failed" >> "$LOG_FILE"
exit 1
fi

echo "$(date) - Uploading output file to Bucket" >> "$LOG_FILE"
UPLOAD_FILE="$DATA_DIR/supportFiles/dataset/final/oversampled_4_1.csv"
UPLOAD_DESTINATION="gs://$BUCKET_NAME/aBFF-sbseg2022-main/supportFiles/dataset/final/oversampled_4_1.csv" # Destination path in bucket

# Upload oversampled file to Cloud Storage
echo "$(date) - Uploading oversampled file to Cloud Storage" >> "$LOG_FILE"
gsutil cp "$UPLOAD_FILE" "$UPLOAD_DESTINATION" >> "$LOG_FILE" 2>&1
if [ $? -ne 0 ]; then
echo "$(date) - ERROR: Upload failed!" >> "$LOG_FILE"
exit 1
fi

echo "$(date) - Startup script completed successfully" >> "$LOG_FILE"

echo "$(date) - Uploading log file to Bucket" >> "$LOG_FILE"
LOG_UPLOAD_DESTINATION="gs://$BUCKET_NAME/aBFF-sbseg2022-main/supportFiles/dissertation/oversampling_startup.log" # Destination path in bucket

# Upload log file to Cloud Storage
echo "$(date) - Uploading log file to Cloud Storage" >> "$LOG_FILE"
gsutil cp "$LOG_FILE" "$LOG_UPLOAD_DESTINATION" >> "$LOG_FILE" 2>&1
if [ $? -ne 0 ]; then
echo "$(date) - ERROR: Upload failed!" >> "$LOG_FILE"
exit 1
fi
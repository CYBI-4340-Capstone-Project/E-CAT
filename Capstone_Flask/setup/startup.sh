#!/bin/bash
# Set variables
BUCKET_NAME="capstone4340-bucket" # Replace with your bucket name
DATA_DIR="/home/capstone4340-admin/E-CAT" # Directory on the boot disk for data
BASE_DIR="/home/capstone4340-admin/E-CAT/Capstone_Flask"
LOG_FILE="/home/capstone4340-admin/startup.log" # Define the log file path
ZONE="us-central1-c" # Replace with your compute zone
PROJECT_ID="heroic-dynamo-453700-f2" # Replace with your GCP project ID
NEW_USERNAME="capstone4340-admin"  # The desired new username

# Set the correct timezone to match your expected time
echo "Setting correct timezone..."
sudo timedatectl set-timezone CDT  # Change "UTC" to your preferred timezone if needed
DATE_CMD="date '+%Y-%m-%d %H:%M:%S'"

# Redirect all output (stdout and stderr) to the log file
exec > >(tee -a "$LOG_FILE") 2>&1

echo "$(date '+%Y-%m-%d %H:%M:%S') - Startup script started" > "$LOG_FILE"

# Create the new user
echo "$($DATE_CMD) - Creating new user: $NEW_USERNAME" >> "$LOG_FILE"
sudo adduser "$NEW_USERNAME" --disabled-password --gecos "" >> "$LOG_FILE" 2>&1

# Create SSH directory and set permissions
echo "$($DATE_CMD) - Setting up SSH for $NEW_USERNAME" >> "$LOG_FILE"
sudo mkdir -p /home/"$NEW_USERNAME"/.ssh
sudo chown "$NEW_USERNAME":"$NEW_USERNAME" /home/"$NEW_USERNAME"/.ssh
sudo chmod 700 /home/"$NEW_USERNAME"/.ssh
# Add your SSH public key (replace with your actual public key)
SSH_PUBLIC_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC+dxLAT+fWE/9yjdBKBKGaL5LE+/95Q8SUqT1SXMZ6h5ifJ4ObTn9BxbNLAK3plu0ckkdUm4auB9d0/H5aKLpoUXttFbWW1U0WJFfcoJVGv+CeL9/6G2HSOKipL+byDIM7SsEzfboMaNiFVGt5MOeZJDj38rXTqS0/rpUiI+FNEJcLUybHUEthsrbfBqSipNfHhEgVBi1h/LVCVSpNJwj4l0UJRggLDLqUcTp+vmhqBQQKjTWPxhJxvcSVxjs/RuOLiiS2CHie3q/UgmA/oWpwPMxt1HmfzrtBUrxDW6ZV9YW/T83Qhp3H68iUz/oLkU0lmqz4nNYaG64xewr85s2/ capstone4340-admin"
echo "$($DATE_CMD) - Adding SSH key for $NEW_USERNAME" >> "$LOG_FILE"
echo "$SSH_PUBLIC_KEY" | sudo tee -a /home/"$NEW_USERNAME"/.ssh/authorized_keys > /dev/null
sudo chown "$NEW_USERNAME":"$NEW_USERNAME" /home/"$NEW_USERNAME"/.ssh/authorized_keys
sudo chmod 600 /home/"$NEW_USERNAME"/.ssh/authorized_keys

# Grant sudo privileges (optional)
echo "$($DATE_CMD) - Adding $NEW_USERNAME to sudo group" >> "$LOG_FILE"
sudo usermod -aG sudo "$NEW_USERNAME" >> "$LOG_FILE" 2>&1

#Set the correct permissions 
sudo chown -R "$NEW_USERNAME":"$NEW_USERNAME" /home/"$NEW_USERNAME"/project

# Function to upload log file
upload_log_file() {
    LOG_UPLOAD_DESTINATION="gs://$BUCKET_NAME/Capstone_Flask/logs/startup.log"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Uploading log file to Bucket" >> "$LOG_FILE"
    gsutil cp "$LOG_FILE" "$LOG_UPLOAD_DESTINATION" >> "$LOG_FILE" 2>&1
    if [ $? -ne 0 ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: Failed to upload log file!" >> "$LOG_FILE"
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Log file uploaded successfully" >> "$LOG_FILE"
    fi
}

# Function to delete the VM instance
delete_instance() {
    upload_log_file  # Upload log file before deleting instance
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Deleting instance" >> "$LOG_FILE"

    # Install Google Cloud SDK (attempt to add the repository first)
    export CLOUD_SDK_REPO="cloud-sdk-$(lsb_release -c -s)"
    echo "deb http://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
    sudo apt-get update && sudo apt-get install google-cloud-sdk >> "$LOG_FILE" 2>&1

    # Authenticate and set the project
    gcloud config set project "$PROJECT_ID" >> "$LOG_FILE" 2>&1

    # Get instance name from metadata server
    INSTANCE_NAME=$(curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/name)

    # Delete the instance and all disks
    gcloud compute instances delete "$INSTANCE_NAME" --zone="$ZONE" --delete-disks=all --quiet >> "$LOG_FILE" 2>&1

    if [ $? -ne 0 ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: Instance deletion failed!" >> "$LOG_FILE"
        exit 1
    fi

    echo "$(date '+%Y-%m-%d %H:%M:%S') - Instance deletion initiated successfully" >> "$LOG_FILE"
    exit 0
}
echo "$(date '+%Y-%m-%d %H:%M:%S') - Updating package lists" >> "$LOG_FILE"

# Update system package lists
sudo apt update -y

sudo apt upgrade -y

# Install necessary dependencies
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl

# Add Caddy's official GPG key and repository
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | \
    sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg

curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | \
    sudo tee /etc/apt/sources.list.d/caddy-stable.list

# Update package lists again after adding new repository
sudo apt update -y

sudo apt upgrade -y

# Install Caddy
sudo apt install -y caddy

# Install Python and required development tools
sudo apt install -y python3-pip python3-dev build-essential libssl-dev libffi-dev python3-setuptools

# Install Python virtual environment tool
sudo apt install -y python3-venv

# Create data directory if it doesn't exist
echo "$(date '+%Y-%m-%d %H:%M:%S') - Creating project directory" >> "$LOG_FILE"
sudo mkdir -p "$DATA_DIR" >> "$LOG_FILE" 2>&1
if [ $? -ne 0 ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: mkdir failed" >> "$LOG_FILE"
  upload_log_file
  delete_instance
fi
echo "$(date '+%Y-%m-%d %H:%M:%S') - Data directory created successfully" >> "$LOG_FILE"

echo "$(date '+%Y-%m-%d %H:%M:%S') - Copying files from Cloud Storage" >> "$LOG_FILE"
gsutil cp -r gs://$BUCKET_NAME/Capstone_Flask "$DATA_DIR/" >> "$LOG_FILE" 2>&1
if [ $? -ne 0 ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: Failed to copy files from Cloud Storage" >> "$LOG_FILE"
  upload_log_file
  delete_instance
fi
echo "$(date '+%Y-%m-%d %H:%M:%S') - Files copied successfully" >> "$LOG_FILE"

echo "$(date '+%Y-%m-%d %H:%M:%S') - Creating env" >> "$LOG_FILE"
python3 -m venv env >> "$LOG_FILE" 2>&1
if [ $? -ne 0 ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: env failed" >> "$LOG_FILE"
  upload_log_file
  delete_instance
fi
echo "$(date '+%Y-%m-%d %H:%M:%S') - Created env successfully" >> "$LOG_FILE"

echo "$(date '+%Y-%m-%d %H:%M:%S') - Activating env" >> "$LOG_FILE"
source env/bin/activate >> "$LOG_FILE" 2>&1
if [ $? -ne 0 ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: env failed" >> "$LOG_FILE"
  upload_log_file
  delete_instance
fi
echo "$(date '+%Y-%m-%d %H:%M:%S') - Activated env successfully" >> "$LOG_FILE"

# Change directory
echo "$(date '+%Y-%m-%d %H:%M:%S') - Changing directory to setup directory" >> "$LOG_FILE"
cd "$BASE_DIR/setup"
if [ $? -ne 0 ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: Failed to change directory" >> "$LOG_FILE"
  upload_log_file
  delete_instance
fi

# Install Dependencies
echo "$(date '+%Y-%m-%d %H:%M:%S') - Installing dependencies" >> "$LOG_FILE"
pip install -r requirements.txt >> "$LOG_FILE" 2>&1
if [ $? -ne 0 ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: Failed to install dependencies" >> "$LOG_FILE"
  upload_log_file
  delete_instance
fi
sudo apt-get install gcc g++ libpcap-dev libssl-dev python3-dev zlib1g-dev
sudo apt install argus-server argus-client -y
if [ $? -ne 0 ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: Failed to install argus" >> "$LOG_FILE"
  upload_log_file
  delete_instance
fi
sudo apt install tcpreplay
sudo apt install dos2unix -y

# Change directory
echo "$(date '+%Y-%m-%d %H:%M:%S') - Changing directory to Capstone_Flask directory" >> "$LOG_FILE"
cd "$BASE_DIR"
if [ $? -ne 0 ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: Failed to change directory" >> "$LOG_FILE"
  upload_log_file
  delete_instance
fi

# Get the external IP address from the metadata server
echo "$(date '+%Y-%m-%d %H:%M:%S') - Getting external IP from metadata server" >> "$LOG_FILE"
EXTERNAL_IP=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip)

if [ -z "$EXTERNAL_IP" ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: Failed to retrieve external IP from metadata server" >> "$LOG_FILE"
  upload_log_file
  delete_instance
fi

# Creating the Caddyfile
echo "$(date '+%Y-%m-%d %H:%M:%S') - Creating the Caddyfile" >> "$LOG_FILE"
cat <<EOF > Caddyfile
http://$EXTERNAL_IP {
    reverse_proxy localhost:8000
}
EOF
if [ $? -ne 0 ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: Failed to create Caddyfile" >> "$LOG_FILE"
    upload_log_file
    delete_instance
fi

# Stopping Caddy instance
echo "$(date '+%Y-%m-%d %H:%M:%S') - Stopping Caddy instance" >> "$LOG_FILE"
caddy stop >> "$LOG_FILE"
if [ $? -ne 0 ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: Failed to stop Caddy instance" >> "$LOG_FILE"
  upload_log_file
  delete_instance
fi

# Starting again
echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting Caddy" >> "$LOG_FILE"
sudo caddy start >> "$LOG_FILE" 2>&1
if [ $? -ne 0 ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: Failed start Caddy" >> "$LOG_FILE"
  upload_log_file
  delete_instance
fi

# Create data directory if it doesn't exist
echo "$(date '+%Y-%m-%d %H:%M:%S') - Creating data directory and changing permissions" >> "$LOG_FILE"
sudo mkdir -p "$BASE_DIR/Databases" >> "$LOG_FILE"
sudo mkdir -p "$BASE_DIR/Databases/OG_PCAPs" >> "$LOG_FILE"
sudo chown -R capstone4340-admin:capstone4340-admin "$BASE_DIR" >> "$LOG_FILE"
sudo chmod -R 755 "$BASE_DIR" >> "$LOG_FILE"
sudo chmod 777 "$BASE_DIR/setup/install_zeek.sh"
sudo chmod 777 "$BASE_DIR/setup/install_java.sh"
sudo chmod 777 "$BASE_DIR/extract_features.sh"
sudo chmod 777 "$BASE_DIR/CICFlowMeter-3.0/bin/CICFlowMeter"
cd "$BASE_DIR/setup"
sudo dos2unix install_zeek.sh
sudo dos2unix install_java.sh
if [ $? -ne 0 ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: mkdir and change permissions failed" >> "$LOG_FILE"
  upload_log_file
fi
echo "$(date '+%Y-%m-%d %H:%M:%S') - Data directory created and permissions changed successfully" >> "$LOG_FILE"

cd "$BASE_DIR"
# Starting gunicorn in background
echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting gunicorn in background" >> "$LOG_FILE"
pwd >> "LOG_FILE" 2>&1
gunicorn app:app >> "$LOG_FILE" 2>&1
if [ $? -ne 0 ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: Failed to start gunicorn in background" >> "$LOG_FILE"
  upload_log_file
  delete_instance
fi

upload_log_file
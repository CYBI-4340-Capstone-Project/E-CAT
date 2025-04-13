#!/bin/bash
# Installing Zeek
echo "Installing Zeek"

# Add Zeek repository
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | \
        sudo tee /etc/apt/sources.list.d/security:zeek.list

# Add repository key
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | \
        gpg --dearmor | \
        sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

# Update and install
sudo apt update -y
sudo apt install -y zeek-6.0

# Add Zeek to PATH in bashrc for all users
echo 'export PATH=/opt/zeek/bin:$PATH' | sudo tee -a /etc/bash.bashrc > /dev/null

# Also add to current user's bashrc
echo 'export PATH=/opt/zeek/bin:$PATH' >> ~/.bashrc

# Source the changes for current session
source ~/.bashrc

sudo su
echo 'export PATH=/opt/zeek/bin:$PATH' >> /root/.bashrc
source /root/.bashrc
exit

# Verify installation
if /opt/zeek/bin/zeek --version; then
  echo "Zeek installed successfully"
  echo "You may need to start a new terminal session for PATH changes to take effect"
else
  echo "ERROR: Failed to install Zeek"
  exit 1
fi
#!/bin/bash
# Installing Zeek
echo "Installing Zeek"
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | \
        sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | \
        gpg --dearmor | \
        sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
sudo apt update -y
sudo apt install -y zeek-6.0
# Add Zeek to PATH
echo 'export PATH=/opt/zeek/bin:$PATH' | sudo tee -a $(which python | sed 's|/bin/python||')/bin/activate > /dev/null
source ~/.bashrc
if [ $? -ne 0 ]; then
  echo "ERROR: Failed to install Zeek"
fi
echo "Done!"
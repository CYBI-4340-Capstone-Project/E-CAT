#!/bin/bash
# Install Java
echo "Installing Java..."
sudo apt update -y
sudo apt install -y default-jre default-jdk

# Determine the actual Java home path (more reliable than hardcoding)
JAVA_HOME=$(readlink -f /usr/bin/java | sed "s:/bin/java::")

# Set JAVA_HOME system-wide
echo "Setting JAVA_HOME to $JAVA_HOME"

# Add to /etc/environment (for system-wide access)
echo "JAVA_HOME=\"$JAVA_HOME\"" | sudo tee -a /etc/environment

# Add to bashrc for current user
echo "export JAVA_HOME=\"$JAVA_HOME\"" >> ~/.bashrc
echo "export PATH=\"\$JAVA_HOME/bin:\$PATH\"" >> ~/.bashrc

# Source immediately for current session
source ~/.bashrc

# Verify installation
if java -version && javac -version; then
    echo "Java installed successfully!"
    echo "Java version: $(java -version 2>&1 | head -n 1)"
    echo "Javac version: $(javac -version 2>&1)"
    echo "JAVA_HOME is set to: $JAVA_HOME"
    echo "You may need to log out and back in for changes to take full effect"
else
    echo "ERROR: Java installation failed!" >&2
    exit 1
fi
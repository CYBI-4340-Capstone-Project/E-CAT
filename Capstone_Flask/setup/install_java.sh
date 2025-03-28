#!/bin/bash
# Install Java
echo "Installing Java"
sudo apt install default-jre -y
sudo apt install default-jdk -y
# Add JAVA_HOME to /etc/environment
JAVA_HOME="/usr/lib/jvm/java-11-openjdk-amd64"
echo "JAVA_HOME=\"$JAVA_HOME\"" | sudo tee -a /etc/environment
if [ $? -ne 0 ]; then
  echo "ERROR: Failed to install Java"
fi
echo "JAVA_HOME set to $JAVA_HOME and sourced successfully"
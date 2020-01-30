#!/bin/bash

# 
# Put any shell based provisioning information in here
# 

# Update the Machine
sudo yum -y update

# Change keyboard to german
sudo localectl set-keymap de

# Install misc. tools
sudo yum -y install mc bind-utils net-tools lynx

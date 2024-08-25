#!/bin/bash
# Dependency installation script for kernel build.
# Author: Siddhant Jajoo.


sudo apt-get install -y libssl-dev
sudo apt-get install -y u-boot-tools
sudo apt-get install -y qemu
sudo apt-get install qemu-system-arm qemu-system-aarch64

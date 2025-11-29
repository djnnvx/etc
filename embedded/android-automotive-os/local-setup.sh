#!/bin/env bash

set -euo pipefail

# confirm that hardware supports virtualisation (should be more than zero):
# egrep -c '(vmx|svm)' /proc/cpuinfo

echo "[+] installing dependencies"
sudo apt install -y \
    qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils \
     android-sdk \
     unzip wget

export ANDROID_HOME=/usr/lib/android-sdk

wget 'https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip'

unzip commandlinetools-linux-13114758_latest.zip -d cmdline-tools
sudo mkdir --parents "/usr/lib/android-sdk/cmdline-tools/latest"
sudo mv cmdline-tools/* "/usr/lib/android-sdk/cmdline-tools/latest/."

PATH_CMDLINE_TOOLS="/usr/lib/android-sdk/cmdline-tools/latest/cmdline-tools/bin/"

echo "[+] Please add $PATH_CMDLINE_TOOLS to your .bashrc or equivalent"
export PATH=/usr/lib/android-sdk/cmdline-tools/latest/cmdline-tools/bin/:$PATH

sudo chown -R $USER:$USER /usr/lib/android-sdk/cmdline-tools/latest/

echo "[+] Installing emulator for AA-OS (Android 33, x86_64)"

VERSION="system-images;android-33;android-automotive;x86_64"

sdkmanager "platform-tools" "emulator" --sdk_root=/usr/lib/android-sdk/cmdline-tools/latest/
sdkmanager --sdk_root=/usr/lib/android-sdk/cmdline-tools/latest/ $VERSION


echo "[+] Listing available virtual devices:"
avdmanager list device | grep "automotive"

echo "[+] Creating new device"
avdmanager create avd --name "p2o-test-device" \
    --package $VERSION \
    --device "automotive_1024p_landscape"

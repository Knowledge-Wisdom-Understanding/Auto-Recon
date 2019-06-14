#!/usr/bin/env bash


# Check if user is root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

echo '[+] Running: apt-get update -y'
apt-get update -y

echo '[+] Downloading Dependencies'
cd /opt
git clone https://github.com/maurosoria/dirsearch.git

echo '[+] Downloading Dependencies'
cd /opt
git clone https://github.com/RoliSoft/ReconScan.git
cd ReconScan
chmod +x vulnscan.py
./vulnscan.py -u

echo '[+] Downloading Dependencies'
apt install odat
cd /opt
git clone https://github.com/quentinhardy/odat.git

cd Auto-Recon
chmod +x auto-recon.sh
chmod +x smb_enum_all.sh

echo '[+] Congratulations, All tools installed successfully!'

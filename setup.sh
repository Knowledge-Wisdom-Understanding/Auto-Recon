#!/usr/bin/env bash

# Check if user is root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

DOPE='\e[92m[+]\e[0m'

echo -e "${DOPE} Running: apt-get update -y"
apt-get update -y

echo -e "${DOPE} Downloading dirsearch repository in /opt folder"
cd /opt
git clone https://github.com/maurosoria/dirsearch.git

echo -e "${DOPE} Updating vulnscan.py"
cd /opt
git clone https://github.com/RoliSoft/ReconScan.git
cd ReconScan
chmod +x vulnscan.py
./vulnscan.py -u

echo -e "${DOPE} Installing magescan and dependencies"
cd /opt
git clone https://github.com/steverobbins/magescan magescan
cd magescan
curl -sS https://getcomposer.org/installer | php
php composer.phar install
apt install php7.3-xml -y
apt install php-guzzlehttp-psr7 -y
php --ini
apt install php7.3-curl -y

echo -e "${DOPE} Installing EyeWitness"
apt install eyewitness -y
cd /opt
git clone https://github.com/FortyNorthSecurity/EyeWitness.git
cd EyeWitness && cd setup
chmod +x setup.sh
./setup.sh

echo -e "${DOPE} Installing ODAT"
apt install odat -y
cd /opt
git clone https://github.com/quentinhardy/odat.git

echo -e "${DOPE} Installing Nmap Vulners & Vulscan scripts"
cd /usr/share/nmap/scripts/
git clone https://github.com/vulnersCom/nmap-vulners.git
git clone https://github.com/scipag/vulscan.git
cd vulscan/utilities/updater
chmod +x updateFiles.sh
./updateFiles.sh

echo -e "${DOPE} Installing Sublist3r"
cd /opt
git clone https://github.com/aboul3la/Sublist3r.git

cd /opt
cd Auto-Recon
chmod +x auto-recon.sh

echo -e "${DOPE} Congratulations, All tools installed successfully!"

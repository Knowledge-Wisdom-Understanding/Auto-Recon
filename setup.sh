#!/usr/bin/env bash


# Check if user is root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

echo '[+] Running: apt-get update -y'
apt-get update -y

echo '[+] Downloading dirsearch repository in /opt folder'
cd /opt
git clone https://github.com/maurosoria/dirsearch.git

echo '[+] Downloading & Installing penetest-machine repository in /opt folder'
cd /opt
git clone https://github.com/DanMcInerney/pentest-machine.git
cd pentest-machine
./setup.sh
cd /opt
git clone https://github.com/RoliSoft/ReconScan.git

echo '[+] Congratulations, All tools installed successfully!'
echo '[+] Done. When you are done running this tool, cd into pentest-machine and deactivate the virtualenv by running the command: source /opt/pentest-machine/pm/deactivate'

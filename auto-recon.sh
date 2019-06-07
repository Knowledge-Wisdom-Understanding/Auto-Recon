#!/usr/bin/env bash

banner1() {

    printf "\e[1;92m   _____________                  ________________                               \e[0m\n"
    printf "\e[1;92m  /___/___      \         ____   /___/__          \                    ____      \e[0m\n"
    printf "\e[1;92m      /  /   _   \_____ _/_/  |______|__|_____ *   \__________________/ /  |___  \e[0m\n"
    printf "\e[1;92m   __/__/   /_\   \ |  |  \   __\/  _ \|  |       __/ __ \_/ ___\/  _ \|       | \e[0m\n"
    printf "\e[1;92m  |   |     ___    \|  |  /|  | (  |_| )  |    |   \  ___/\  \__(  |_| )   |   | \e[0m\n"
    printf "\e[1;92m  |___|____/\__\____|____/_|__|\_\____/|__|____|_  /\___  |\___  \____/|___|  /  \e[0m\n"
    printf "\e[1;92m                                             \___\/  \__\/  \__\/        \__\/   \e[0mv3.0\n"
    printf "\e[1;77m\e[45m         AUTO RECON, Low Budget Butta Script by github.com/Knowledge-Wisdom-Understanding                        \e[0m\n"
    printf "\n"

}

banner2() {

    printf "\e[1;92m  █████╗ ██╗   ██╗████████╗ ██████╗     ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗ \e[0m\n"
    printf "\e[1;92m ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║ \e[0m\n"
    printf "\e[1;92m ███████║██║   ██║   ██║   ██║   ██║    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ \e[0m\n"
    printf "\e[1;92m ██╔══██║██║   ██║   ██║   ██║   ██║    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ \e[0m\n"
    printf "\e[1;92m ██║  ██║╚██████╔╝   ██║   ╚██████╔╝    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║ \e[0m\n"
    printf "\e[1;92m ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝ \e[0mv3.0\n"
    printf "\e[1;77m\e[45m         AUTO RECON, Low Budget Butta Script by github.com/Knowledge-Wisdom-Understanding                           \e[0m\n"
    printf "\n"

}

# Use a pseudo-random banner on program execution
shuffle_banners() {

    declare -a banners=(banner1 banner2)
    $(shuf -n1 -e "${banners[@]}")

}
shuffle_banners

RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
DOPE='\e[92m[+]\e[0m'

helpFunction() {
    echo -e "${DOPE}Usage: $0 TARGET-IP"
    echo
    echo "Example: "
    echo "./$0 10.11.1.123"
    printf "\n"
    exit 1
}

if [ -z $1 ]; then helpFunction && exit; else rhost=$1; fi

if [[ $rhost =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo -e "\e[92m[+]\e[0m SUCCESS"
else
    echo -e "\e[31m[+]\e[0m NOT A VALID IP ADDRESS"
    exit 1
fi
# Function Definitions
exitFunction() {
    echo "Error - Bad Argument: $1 not found. Use -h or --help." >&2
    exit 1
}

# getUpHosts() {
#     # Live Hosts
#     nmap -sn $rhost -oG /tmp/live-hosts.txt >/dev/null
#     cat /tmp/live-hosts.txt | grep "Up" | cut -d " " -f2 >live-hosts-ip.txt
#     rm /tmp/live-hosts.txt
#     Live_Host=live-hosts-ip.txt
#     echo "[*] Live Hosts Recon On $rhost Done!"
# }

# Full_TCP_Scan_All() {
#     Live_Host=live-hosts-ip.txt
#     if [ -n "$Live_Host" ]; then
#         echo ""
#         echo -e "${GREEN}Scanning all hosts"
#         nmap -v -Pn -A -O -p- --max-retries 1 --max-rate 500 --max-scan-delay 20 -T4 -v -oA nmap/hostfilescan -iL $Live_Host
#     fi
# }

Open_Ports_Scan() {
    echo -e "${DOPE}Scanning $rhost"
    create_nmap_dir() {
        if [ -d nmap ]; then
            echo "nmap directory exists"
        else
            echo "creating nmap directory"
            mkdir -p nmap
        fi
    }
    create_nmap_dir
    # nmap -v -Pn -A -O -p- --max-retries 1 --max-rate 500 --max-scan-delay 20 -T4 -oN nmap/FullTCP $rhost
    #nmap -vv -sT -Pn -p- --disable-arp-ping -T4 -oA nmap/open-ports-$rhost $rhost
    nmap -vv -sT -Pn --top-ports 100 --disable-arp-ping --max-retries 1 -oA nmap/open-ports-$rhost $rhost
}

# TODO: Fix this for loop to save space and avoid repeating this function over and over again.
# Enum_Http() {
#     portlist=80,8000,8080,8888,9050,9999,1234,1337,31337,10000,65535
#     grep -i "/tcp" nmap/open-ports-$rhost.nmap | cut -d "/" -f 1 >openports-$rhost.txt
#     for port in ${portlist//,/ }; do
#         if grep -q $port openports-$rhost.nmap; then
#             wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
#             echo -e "${DOPE} Running The Following Commands"
#             echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u http://$rhost:$port -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-$port.log"
#             echo -e "${DOPE} nikto -h http://$rhost:$port -output niktoscan-port$port-$rhost.txt"
#             echo -e "${DOPE} whatweb -a 3 http://$rhost:$port | tee whatweb-$rhost-$port.log"

#             gnome-terminal --geometry 105x26-0+0 -- bash -c "python3 /opt/dirsearch/dirsearch.py -u http://$rhost:$port -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-$port.log; exec $SHELL"
#             gnome-terminal --geometry 105x26+0+0 -- bash -c "nikto -h http://$rhost:$port -output niktoscan-port$port-$rhost.txt; exec $SHELL"
#             gnome-terminal --geometry 105x25+0-0 -- bash -c "whatweb -a 3 http://$rhost:$port | tee whatweb-$rhost-$port.log; exec $SHELL"
#         fi
#     done
#     whatweb_process_id() {
#         getpid=$(ps -elf | grep whatweb | grep -v grep | awk '{print $4}')
#         procid=$(echo $getpid)
#         whatwebid=$(expr "$procid" : '.* \(.*\)')
#     }
#     whatweb_process_id
#     if [ $? -eq 0 ]; then
#         printf "\e[36m[+]\e[0m Waiting for WHATWEB PID $whatwebid Scan To Finish up \n"
#         for i in $(seq 1 50); do
#             printf "\e[93m#*\e[0m"
#         done
#         printf "\n"
#         # echo "waiting for PID $procid to finish running NMAP script"
#         while ps -p $whatwebid >/dev/null; do sleep 1; done
#     else
#         echo "Running CMS Enumeration"
#     fi
#     if grep -q "WordPress" whatweb-$rhost-$port.log; then
#         wpscan --url http://$rhost/ --enumerate p,t,u | tee -a wpscan.log
#     elif grep -q "Drupal" whatweb-$rhost-$port.log; then
#         droopescan scan drupal -u http://$rhost -t 32 | tee -a drupalscan.log
#     elif grep -q "Joomla" whatweb-$rhost.log; then
#         joomscan --url http://$rhost -ec | tee -a joomlascan.log
#     elif grep -q "WebDAV" whatweb-$rhost-$port.log; then
#         davtest -move -sendbd auto -url http://$rhost | tee -a davtestscan.log
#     else
#         echo "Couldn't find a CMS"
#     fi
# }

# TODO: Fix this for loop to save space and avoid repeating this function over and over again.
# Enum_Https() {
#     portlist=443,10443,4443,8443,9443
#     grep -i "/tcp" nmap/open-ports-$rhost.nmap | cut -d "/" -f 1 >openports-$rhost.txt
#     for port in ${portlist//,/ }; do
#         if grep -q $port openports-$rhost.nmap; then
#             wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
#             echo -e "${DOPE} Running The Following Commands"
#             echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u https://$rhost:$port -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-$port.log"
#             echo -e "${DOPE} nikto -h https://$rhost:$port -output niktoscan-port$port-$rhost.txt"
#             echo -e "${DOPE} whatweb -a 3 https://$rhost:$port | tee whatweb-$rhost-$port.log"

#             gnome-terminal --geometry 105x26-0+0 -- bash -c "python3 /opt/dirsearch/dirsearch.py -u https://$rhost:$port -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-$port.log; exec $SHELL"
#             gnome-terminal --geometry 105x26+0+0 -- bash -c "nikto -h https://$rhost:$port -output niktoscan-port$port-$rhost.txt; exec $SHELL"
#             gnome-terminal --geometry 105x25+0-0 -- bash -c "whatweb -a 3 https://$rhost:$port | tee whatweb-$rhost-$port.log; exec $SHELL"
#         fi
#     done
#     whatweb_process_id() {
#         getpid=$(ps -elf | grep whatweb | grep -v grep | awk '{print $4}')
#         procid=$(echo $getpid)
#         whatwebid=$(expr "$procid" : '.* \(.*\)')
#     }
#     whatweb_process_id
#     if [ $? -eq 0 ]; then
#         printf "\e[36m[+]\e[0m Waiting for WHATWEB PID $whatwebid Scan To Finish up \n"
#         for i in $(seq 1 50); do
#             printf "\e[93m#*\e[0m"
#         done
#         printf "\n"
#         # echo "waiting for PID $procid to finish running NMAP script"
#         while ps -p $whatwebid >/dev/null; do sleep 1; done
#     else
#         echo "Running CMS Enumeration"
#     fi
#     if grep -q "WordPress" whatweb-$rhost-$port.log; then
#         wpscan --url https://$rhost/ --enumerate p,t,u | tee -a wpscan.log
#     elif grep -q "Drupal" whatweb-$rhost-$port.log; then
#         droopescan scan drupal -u https://$rhost -t 32 | tee -a drupalscan.log
#     elif grep -q "Joomla" whatweb-$rhost.log; then
#         joomscan --url https://$rhost -ec | tee -a joomlascan.log
#     elif grep -q "WebDAV" whatweb-$rhost-$port.log; then
#         davtest -move -sendbd auto -url https://$rhost | tee -a davtestscan.log
#     else
#         echo "Couldn't find a CMS"
#     fi
# }

Enum_Web() {
    grep -i "/tcp" nmap/open-ports-$rhost.nmap | cut -d "/" -f 1 >openports-$rhost.txt
    if grep -q "80" openports-$rhost.txt; then
        wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        echo -e "${DOPE} Running The Following Commands"
        echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u http://$rhost -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-80.log"
        echo -e "${DOPE} nikto -h http://$rhost -output niktoscan-port80-$rhost.txt"
        echo -e "${DOPE} whatweb -a 3 http://$rhost:80 | tee whatweb-$rhost-80.log"
        echo -e "${DOPE} curl -O http://$rhost:80/robots.txt"
        echo -e "${DOPE} uniscan -u http://$rhost/ -qweds | tee uniscan-$rhost-80.log"
        curl http://$rhost:80/robots.txt -o robots-$rhost-80.txt
        gnome-terminal --geometry 105x26-0+0 -- bash -c "python3 /opt/dirsearch/dirsearch.py -u http://$rhost -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-80.log; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x26+0+0 -- bash -c "nikto -host http://$rhost -output niktoscan-port80-$rhost.txt; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x25+0-0 -- bash -c "whatweb -a 3 http://$rhost:80 | tee whatweb-$rhost-80.log; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x25-0-0 -- bash -c "uniscan -u http://$rhost -qweds | tee uniscan-$rhost-80.log; exec $SHELL" &>/dev/null
    fi
    whatweb_process_id() {
        getpid=$(ps -elf | grep whatweb | grep -v grep | awk '{print $4}')
        procid=$(echo $getpid)
        whatwebid=$(expr "$procid" : '.* \(.*\)')
    }
    whatweb_process_id
    if [ $? -eq 0 ]; then
        printf "\e[36m[+]\e[0m Waiting for WHATWEB PID $whatwebid Scan To Finish up \n"
        for i in $(seq 1 50); do
            printf "\e[93m#*\e[0m"
        done
        printf "\n"
        # echo "waiting for PID $procid to finish running NMAP script"
        while ps -p $whatwebid >/dev/null; do sleep 1; done
    else
        :
    fi
    if grep -i "WordPress" whatweb-$rhost-80.log 2>/dev/null; then
        echo -e "${DOPE} Found WordPress! Running wpscan --url http://$rhost/ --enumerate p,t,u | tee -a wpscan-$rhost-80.log"
        wpscan --url http://$rhost/ --enumerate p,t,u | tee -a wpscan.log
    elif grep -i "Drupal" whatweb-$rhost-80.log 2>/dev/null; then
        echo -e "${DOPE} Found Drupal! Running droopescan scan drupal -u http://$rhost -t 32 | tee -a drupalscan-$rhost-80.log"
        droopescan scan drupal -u http://$rhost -t 32 | tee -a drupalscan.log
    elif grep -i "Joomla" whatweb-$rhost-80.log 2>/dev/null; then
        echo -e "${DOPE} Found Joomla! Running joomscan --url http://$rhost/ -ec | tee -a joomlascan-$rhost-80.log"
        joomscan --url http://$rhost -ec | tee -a joomlascan.log
    elif grep -i "WebDAV" whatweb-$rhost-80.log 2>/dev/null; then
        echo -e "${DOPE} Found WebDAV! Running davtest -move -sendbd auto -url http://$rhost/ | tee -a davtestscan-$rhost-80.log"
        davtest -move -sendbd auto -url http://$rhost | tee -a davtestscan.log
    else
        :
    fi
    if grep -q "8080" openports-$rhost.txt; then
        wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        echo -e "${DOPE} Running The Following Commands"
        echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u http://$rhost:8080 -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-8080.log"
        echo -e "${DOPE} nikto -h http://$rhost:8080 -output niktoscan-port8080-$rhost.txt"
        echo -e "${DOPE} whatweb -a 3 http://$rhost:8080 | tee whatweb-$rhost-8080.log"
        echo -e "${DOPE} curl -O http://$rhost:8080/robots.txt"
        echo -e "${DOPE} uniscan -u http://$rhost:8080/ -qweds | tee uniscan-$rhost-8080.log"
        curl http://$rhost:8080/robots.txt -o robots-$rhost-8080.txt

        gnome-terminal --geometry 105x26-0+0 -- bash -c "python3 /opt/dirsearch/dirsearch.py -u http://$rhost:8080 -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-8080.log; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x26+0+0 -- bash -c "nikto -h http://$rhost:8080/ -output niktoscan-port8080-$rhost.txt; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x25+0-0 -- bash -c "whatweb -a 3 http://$rhost:8080 | tee whatweb-$rhost-8080.log; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x25-0-0 -- bash -c "uniscan -u http://$rhost:8080/ -qweds | tee uniscan-$rhost-8080.log; exec $SHELL" &>/dev/null
    fi
    whatweb_process_id() {
        getpid=$(ps -elf | grep whatweb | grep -v grep | awk '{print $4}')
        procid=$(echo $getpid)
        whatwebid=$(expr "$procid" : '.* \(.*\)')
    }
    whatweb_process_id
    if [ $? -eq 0 ]; then
        printf "\e[36m[+]\e[0m Waiting for WHATWEB PID $whatwebid Scan To Finish up \n"
        for i in $(seq 1 50); do
            printf "\e[93m#*\e[0m"
        done
        printf "\n"
        # echo "waiting for PID $procid to finish running NMAP script"
        while ps -p $whatwebid >/dev/null; do sleep 1; done
    else
        :
    fi
    if grep -i "WordPress" whatweb-$rhost-8080.log 2>/dev/null; then
        echo -e "${DOPE} Found WordPress! Running wpscan --url http://$rhost:8080/ --enumerate p,t,u | tee -a wpscan-$rhost-8080.log"
        wpscan --url http://$rhost:8080/ --enumerate p,t,u | tee -a wpscan-$rhost-8080.log
    elif grep -i "Drupal" whatweb-$rhost-8080.log 2>/dev/null; then
        echo -e "${DOPE} Found Drupal! Running droopescan scan drupal -u http://$rhost:8080/ -t 32 | tee -a drupalscan-$rhost-8080.log"
        droopescan scan drupal -u http://$rhost:8080/ -t 32 | tee -a drupalscan-$rhost-8080.log
    elif grep -i "Joomla" whatweb-$rhost-8080.log 2>/dev/null; then
        echo -e "${DOPE} Found Joomla! Running joomscan --url http://$rhost:8080/ -ec | tee -a joomlascan-$rhost-8080.log"
        joomscan --url http://$rhost:8080/ -ec | tee -a joomlascan-$rhost-8080.log
    elif grep -i "WebDAV" whatweb-$rhost-8080.log 2>/dev/null; then
        echo -e "${DOPE} Found WebDAV! Running davtest -move -sendbd auto -url http://$rhost:8080/ | tee -a davtestscan-$rhost-8080.log"
        davtest -move -sendbd auto -url http://$rhost:8080/ | tee -a davtestscan-$rhost-8080.log
    else
        :
    fi
    if grep -q "8000" openports-$rhost.txt; then
        wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        echo -e "${DOPE} Running The Following Commands"
        echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u http://$rhost:8000 -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-8080.log"
        echo -e "${DOPE} nikto -h http://$rhost:8000 -output niktoscan-port8000-$rhost.txt"
        echo -e "${DOPE} whatweb -a 3 http://$rhost:8000 | tee whatweb-$rhost-8000.log"
        echo -e "${DOPE} curl -O http://$rhost:8000/robots.txt"
        echo -e "${DOPE} uniscan -u http://$rhost:8000/ -qweds | tee uniscan-$rhost-8000.log"
        curl http://$rhost:8000/robots.txt -o robots-$rhost-8000.txt
        gnome-terminal --geometry 105x26-0+0 -- bash -c "python3 /opt/dirsearch/dirsearch.py -u http://$rhost:8000 -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-8000.log; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x26+0+0 -- bash -c "nikto -h http://$rhost:8000/ -output niktoscan-port8000-$rhost.txt; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x25+0-0 -- bash -c "whatweb -a 3 http://$rhost:8000 | tee whatweb-$rhost-8000.log; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x25-0-0 -- bash -c "uniscan -u http://$rhost:8000/ -qweds | tee uniscan-$rhost-8000.log; exec $SHELL" &>/dev/null
    fi
    whatweb_process_id() {
        getpid=$(ps -elf | grep whatweb | grep -v grep | awk '{print $4}')
        procid=$(echo $getpid)
        whatwebid=$(expr "$procid" : '.* \(.*\)')
    }
    whatweb_process_id
    if [ $? -eq 0 ]; then
        printf "\e[36m[+]\e[0m Waiting for WHATWEB PID $whatwebid Scan To Finish up \n"
        for i in $(seq 1 50); do
            printf "\e[93m#*\e[0m"
        done
        printf "\n"
        # echo "waiting for PID $procid to finish running NMAP script"
        while ps -p $whatwebid >/dev/null; do sleep 1; done
    else
        :
    fi
    if grep -i "WordPress" whatweb-$rhost-8000.log 2>/dev/null; then
        echo -e "${DOPE} Found WordPress! Running wpscan --url http://$rhost:8000/ --enumerate p,t,u | tee -a wpscan.log"
        wpscan --url http://$rhost:8000/ --enumerate p,t,u | tee -a wpscan-$rhost.log
    elif grep -i "Drupal" whatweb-$rhost-8000.log 2>/dev/null; then
        echo -e "${DOPE} Found Drupal! Running droopescan scan drupal -u http://$rhost:8000/ -t 32 | tee -a drupalscan-$rhost-8000.log"
        droopescan scan drupal -u http://$rhost:8000/ -t 32 | tee -a drupalscan-$rhost.log
    elif grep -i "Joomla" whatweb-$rhost-8000.log 2>/dev/null; then
        echo -e "${DOPE} Found Joomla! Running joomscan --url http://$rhost:8000/ -ec | tee -a joomlascan-$rhost-8000.log"
        joomscan --url http://$rhost:8000/ -ec | tee -a joomlascan-$rhost.log
    elif grep -i "WebDAV" whatweb-$rhost-8000.log 2>/dev/null; then
        echo -e "${DOPE} Found WebDAV! Running davtest -move -sendbd auto -url http://$rhost:8000/ | tee -a davtestscan-$rhost-8000.log"
        davtest -move -sendbd auto -url http://$rhost:8000/ | tee -a davtestscan-$rhost.log
    else
        :
    fi
    if grep -q "8888" openports-$rhost.txt; then
        wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        echo -e "${DOPE} Running The Following Commands"
        echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u http://$rhost:8888 -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-8888.log"
        echo -e "${DOPE} nikto -h http://$rhost:8888 -output niktoscan-port8888-$rhost.txt"
        echo -e "${DOPE} whatweb -a 3 http://$rhost:8888 | tee whatweb-$rhost-8888.log"
        echo -e "${DOPE} curl -O http://$rhost:8888/robots.txt"
        echo -e "${DOPE} uniscan -u http://$rhost:8888/ -qweds | tee uniscan-$rhost-8888.log"
        curl http://$rhost:8888/robots.txt -o robots-$rhost-8888.txt
        gnome-terminal --geometry 105x26-0+0 -- bash -c "python3 /opt/dirsearch/dirsearch.py -u http://$rhost:8888 -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-8888.log; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x26+0+0 -- bash -c "nikto -h http://$rhost:8888/ -output niktoscan-port8888-$rhost.txt; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x25+0-0 -- bash -c "whatweb -a 3 http://$rhost:8888 | tee whatweb-$rhost-8888.log; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x25-0-0 -- bash -c "uniscan -u http://$rhost:8888/ -qweds | tee uniscan-$rhost-8888.log; exec $SHELL" &>/dev/null
    fi
    whatweb_process_id() {
        getpid=$(ps -elf | grep whatweb | grep -v grep | awk '{print $4}')
        procid=$(echo $getpid)
        whatwebid=$(expr "$procid" : '.* \(.*\)')
    }
    whatweb_process_id
    if [ $? -eq 0 ]; then
        printf "\e[36m[+]\e[0m Waiting for WHATWEB PID $whatwebid Scan To Finish up \n"
        for i in $(seq 1 50); do
            printf "\e[93m#*\e[0m"
        done
        printf "\n"
        # echo "waiting for PID $procid to finish running NMAP script"
        while ps -p $whatwebid >/dev/null; do sleep 1; done
    else
        :
    fi
    if grep -i "WordPress" whatweb-$rhost-8888.log 2>/dev/null; then
        echo -e "${DOPE} Found WordPress! Running wpscan --url http://$rhost:8888/ --enumerate p,t,u | tee -a wpscan-$rhost-8888.log"
        wpscan --url http://$rhost:8888/ --enumerate p,t,u | tee -a wpscan-$rhost-8888.log
    elif grep -i "Drupal" whatweb-$rhost-8888.log 2>/dev/null; then
        echo -e "${DOPE} Found Drupal! Running droopescan scan drupal -u http://$rhost:8888/ -t 32 | tee -a drupalscan-$rhost-8888.log"
        droopescan scan drupal -u http://$rhost:8888/ -t 32 | tee -a drupalscan-$rhost-8888.log
    elif grep -i "Joomla" whatweb-$rhost-8888.log 2>/dev/null; then
        echo -e "${DOPE} Found Joomla! Running joomscan --url http://$rhost:8888/ -ec | tee -a joomlascan-$rhost-8888.log"
        joomscan --url http://$rhost:8888/ -ec | tee -a joomlascan-$rhost-8888.log
    elif grep -i "WebDAV" whatweb-$rhost-8888.log 2>/dev/null; then
        echo -e "${DOPE} Found WebDAV! Running davtest -move -sendbd auto -url http://$rhost:8888/ | tee -a davtestscan-$rhost-8888.log"
        davtest -move -sendbd auto -url http://$rhost:8888/ | tee -a davtestscan-$rhost-8888.log
    else
        :
    fi
    if grep -q "1234" openports-$rhost.txt; then
        wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        echo -e "${DOPE} Running The Following Commands"
        echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u http://$rhost:1234 -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-1234.log"
        echo -e "${DOPE} nikto -h http://$rhost:1234 -output niktoscan-port1234-$rhost.txt"
        echo -e "${DOPE} whatweb -a 3 http://$rhost:1234 | tee whatweb-$rhost-1234.log"
        echo -e "${DOPE} curl -O http://$rhost:1234/robots.txt"
        echo -e "${DOPE} uniscan -u http://$rhost:1234/ -qweds | tee uniscan-$rhost-1234.log"
        curl http://$rhost:1234/robots.txt -o robots-$rhost-1234.txt
        gnome-terminal --geometry 105x26-0+0 -- bash -c "python3 /opt/dirsearch/dirsearch.py -u http://$rhost:1234 -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-1234.log; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x26+0+0 -- bash -c "nikto -h http://$rhost:1234/ -output niktoscan-port1234-$rhost.txt; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x25+0-0 -- bash -c "whatweb -a 3 http://$rhost:1234 | tee whatweb-$rhost-1234.log; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x25-0-0 -- bash -c "uniscan -u http://$rhost:1234/ -qweds | tee uniscan-$rhost-1234.log; exec $SHELL" &>/dev/null
    fi
    whatweb_process_id() {
        getpid=$(ps -elf | grep whatweb | grep -v grep | awk '{print $4}')
        procid=$(echo $getpid)
        whatwebid=$(expr "$procid" : '.* \(.*\)')
    }
    whatweb_process_id
    if [ $? -eq 0 ]; then
        printf "\e[36m[+]\e[0m Waiting for WHATWEB PID $whatwebid Scan To Finish up \n"
        for i in $(seq 1 50); do
            printf "\e[93m#*\e[0m"
        done
        printf "\n"
        # echo "waiting for PID $procid to finish running NMAP script"
        while ps -p $whatwebid >/dev/null; do sleep 1; done
    else
        :
    fi
    if grep -i "WordPress" whatweb-$rhost-1234.log 2>/dev/null; then
        echo -e "${DOPE} Found WordPress! Running wpscan --url http://$rhost:1234/ --enumerate p,t,u | tee -a wpscan-$rhost-1234.log"
        wpscan --url http://$rhost:1234/ --enumerate p,t,u | tee -a wpscan-$rhost-1234.log
    elif grep -i "Drupal" whatweb-$rhost-1234.log 2>/dev/null; then
        echo -e "${DOPE} Found Drupal! Running droopescan scan drupal -u http://$rhost:1234/ -t 32 | tee -a drupalscan-$rhost-1234.log"
        droopescan scan drupal -u http://$rhost:1234/ -t 32 | tee -a drupalscan-$rhost-1234.log
    elif grep -i "Joomla" whatweb-$rhost-1234.log 2>/dev/null; then
        echo -e "${DOPE} Found Joomla! Running joomscan --url http://$rhost:1234/ -ec | tee -a joomlascan-$rhost-1234.log"
        joomscan --url http://$rhost:1234/ -ec | tee -a joomlascan-$rhost-1234.log
    elif grep -i "WebDAV" whatweb-$rhost-1234.log 2>/dev/null; then
        echo -e "${DOPE} Found WebDAV! Running davtest -move -sendbd auto -url http://$rhost:1234/ | tee -a davtestscan-$rhost-1234.log"
        davtest -move -sendbd auto -url http://$rhost:1234/ | tee -a davtestscan-$rhost-1234.log
    else
        :
    fi
    if grep -q "1337" openports-$rhost.txt; then
        wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        echo -e "${DOPE} Running The Following Commands"
        echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u http://$rhost:1337 -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-1337.log"
        echo -e "${DOPE} nikto -h http://$rhost:1337 -output niktoscan-port1337-$rhost.txt"
        echo -e "${DOPE} whatweb -a 3 http://$rhost:1337 | tee whatweb-$rhost-1337.log"
        echo -e "${DOPE} curl -O http://$rhost:1337/robots.txt"
        echo -e "${DOPE} uniscan -u http://$rhost:1337/ -qweds | tee uniscan-$rhost-1337.log"
        curl http://$rhost:1337/robots.txt -o robots-$rhost-1337.txt
        gnome-terminal --geometry 105x26-0+0 -- bash -c "python3 /opt/dirsearch/dirsearch.py -u http://$rhost:1337 -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-1337.log; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x26+0+0 -- bash -c "nikto -h http://$rhost:1337/ -output niktoscan-port1337-$rhost.txt; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x25+0-0 -- bash -c "whatweb -a 3 http://$rhost:1337 | tee whatweb-$rhost-1337.log; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x25-0-0 -- bash -c "uniscan -u http://$rhost:1337/ -qweds | tee uniscan-$rhost-1337.log; exec $SHELL" &>/dev/null
    fi
    whatweb_process_id() {
        getpid=$(ps -elf | grep whatweb | grep -v grep | awk '{print $4}')
        procid=$(echo $getpid)
        whatwebid=$(expr "$procid" : '.* \(.*\)')
    }
    whatweb_process_id
    if [ $? -eq 0 ]; then
        printf "\e[36m[+]\e[0m Waiting for WHATWEB PID $whatwebid Scan To Finish up \n"
        for i in $(seq 1 50); do
            printf "\e[93m#*\e[0m"
        done
        printf "\n"
        # echo "waiting for PID $procid to finish running NMAP script"
        while ps -p $whatwebid >/dev/null; do sleep 1; done
    else
        :
    fi
    if grep -i "WordPress" whatweb-$rhost-1337.log 2>/dev/null; then
        echo -e "${DOPE} Found WordPress! Running wpscan --url http://$rhost:1337/ --enumerate p,t,u | tee -a wpscan-$rhost-1337.log"
        wpscan --url http://$rhost:1337/ --enumerate p,t,u | tee -a wpscan-$rhost-1337.log
    elif grep -i "Drupal" whatweb-$rhost-1337.log 2>/dev/null; then
        echo -e "${DOPE} Found Drupal! Running droopescan scan drupal -u http://$rhost:1337/ -t 32 | tee -a drupalscan-$rhost-1337.log"
        droopescan scan drupal -u http://$rhost:1337/ -t 32 | tee -a drupalscan-$rhost-1337.log
    elif grep -i "Joomla" whatweb-$rhost-1337.log 2>/dev/null; then
        echo -e "${DOPE} Found Joomla! Running joomscan --url http://$rhost:1337/ -ec | tee -a joomlascan-$rhost-1337.log"
        joomscan --url http://$rhost:1337/ -ec | tee -a joomlascan-$rhost-1337.log
    elif grep -i "WebDAV" whatweb-$rhost-1337.log 2>/dev/null; then
        echo -e "${DOPE} Found WebDAV! Running davtest -move -sendbd auto -url http://$rhost:1337/ | tee -a davtestscan-$rhost-1337.log"
        davtest -move -sendbd auto -url http://$rhost:1337/ | tee -a davtestscan-$rhost-1337.log
    else
        :
    fi
    if grep -q "31337" openports-$rhost.txt; then
        wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        echo -e "${DOPE} Running The Following Commands"
        echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u http://$rhost:31337 -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-31337.log"
        echo -e "${DOPE} nikto -h http://$rhost:31337 -output niktoscan-port31337-$rhost.txt"
        echo -e "${DOPE} whatweb -a 3 http://$rhost:31337 | tee whatweb-$rhost-31337.log"
        echo -e "${DOPE} curl -O http://$rhost:31337/robots.txt"
        echo -e "${DOPE} uniscan -u http://$rhost:31337/ -qweds | tee uniscan-$rhost-31337.log"
        curl http://$rhost:31337/robots.txt -o robots-$rhost-31337.txt
        gnome-terminal --geometry 105x26-0+0 -- bash -c "python3 /opt/dirsearch/dirsearch.py -u http://$rhost:31337 -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-31337.log; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x26+0+0 -- bash -c "nikto -h http://$rhost:31337/ -output niktoscan-port31337-$rhost.txt; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x25+0-0 -- bash -c "whatweb -a 3 http://$rhost:31337 | tee whatweb-$rhost-31337.log; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x25-0-0 -- bash -c "uniscan -u http://$rhost:31337/ -qweds | tee uniscan-$rhost-31337.log; exec $SHELL" &>/dev/null
    fi
    whatweb_process_id() {
        getpid=$(ps -elf | grep whatweb | grep -v grep | awk '{print $4}')
        procid=$(echo $getpid)
        whatwebid=$(expr "$procid" : '.* \(.*\)')
    }
    whatweb_process_id
    if [ $? -eq 0 ]; then
        printf "\e[36m[+]\e[0m Waiting for WHATWEB PID $whatwebid Scan To Finish up \n"
        for i in $(seq 1 50); do
            printf "\e[93m#*\e[0m"
        done
        printf "\n"
        # echo "waiting for PID $procid to finish running NMAP script"
        while ps -p $whatwebid >/dev/null; do sleep 1; done
    else
        :
    fi
    if grep -i "WordPress" whatweb-$rhost-31337.log 2>/dev/null; then
        echo -e "${DOPE} Found WordPress! Running wpscan --url http://$rhost:31337/ --enumerate p,t,u | tee -a wpscan-$rhost-31337.log"
        wpscan --url http://$rhost:31337/ --enumerate p,t,u | tee -a wpscan-$rhost-31337.log
    elif grep -i "Drupal" whatweb-$rhost-31337.log 2>/dev/null; then
        echo -e "${DOPE} Found Drupal! Running droopescan scan drupal -u http://$rhost:31337/ -t 32 | tee -a drupalscan-$rhost-31337.log"
        droopescan scan drupal -u http://$rhost:31337/ -t 32 | tee -a drupalscan-$rhost-31337.log
    elif grep -i "Joomla" whatweb-$rhost-31337.log 2>/dev/null; then
        echo -e "${DOPE} Found Joomla! Running joomscan --url http://$rhost:31337/ -ec | tee -a joomlascan-$rhost-31337.log"
        joomscan --url http://$rhost:31337/ -ec | tee -a joomlascan-$rhost-31337.log
    elif grep -i "WebDAV" whatweb-$rhost-31337.log 2>/dev/null; then
        echo -e "${DOPE} Found WebDAV! Running davtest -move -sendbd auto -url http://$rhost:31337/ | tee -a davtestscan-$rhost-31337.log"
        davtest -move -sendbd auto -url http://$rhost:31337/ | tee -a davtestscan-$rhost-31337.log
    else
        :
    fi
    if grep -q "9050" openports-$rhost.txt; then
        wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        echo -e "${DOPE} Running The Following Commands"
        echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u http://$rhost:9050 -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-9050.log"
        echo -e "${DOPE} nikto -h http://$rhost:9050 -output niktoscan-port9050-$rhost.txt"
        echo -e "${DOPE} whatweb -a 3 http://$rhost:9050 | tee whatweb-$rhost-9050.log"
        echo -e "${DOPE} curl -O http://$rhost:9050/robots.txt"
        echo -e "${DOPE} uniscan -u http://$rhost:9050/ -qweds | tee uniscan-$rhost-9050.log"
        curl http://$rhost:9050/robots.txt -o robots-$rhost-9505.txt
        gnome-terminal --geometry 105x26-0+0 -- bash -c "python3 /opt/dirsearch/dirsearch.py -u http://$rhost:9050 -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-9050.log; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x26+0+0 -- bash -c "nikto -h http://$rhost:9050/ -output niktoscan-port9050-$rhost.txt; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x25+0-0 -- bash -c "whatweb -a 3 http://$rhost:9050 | tee whatweb-$rhost-9050.log; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x25-0-0 -- bash -c "uniscan -u http://$rhost:9050/ -qweds | tee uniscan-$rhost-9050.log; exec $SHELL" &>/dev/null
    fi
    whatweb_process_id() {
        getpid=$(ps -elf | grep whatweb | grep -v grep | awk '{print $4}')
        procid=$(echo $getpid)
        whatwebid=$(expr "$procid" : '.* \(.*\)')
    }
    whatweb_process_id
    if [ $? -eq 0 ]; then
        printf "\e[36m[+]\e[0m Waiting for WHATWEB PID $whatwebid Scan To Finish up \n"
        for i in $(seq 1 50); do
            printf "\e[93m#*\e[0m"
        done
        printf "\n"
        # echo "waiting for PID $procid to finish running NMAP script"
        while ps -p $whatwebid >/dev/null; do sleep 1; done
    else
        :
    fi
    if grep -i "WordPress" whatweb-$rhost-9050.log 2>/dev/null; then
        echo -e "${DOPE} Found WordPress! Running wpscan --url http://$rhost:9050/ --enumerate p,t,u | tee -a wpscan-$rhost-9050.log"
        wpscan --url http://$rhost:9050/ --enumerate p,t,u | tee -a wpscan-$rhost-9050.log
    elif grep -i "Drupal" whatweb-$rhost-9050.log 2>/dev/null; then
        echo -e "${DOPE} Found Drupal! Running droopescan scan drupal -u http://$rhost:9050/ -t 32 | tee -a drupalscan-$rhost-9050.log"
        droopescan scan drupal -u http://$rhost:9050/ -t 32 | tee -a drupalscan-$rhost-9050.log
    elif grep -i "Joomla" whatweb-$rhost-9050.log 2>/dev/null; then
        echo -e "${DOPE} Found Joomla! Running joomscan --url http://$rhost:9050/ -ec | tee -a joomlascan-$rhost-9050.log"
        joomscan --url http://$rhost:9050/ -ec | tee -a joomlascan-$rhost-9050.log
    elif grep -i "WebDAV" whatweb-$rhost-9050.log 2>/dev/null; then
        echo -e "${DOPE} Found WebDAV! Running davtest -move -sendbd auto -url http://$rhost:9050/ | tee -a davtestscan-$rhost-9050.log"
        davtest -move -sendbd auto -url http://$rhost:9050/ | tee -a davtestscan-$rhost-9050.log
    else
        :
    fi
    if grep -q "443" openports-$rhost.txt; then
        wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        echo -e "${DOPE} Running The Following Commands"
        echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u https://$rhost -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-443.log"
        echo -e "${DOPE} nikto -h https://$rhost/ -output niktoscanport443-$rhost.txt"
        echo -e "${DOPE} whatweb -a 3 https://$rhost:443 | tee whatweb-$rhost-443.log"
        echo -e "${DOPE} curl -O http://$rhost:443/robots.txt"
        echo -e "${DOPE} sslscan https://$rhost:443 | tee sslscan-$rhost-$port.log"
        echo -e "${DOPE} uniscan -u https://$rhost -qweds | tee uniscan-$rhost-443.log"
        curl http://$rhost:443/robots.txt -o robots-$rhost-443.txt
        gnome-terminal --geometry 123x35-0+0 -- bash -c "gobuster -e -u https://$rhost:443 -w $wordlist -s '200,204,301,302,307,403,500' -o gobuster-$rhost-443.txt -t 50 -k; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x26+0+0 -- bash -c "nikto -host https://$rhost:443 -ssl -output niktoscan-port443-$rhost.txt; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x25+0-0 -- bash -c "whatweb -a 3 https://$rhost:443 | tee whatweb-$rhost-443.log; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x25-0-0 -- bash -c "sslscan https://$rhost:443 | tee sslscan-$rhost-$port.log; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x25-0-0 -- bash -c "uniscan -u https://$rhost -qweds | tee uniscan-$rhost-443.log; exec $SHELL" &>/dev/null

        whatweb_process_id() {
            getpid=$(ps -elf | grep whatweb | grep -v grep | awk '{print $4}')
            procid=$(echo $getpid)
            whatwebid=$(expr "$procid" : '.* \(.*\)')
        }
        whatweb_process_id
        if [ $? -eq 0 ]; then
            printf "\e[36m[+]\e[0m Waiting for WHATWEB PID $whatwebid Scan To Finish up \n"
            for i in $(seq 1 50); do
                printf "\e[93m#*\e[0m"
            done
            printf "\n"
            # echo "waiting for PID $procid to finish running NMAP script"
            while ps -p $whatwebid >/dev/null; do sleep 1; done
        else
            :
        fi
        if grep -i "WordPress" whatweb-$rhost-443.log 2>/dev/null; then
            echo -e "${DOPE} Found WordPress! Running wpscan --url https://$rhost/ --enumerate p,t,u | tee -a wpscan-$rhost-443.log"
            wpscan --url https://$rhost/ --enumerate p,t,u | tee -a wpscan-443.log
        elif grep -i "Drupal" whatweb-$rhost-443.log 2>/dev/null; then
            echo -e "${DOPE} Found Drupal! Running droopescan scan drupal -u https://$rhost/ -t 32 | tee -a drupalscan-$rhost-443.log"
            droopescan scan drupal -u https://$rhost/ -t 32 | tee -a drupalscan-443.log
        elif grep -i "Joomla" whatweb-$rhost-443.log 2>/dev/null; then
            echo -e "${DOPE} Found Joomla! Running joomscan --url https://$rhost -ec | tee -a joomlascan-$rhost-443.log"
            joomscan --url https://$rhost/ -ec | tee -a joomlascan-443.log
        elif grep -i "WebDAV" whatweb-$rhost-443.log 2>/dev/null; then
            echo -e "${DOPE} Found WebDAV! Running davtest -move -sendbd auto -url https://$rhost/ | tee -a davtestscan-$rhost-443.log"
            davtest -move -sendbd auto -url https://$rhost | tee -a davtestscan-443.log
        else
            :
        fi
    fi
}

Intense_Nmap_Scan() {
    gnome-terminal --geometry 135x55-0-0 -- bash -c "nmap -vv -Pn -A -O -script-args=unsafe=1 -p $(tr '\n' , <openports-$rhost.txt) -oA nmap/intense-scan-$rhost $rhost; exec $SHELL" &>/dev/null
    printf "\e[93m################### RUNNING NMAP INTENSE SCAN TOP OPEN PORTS ##################################################### \e[0m\n"
    sleep 2

    nmap_process_id() {
        getpid=$(ps -elf | grep nmap | grep -v grep | awk '{print $4}')
        procid=$(echo $getpid)
        nmapid=$(expr "$procid" : '.* \(.*\)')
    }

    nmap_process_id
    if [ $? -eq 0 ]; then
        printf "\e[36m[+] Waiting for NMAP PID $nmapid Scan To Finish up \e[0m\n"
        for i in $(seq 1 50); do
            printf "\e[93m#*\e[0m"
        done
        printf "\n"
        # echo "waiting for PID $procid to finish running NMAP script"
        while ps -p $nmapid >/dev/null; do sleep 1; done
    else
        :
    fi
    gnome-terminal --geometry 105x25-0-0 -- bash -c "nmap -sUV -v --reason -T4 --max-retries 3 --max-rtt-timeout 150ms -pU:53,67-69,111,123,135,137-139,161-162,445,500,514,520,631,998,1434,1701,1900,4500,5353,49152,49154 -oA nmap/udp-$rhost $rhost; exec $SHELL" &>/dev/null
    printf "\e[93m################### RUNNING NMAP TOP UDP PORTS ##################################################### \e[0m\n"
    sleep 2
    nmap_process_id
    if [ $? -eq 0 ]; then
        printf "\e[36m[+] Waiting for UDP NMAP PID $nmapid Scan To Finish up \e[0m\n"
        for i in $(seq 1 50); do
            printf "\e[93m#*\e[0m"
        done
        printf "\n"
        # echo "waiting for PID $procid to finish running NMAP script"
        while ps -p $nmapid >/dev/null; do sleep 1; done
    else
        :
    fi

    cwd=$(pwd)
    echo $cwd
    printf "\e[93m#################################################################################################### \e[0m\n"
    printf "\e[96m[+] Waiting for All SCANS To Finish up \e[0m\n"
    printf "\e[93m#################################################################################################### \e[0m\n"
    printf "\e[96m[+] FINISHED SCANS \e[0m\n"
    printf "\e[93m#################################################################################################### \e[0m\n"
    printf "\e[96m[+] Checking Vulnerabilities \e[0m\n"
    printf "\e[93m#################################################################################################### \e[0m\n"
    cd /opt/ReconScan && python3 vulnscan.py $cwd/nmap/intense-scan-$rhost.xml
    cd - &>/dev/null
}

Enum_SMB() {
    grep -i "/tcp" nmap/open-ports-$rhost.nmap | cut -d "/" -f 1 >openports2.txt
    if [ $(grep -i "445" openports2.txt) ] || [ $(grep -i "139" openports2.txt) ]; then
        echo -e "\e[92m[+]\e[0m Running SMBCLIENT, Checking shares" | tee -a smb-scan-$rhost.txt
        smbclient -L //$rhost -U "guest"% | tee -a smb-scan-$rhost.txt

        echo -e "\e[92m[+]\e[0m Running ENUM4LINUX" | tee -a smb-scan-$rhost.txt
        enum4linux -av $rhost | tee -a smb-scan-$rhost.txt

        echo -e "\e[92m[+]\e[0m Running NMBLOOKUP" | tee -a smb-scan-$rhost.txt
        nmblookup -A $rhost | tee -a smb-scan-$rhost.txt

        # create an nmap directory if one doesn't exist

        echo -e "\e[92m[+]\e[0m Running All SMB nmap Vuln / Enum checks" | tee -a smb-scan-$rhost.txt
        nmap -vv -sV -Pn -p139,445 --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse --script-args=unsafe=1 -oA nmap/smbvulns-$rhost $rhost | tee -a smb-scan-$rhost.txt

        echo -e "\e[92m[+]\e[0m Running NBTSCAN" | tee -a smb-scan-$rhost.txt
        nbtscan -rvh $rhost | tee -a smb-scan-$rhost.txt

        echo -e "\e[92m[+]\e[0m Running smbmap" | tee -a smb-scan-$rhost.txt
        smbmap -H $rhost | tee -a smb-scan-$rhost.txt

        echo -e "\e[92m[+]\e[0m All checks completed Successfully" | tee -a smb-scan-$rhost.txt
    fi
}

Open_Ports_Scan
Enum_Web
Enum_SMB
Intense_Nmap_Scan

# to-do
# Scan_Udp() {
#     nmap -v -Pn -sU --top-ports 100 -T3 --max-retries 3 --max-rtt-timeout 150ms -oA nmap/udp-$rhost $rhost
# }
# Scan_Udp

Enum_SNMP() {
    cwd=$(pwd)
    # echo $cwd
    cd $cwd
    grep -i "/udp" nmap/udp-$rhost.nmap | cut -d "/" -f 1 | tail -n 1 >udp-scan-$rhost.txt
    grep -i "/udp" nmap/udp-$rhost.nmap | cut -d "/" -f 1 | tail -n 1 >>udp-scan-$rhost.txt
    if [ $(grep -q "161" udp-scan-$rhost.txt) ] || [ $(grep -q "162" udp-scan-$rhost.txt) ]; then
        printf "\e[93m################### RUNNING SNMP-ENUMERATION ##################################################### \e[0m\n"
        onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $rhost | tee -a snmpenum-scan.log
        echo "${DOPE} Running: snmp-check -c public -v 1 -d $rhost | tee -a snmpenum-scan.log "
        echo "${DOPE} Running: snmp-check -c public -v 2 -d $rhost | tee -a snmpenum-scan.log "
        snmp-check -c public -v 1 -d $rhost | tee -a snmpenum-scan.log
        snmp-check -c public -v 2 -d $rhost | tee -a snmpenum-scan.log
        # echo "${DOPE} Running: snmpenum $rhost public /opt/snmpenum/windows.txt | tee -a snmpenum-scan.log"
        # snmpenum $rhost public /opt/snmpenum/windows.txt | tee -a snmpenum-scan.log

    else
        echo -e "${DOPE} SNMP Port not open."
    fi
}
Enum_SNMP

GOOD_MEASUERE() {
    echo -e "${DOPE} Running Full Nmap TCP port Scan For Good Measuere, just in case we missed one ;)"
    nmap -vv -Pn -A -O -script-args=unsafe=1 -p- -T4 -oA nmap/full-tcp-scan-$rhost $rhost
    printf "\e[93m#################################################################################################### \e[0m\n"
    printf "\e[96m##############################    See You Space Cowboy...  ######################################### \e[0m\n"
    printf "\e[93m#################################################################################################### \e[0m\n"
}
GOOD_MEASUERE

Clean_Up() {
    cwd=$(pwd)
    cd $cwd
    rm openports-$rhost.txt
    rm openports2.txt
    rm udp-scan-$rhost.txt
    mkdir $rhost-report
    find $cwd/ -maxdepth 1 -name "*$rhost*.*" -exec mv {} $cwd/$rhost-report/ \;
    find $cwd/ -maxdepth 1 -name 'dirsearch*.*' -exec mv {} $cwd/$rhost-report/ \;
}
Clean_Up

traperr() {
    echo "ERROR: ${BASH_SOURCE[1]} at about ${BASH_LINENO[0]}"
}

set -o errtrace
trap traperr ERR

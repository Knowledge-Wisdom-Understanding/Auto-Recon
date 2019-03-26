#!/usr/bin/env bash
# A script to automate Web Enumeration on KALI LINUX

# TODO, Make Banner


get_target() {
    printf "Enter Target IP-ADDRESS: "
    read IP
    
    if [[ $IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "\e[92m[+] SUCCESS"
    else
        echo -e "\e[31m[+] NOT A VALID IP ADDRESS"
    fi
}

get_port() {
    printf "Enter the Target PORT: "
    read PORT
    
    if [[ $PORT =~ ^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$ ]]; then
        echo -e "\e[92m[+] SUCCESS"
    else
        echo -e "\e[31m[+] NOT A VALID PORT NUMBER"
    fi
}

get_http() {
    printf "Enter http or https: "
    read HP
    if [[ $HP =~ ^http|https ]]; then
        echo -e "\e[92m[+] SUCCESS"
    else
        echo -e "\e[31m[+] must be lowercase. please enter http or https"
    fi
}

# TODO. if port 445 is open run this nmap script, nmap -PS445 -p445 --script=smb-os-discovery,smb-enum-shares,smb-ls --script-args=ls.maxdepth=10 192.168.1.9

# run uniscan in new terminal-bottom left
uniscan() {
    gnome-terminal --geometry 105x25-0-0 -- bash -c "uniscan -u $HP://$IP:$PORT -qweds | tee uniscan.log; exec $SHELL"
}

# gobuster() {
#     wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
#     gnome-terminal --geometry 123x35-0+0 -- bash -c "gobuster -e -u $HP://$IP:$PORT -w $wordlist -o gobusterOutput.txt; exec $SHELL"
# }

# Running Nikto2 in new terminal-bottom left
nikto() {
    gnome-terminal --geometry 105x25+0-0 -- bash -c "nikto -h $HP://$IP:$PORT -Format txt -C all -o niktoutput.txt; exec $SHELL"
}

# Running Dirsearch in new terminal-top right
dirsearch() {
    # wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    gnome-terminal --geometry 105x26-0+0 -- bash -c "python3 /opt/dirsearch/dirsearch.py -u $HP://$IP:$PORT -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch.log; exec $SHELL"
    
}

dirb() {
    gnome-terminal --geometry 105x25+0+0 -- bash -c "dirb $HP://$IP:$PORT /usr/share/wordlists/dirb/big.txt -o dirbOutput.txt; exec $SHELL"
}


whatweb() {
    gnome-terminal --geometry 105x25+0-0 -- bash -c "whatweb -a 3 $HP://$IP:$PORT; exec $SHELL"
}

fimap() {
    gnome-terminal --geometry 105x25+0-0 -- bash -c "fimap -u $HP://$IP:$PORT; exec $SHELL"
}

# wpscan() {
#     gnome-terminal --geometry 105x25+0-0 -- bash -c "wpscan --url $HP://$IP:$PORT --wp-content-dir wp-login.php --enumerate p,t,u,tt | tee wpscan.log; exec $SHELL"
# }

eyewitness() {
    gnome-terminal -- bash -c "eyewitness --threads 5 --ocr --no-prompt --active-scan --all-protocols --web --single $IP --add-http-ports $PORT; exec $SHELL"
}

# cwd=$(pwd)

# create_web_report_dir(){
#     if [ -d web_report ]; then
#         find $cwd/ -name 'dirsearch.log' -exec mv {} $cwd/web_report/ \;
#         find $cwd/ -name 'uniscan.log' -exec mv {} $cwd/web_report/ \;
#         find $cwd/ -name 'niktoutput.txt' -exec mv {} $cwd/web_report/ \;
#         find $cwd/ -name 'dirbOutput.txt' -exec mv {} $cwd/web_report/ \;
#     else
#         mkdir -p web_report
#         find $cwd/ -name 'dirsearch.log' -exec mv {} $cwd/web_report/ \;
#         find $cwd/ -name 'uniscan.log' -exec mv {} $cwd/web_report/ \;
#         find $cwd/ -name 'niktoutput.txt' -exec mv {} $cwd/web_report/ \;
#         find $cwd/ -name 'dirbOutput.txt' -exec mv {} $cwd/web_report/ \;
#     fi
# }


traperr() {
    echo "ERROR: ${BASH_SOURCE[1]} at about ${BASH_LINENO[0]}"
}

set -o errtrace
trap traperr ERR

get_target
get_port
get_http
nikto
uniscan
dirb
whatweb
dirsearch
fimap
# wpscan
eyewitness
# create_web_report_dir

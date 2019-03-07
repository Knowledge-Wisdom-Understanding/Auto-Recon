#!/usr/bin/env bash
# A script to automate information gathering on KALI LINUX

# banner
banner() {
    
    printf "\e[1;92m   _________                      ____________                               \e[0m\n"
    printf "\e[1;92m  /___      \           __       /__          \                      __     \e[0m\n"
    printf "\e[1;92m     /   _   \   __ ___/  |_  ____  \______*   \ ____   ____  ____  /  |___ \e[0m\n"
    printf "\e[1;92m   _/   /_\   \ |  |  \   __\/  _ \   |       _// __ \_/ ___\/  _ \|       | \e[0m\n"
    printf "\e[1;92m  |     ___    \|  |  /|  | (  |_| )  |    |   \  ___/\  \__(  |_| )   |   | \e[0m\n"
    printf "\e[1;92m  |____/   \____|____/ |__|  \____/   |____|_  /\___  |\___  )____/|___|  /  \e[0m\n"
    printf "\e[1;92m                                             \/     \/     \/           \/  \e[0mv1.1\n"
    printf "\e[1;77m\e[45m        AUTO RECON by @Knowledge-Wisdom-Understanding                  \e[0m\n"
    printf "\n"
    
}

# get target
get_target() {
    printf "Enter Target IP-ADDRESS: "
    read IP
    
    if [[ $IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "\e[92m[+] SUCCESS"
    else
        echo -e "\e[31m[+] NOT A VALID IP ADDRESS"
    fi
}


# create an nmap directory if one doesn't exist
create_nmap_dir(){
    if [ -d nmap ]; then
        echo "nmap directory exists"
    else
        echo "creating nmap directory"
        mkdir -p nmap
    fi
}

# run full tcp port scan with default nmap scripts in new terminal window.
run_nmap() {
    gnome-terminal --geometry 118x50+0+0 -- bash -c "nmap -sC -v -sV -p- -T4 -oA nmap/initial $IP; exec $SHELL"
}

# run uniscan in seperate window
# uniscan() {
#     gnome-terminal --geometry 92x20-0+0 -- bash -c "uniscan -u http://$IP -qweds; exec $SHELL"
# }

# gobuster() {
#     wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
#     gnome-terminal --geometry 123x35-0-0 -- bash -c "gobuster -e -u http://$IP -w $wordlist -o gobusterOutput.txt; exec $SHELL"
# }

dirsearch() {
    wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    gnome-terminal --geometry 92x20-0+0 -- bash -c "python3 /opt/dirsearch/dirsearch.py -u http://$IP -w $wordlist -t 80 -e php,asp,aspx,htm; exec $SHELL"
}

dirb() {
    gnome-terminal --geometry 123x25-0-0 -- bash -c "dirb http://$IP -o dirbOutput.txt; exec $SHELL"
}

banner
get_target
create_nmap_dir
run_nmap
# uniscan
dirsearch
# gobuster
dirb

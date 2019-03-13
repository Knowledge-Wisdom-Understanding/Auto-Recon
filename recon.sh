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
    printf "\e[1;92m                                             \/     \/     \/           \/  \e[0mv2.4\n"
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
    
    gnome-terminal --geometry 105x26+0+0 -- bash -c "nmap -sC -v -sV -p- -T4 -oA nmap/initial $IP; exec $SHELL"
    printf "\e[93m################### RUNNING NMAP ALL TCP PORTS ################################ \e[0m\n"
    sleep 2
    
    getpid=`ps -elf | grep nmap | grep -v grep | awk '{print $4}'`
    procid=`echo $getpid`
    nmapid=`expr "$procid" : '.* \(.*\)'`
    if [ $? -eq 0 ]
    then
        printf "\e[36m[+] Waiting for NMAP PID $nmapid Scan To Finish up \e[0m\n"
        for i in $(seq 1 50 )
        do
            printf "\e[93m#*\e[0m"
        done
        printf "\n"
        # echo "waiting for PID $procid to finish running NMAP script"
        while ps -p $nmapid > /dev/null; do sleep 1; done;
    else
        echo "failed to find process with PID $nmapid" >&2
        exit 1
    fi
    cwd=$(pwd)
    cd /opt/pentest-machine && source pm/bin/activate && ./pentest-machine.py -x $cwd/nmap/initial.xml
    # cd /opt/pentest-machine && echo $IP > $cwd/hostlist.txt && ./pentest-machine.py -l $cwd/hostlist.txt
    cd $cwd
    gnome-terminal --geometry 105x25-0-0 -- bash -c "nmap -sSUV -v --reason -T4 --max-retries 3 --max-rtt-timeout 150ms -pU:53,67-69,111,123,135,137-139,161-162,445,500,514,520,631,998,1434,1701,1900,4500,5353,49152,49154 -oA nmap/udp $IP; exec $SHELL"
    printf "\e[93m################### RUNNING NMAP TOP UDP PORTS ################################ \e[0m\n"
    sleep 2
    
    getpid=`ps -elf | grep nmap | grep -v grep | awk '{print $4}'`
    procid=`echo $getpid`
    nmapid=`expr "$procid" : '.* \(.*\)'`
    if [ $? -eq 0 ]
    then
        printf "\e[36m[+] Waiting for UDP NMAP PID $nmapid Scan To Finish up \e[0m\n"
        for i in $(seq 1 50 )
        do
            printf "\e[93m#*\e[0m"
        done
        printf "\n"
        # echo "waiting for PID $procid to finish running NMAP script"
        while ps -p $nmapid > /dev/null; do sleep 1; done;
    else
        echo "failed to find process with PID $nmapid" >&2
        exit 1
    fi
    cd /opt/pentest-machine && source pm/bin/activate && ./pentest-machine.py -x $cwd/nmap/udp.xml
    printf "\e[93m[+] Waiting for All SCANS To Finish up \e[0m\n"
    printf "\e[36m########################################################## \e[0m\n"
    printf "\e[93m[+] FINISHED SCANS \e[0m\n"
    printf "\e[93m[+] Review Enumeration Info \e[0m\n"
    echo "[+] See you Space Cowboy..."
}

# run uniscan in new terminal-bottom left
# uniscan() {
#     gnome-terminal --geometry 105x25+0-0 -- bash -c "uniscan -u http://$IP -qweds; exec $SHELL"
# }

# gobuster() {
#     wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
#     gnome-terminal --geometry 123x35-0-0 -- bash -c "gobuster -e -u http://$IP -w $wordlist -o gobusterOutput.txt; exec $SHELL"
# }

# Running Nikto2 in new terminal-bottom left
nikto() {
    gnome-terminal --geometry 105x25+0-0 -- bash -c "nikto -h $IP -Format txt -o niktoutput.txt; exec $SHELL"
}

# Running Dirsearch in new terminal-top right
dirsearch() {
    wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    gnome-terminal --geometry 105x26-0+0 -- bash -c "python3 /opt/dirsearch/dirsearch.py -u http://$IP -w $wordlist -t 80 -e php,asp,aspx,htm; exec $SHELL"
}

# dirb() {
#     gnome-terminal --geometry 105x25-0-0 -- bash -c "dirb http://$IP -o dirbOutput.txt; exec $SHELL"
# }



banner
get_target
create_nmap_dir
nikto
# dirb
# uniscan
# gobuster
dirsearch
run_nmap




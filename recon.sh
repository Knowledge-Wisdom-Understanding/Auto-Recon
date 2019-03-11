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
    printf "\e[1;92m                                             \/     \/     \/           \/  \e[0mv2.3\n"
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
    printf "\e[93m########################################################## \e[0m\n"
    sleep 3
    
    getpid=`ps -elf | grep nmap | grep -v grep | awk '{print $4}'`
    procid=`echo $getpid`
    nmapid=`expr "$procid" : '.* \(.*\)'`
    if [ $? -eq 0 ]
    then
        printf "\e[93m[+] Waiting for NMAP PID $nmapid Scan To Finish up \e[0m\n"
        for i in $(seq 1 50 )
        do
            printf "\e[36m#*\e[0m"
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
    cd /opt/pentest-machine && echo $IP > $cwd/hostlist.txt && ./pentest-machine.py -l $cwd/hostlist.txt
    cd $cwd
    printf "\e[93m[+] Waiting for All SCANS To Finish up \e[0m\n"
    printf "\e[93m########################################################## \e[0m\n"
    getpid=`ps -elf | grep tcpdump | grep -v grep | awk '{print $4}'`
    procid=`echo $getpid`
    tcpdumpid=`expr "$procid" : '.* \(.*\)'`
    getpid=`ps -elf | grep dirsearch  | grep -v grep | awk '{print $4}'`
    procid=`echo $getpid`
    dirsearchid=`expr "$procid" : '.* \(.*\)'`
    getpid=`ps -elf | grep nikto  | grep -v grep | awk '{print $4}'`
    procid=`echo $getpid`
    niktoid=`expr "$procid" : '.* \(.*\)'`
    getpid=`ps -elf | grep dirb  | grep -v grep | awk '{print $4}'`
    procid=`echo $getpid`
    dirbid=`expr "$procid" : '.* \(.*\)'`
    getpid=`ps -elf | grep netcreds  | grep -v grep | awk '{print $4}'`
    procid=`echo $getpid`
    netcredsid=`expr "$procid" : '.* \(.*\)'`
    if [[ $nmapid ]] || [[ $dirsearchid ]] || [[ $niktoid ]] || [[ $dirbid ]]
    then
        printf "\e[93m[+] Waiting for All SCANS To Finish up \e[0m\n"
        printf "\e[93m########################################################## \e[0m\n"
        while ps -p $tcpdumpid > /dev/null; do sleep 1;
            if ! { [[ $nmapid ]] && [[ $dirsearchid ]] && [[ $niktoid ]] && [[ $dirbid ]] && [[ $netcredsid ]]; };
            then
                getpid=`ps -elf | grep tcpdump | grep -v grep | awk '{print $4}'`
                procid=`echo $getpid`
                tcpdumpid=`expr "$procid" : '.* \(.*\)'`
                sleep 5
                kill -1 $tcpdumpid
                break
            else
                echo "failed to find process with PID $tcpdumpid" >&2
                exit 1
            fi
        done;
        
    fi
}

tcpdump() {
    gnome-terminal --geometry 105x10+200+200 -- bash -c "tcpdump -vv -U -i tun0 host $IP -s0 -w dump.pcap && sleep 5; exec $SHELL"
}

# run uniscan in seperate window
# uniscan() {
#     gnome-terminal --geometry 105x25+0-0 -- bash -c "uniscan -u http://$IP -qweds; exec $SHELL"
# }

# gobuster() {
#     wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
#     gnome-terminal --geometry 123x35-0-0 -- bash -c "gobuster -e -u http://$IP -w $wordlist -o gobusterOutput.txt; exec $SHELL"
# }

nikto() {
    gnome-terminal --geometry 105x25+0-0 -- bash -c "nikto -h $IP -Format txt -o niktoutput.txt; exec $SHELL"
}

dirsearch() {
    wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    gnome-terminal --geometry 105x26-0+0 -- bash -c "python3 /opt/dirsearch/dirsearch.py -u http://$IP -w $wordlist -t 80 -e php,asp,aspx,htm; exec $SHELL"
}

dirb() {
    gnome-terminal --geometry 105x25-0-0 -- bash -c "dirb http://$IP -o dirbOutput.txt; exec $SHELL"
}

netcreds() {
    getpid=`ps -elf | grep tcpdump | grep -v grep | awk '{print $4}'`
    procid=`echo $getpid`
    tcpdumpid=`expr "$procid" : '.* \(.*\)'`
    if [ $? -eq 0 ]
    then
        printf "\e[93m[+] Waiting for TCPDUMP To Finish up \e[0m\n"
        printf "\e[93m########################################################## \e[0m\n"
    else
        echo "failed to find process with PID $tcpdumpid" >&2
        exit 1
    fi
    dumpfile=$cwd/dump.pcap
    if [[ -e $dumpfile ]];
    then
        sleep 20
        cd $cwd
        python /opt/net-creds/net-creds.py -p $cwd/dump.pcap && sleep 7
    else
        sleep 20
        cd $cwd
        gnome-terminal --working-directory=$cwd/ --geometry 105x25+500+200 -- bash -c "python /opt/net-creds/net-creds.py -p $cwd/dump.pcap && sleep 7; exec $SHELL"
    fi
}



banner
get_target
create_nmap_dir
tcpdump
# uniscan
nikto
dirsearch
# gobuster
dirb
run_nmap
netcreds


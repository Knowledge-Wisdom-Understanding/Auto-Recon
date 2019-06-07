#!/usr/bin/env bash

banner1() {

    printf "\e[1;92m   _____________                  ________________                               \e[0m\n"
    printf "\e[1;92m  /___/___      \         ____   /___/__          \                    ____      \e[0m\n"
    printf "\e[1;92m      /  /   _   \_____ _/_/  |______|__|_____ *   \__________________/ /  |___  \e[0m\n"
    printf "\e[1;92m   __/__/   /_\   \ |  |  \   __\/  _ \|  |       __/ __ \_/ ___\/  _ \|       | \e[0m\n"
    printf "\e[1;92m  |   |     ___    \|  |  /|  | (  |_| )  |    |   \  ___/\  \__(  |_| )   |   | \e[0m\n"
    printf "\e[1;92m  |___|____/\__\____|____/_|__|\_\____/|__|____|_  /\___  |\___  \____/|___|  /  \e[0m\n"
    printf "\e[1;92m                                             \___\/  \__\/  \___\/      \___\/   \e[0mv3.0\n"
    printf "\e[1;77m\e[45m         AUTO RECON by github.com/Knowledge-Wisdom-Understanding                        \e[0m\n"
    printf "\n"

}

banner2() {

    printf "\e[1;92m  █████╗ ██╗   ██╗████████╗ ██████╗     ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗ \e[0m\n"
    printf "\e[1;92m ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║ \e[0m\n"
    printf "\e[1;92m ███████║██║   ██║   ██║   ██║   ██║    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ \e[0m\n"
    printf "\e[1;92m ██╔══██║██║   ██║   ██║   ██║   ██║    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ \e[0m\n"
    printf "\e[1;92m ██║  ██║╚██████╔╝   ██║   ╚██████╔╝    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║ \e[0m\n"
    printf "\e[1;92m ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝ \e[0mv3.0\n"
    printf "\e[1;77m\e[45m         AUTO RECON by github.com/Knowledge-Wisdom-Understanding                           \e[0m\n"
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

getUpHosts() {
    # Live Hosts
    baseip=$(echo $rhost | cut -d "." -f1-3)
    cidr_range=$(echo $baseip".0")
    nmap -sn $cidr_range/24 -oG /tmp/live-hosts.txt >/dev/null
    cat /tmp/live-hosts.txt | grep "Up" | cut -d " " -f2 >live-hosts-ip.txt
    rm /tmp/live-hosts.txt
    Live_Host=live-hosts-ip.txt
    echo -e "${DOPE} Live Hosts Recon On $cidr_range/24 Done!"
    cat live-hosts-ip.txt
    # cat $uphostfile
}

Full_TCP_Scan_All() {
    Live_Host=live-hosts-ip.txt
    if [ -e live-hosts-ip.txt ]; then
        echo ""
        echo -e "${DOPE} Scanning all hosts"
        echo -e "${DOPE} Running: nmap -v -Pn -A -O -p- --max-retries 1 -sS --max-rate 500 -T4 -v -oA nmap/hostfilescan -iL $Live_Host In new Terminal Window."
        gnome-terminal --geometry 105x26-0+0 -- bash -c "nmap -v -Pn -A -O -p- --max-retries 1 -sS --max-rate 500 -T4 -v -oA nmap/hostfilescan -iL $Live_Host; exec $SHELL" &>/dev/null
    fi
}

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

Enum_Web() {
    grep -w "http" nmap/open-ports-$rhost.nmap | cut -d "/" -f 1 >openports-$rhost.txt
    portfilename=openports-$rhost.txt
    echo $portfilename
    httpPortsLines=$(cat $portfilename)
    for port in $httpPortsLines; do
        wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        echo -e "${DOPE} Running The Following Commands"
        echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u http://$rhost:$port -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-80.log"
        echo -e "${DOPE} nikto -h http://$rhost:$port -output niktoscan-$port-$rhost.txt"
        echo -e "${DOPE} whatweb -a 3 http://$rhost:$port/ | tee whatweb-$rhost:$port.log"
        echo -e "${DOPE} curl -O http://$rhost:$port/robots.txt"
        echo -e "${DOPE} uniscan -u http://$rhost:$port/ -qweds | tee uniscan-$rhost-$port.log"
        curl http://$rhost:$port/robots.txt -o robots-$rhost-$port.txt
        gnome-terminal --geometry 105x26-0+0 -- bash -c "python3 /opt/dirsearch/dirsearch.py -u http://$rhost:$port -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-$port.log; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x26+0+0 -- bash -c "nikto -host http://$rhost:$port -output niktoscan-$port-$rhost.txt; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x25+0-0 -- bash -c "whatweb -a 3 http://$rhost:$port | tee whatweb-$rhost-$port.log; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x25-0-0 -- bash -c "uniscan -u http://$rhost:$port -qweds | tee uniscan-$rhost-$port.log; exec $SHELL" &>/dev/null
        # fi
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
        if grep -i "WordPress" whatweb-$rhost-$port.log 2>/dev/null; then
            echo -e "${DOPE} Found WordPress! Running wpscan --url http://$rhost/ --enumerate p,t,u | tee -a wpscan-$rhost-80.log"
            wpscan --url http://$rhost:$port/ --enumerate p,t,u | tee -a wpscan.log
        elif grep -i "Drupal" whatweb-$rhost-$port.log 2>/dev/null; then
            echo -e "${DOPE} Found Drupal! Running droopescan scan drupal -u http://$rhost -t 32 | tee -a drupalscan-$rhost-80.log"
            droopescan scan drupal -u http://$rhost:$port/ -t 32 | tee -a drupalscan-$rhost-$port.log
        elif grep -i "Joomla" whatweb-$rhost-$port.log 2>/dev/null; then
            echo -e "${DOPE} Found Joomla! Running joomscan --url http://$rhost/ -ec | tee -a joomlascan-$rhost-$port.log"
            joomscan --url http://$rhost:$port/ -ec | tee -a joomlascan-$rhost-$port.log
        elif grep -i "WebDAV" whatweb-$rhost-$port.log 2>/dev/null; then
            echo -e "${DOPE} Found WebDAV! Running davtest -move -sendbd auto -url http://$rhost:$port/ | tee -a davtestscan-$rhost-$port.log"
            davtest -move -sendbd auto -url http://$rhost:$port/ | tee -a davtestscan-$port.log
        else
            :
        fi
    done
}

Enum_Web_SSL() {
    grep -w "https" nmap/open-ports-$rhost.nmap | cut -d "/" -f 1 >openportsSSL-$rhost.txt
    portfilenameSSL=openportsSSL-$rhost.txt
    echo $portfilenameSSL
    httpPortsLinesSSL=$(cat $portfilenameSSL)
    for port in $httpPortsLinesSSL; do
        wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
        echo -e "${DOPE} Running The Following Commands"
        echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u http://$rhost:$port -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-80.log"
        echo -e "${DOPE} nikto -h http://$rhost:$port -output niktoscan-$port-$rhost.txt"
        echo -e "${DOPE} whatweb -a 3 http://$rhost:$port/ | tee whatweb-$rhost:$port.log"
        echo -e "${DOPE} curl -O http://$rhost:$port/robots.txt"
        echo -e "${DOPE} uniscan -u http://$rhost:$port/ -qweds | tee uniscan-$rhost-$port.log"
        curl http://$rhost:$port/robots.txt -o robots-$rhost-$port.txt
        gnome-terminal --geometry 123x35-0+0 -- bash -c "gobuster -e -u https://$rhost:443 -w $wordlist -s '200,204,301,302,307,403,500' -o gobuster-$rhost-443.txt -t 50 -k; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x26+0+0 -- bash -c "nikto -host https://$rhost:$port -output niktoscan-$port-$rhost.txt; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x25+0-0 -- bash -c "whatweb -a 3 https://$rhost:$port | tee whatweb-$rhost-$port.log; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x25-0-0 -- bash -c "uniscan -u https://$rhost:$port -qweds | tee uniscan-$rhost-$port.log; exec $SHELL" &>/dev/null
        gnome-terminal --geometry 105x25-0-0 -- bash -c "sslscan https://$rhost:$port | tee sslscan-$rhost-$port.log; exec $SHELL" &>/dev/null
        # fi
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
        if grep -i "WordPress" whatweb-$rhost-$port.log 2>/dev/null; then
            echo -e "${DOPE} Found WordPress! Running wpscan --url https://$rhost/ --enumerate p,t,u | tee -a wpscan-$rhost-$port.log"
            wpscan --url https://$rhost:$port/ --enumerate p,t,u | tee -a wpscan.log
        elif grep -i "Drupal" whatweb-$rhost-$port.log 2>/dev/null; then
            echo -e "${DOPE} Found Drupal! Running droopescan scan drupal -u https://$rhost -t 32 | tee -a drupalscan-$rhost-$port.log"
            droopescan scan drupal -u https://$rhost:$port/ -t 32 | tee -a drupalscan.log
        elif grep -i "Joomla" whatweb-$rhost-$port.log 2>/dev/null; then
            echo -e "${DOPE} Found Joomla! Running joomscan --url https://$rhost/ -ec | tee -a joomlascan-$rhost-$port.log"
            joomscan --url https://$rhost:$port/ -ec | tee -a joomlascan-$rhost-$port.log
        elif grep -i "WebDAV" whatweb-$rhost-$port.log 2>/dev/null; then
            echo -e "${DOPE} Found WebDAV! Running davtest -move -sendbd auto -url https://$rhost:$port/ | tee -a davtestscan-$rhost-$port.log"
            davtest -move -sendbd auto -url https://$rhost:$port/ | tee -a davtestscan-$port.log
        else
            :
        fi
    done
}

Intense_Nmap_UDP_Scan() {
    # gnome-terminal --geometry 135x55+0+0 -- bash -c "nmap -vv -Pn -A -O -script-args=unsafe=1 -p $(tr '\n' , <openports-$rhost.txt) -oA nmap/intense-scan-$rhost $rhost; exec $SHELL" &>/dev/null
    # printf "\e[93m################### RUNNING NMAP INTENSE SCAN TOP OPEN PORTS ##################################################### \e[0m\n"
    # sleep 2

    # nmap_process_id() {
    #     getpid=$(ps -elf | grep nmap | grep -v grep | awk '{print $4}')
    #     procid=$(echo $getpid)
    #     nmapid=$(expr "$procid" : '.* \(.*\)')
    # }

    # nmap_process_id
    # if [ $? -eq 0 ]; then
    #     printf "\e[36m[+] Waiting for NMAP PID $nmapid Scan To Finish up \e[0m\n"
    #     for i in $(seq 1 50); do
    #         printf "\e[93m#*\e[0m"
    #     done
    #     printf "\n"
    #     # echo "waiting for PID $procid to finish running NMAP script"
    #     while ps -p $nmapid >/dev/null; do sleep 1; done
    # else
    #     :
    # fi
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

    # cwd=$(pwd)
    # echo $cwd
    printf "\e[93m#################################################################################################### \e[0m\n"
    printf "\e[96m[+] Waiting for All SCANS To Finish up \e[0m\n"
    printf "\e[93m#################################################################################################### \e[0m\n"
    printf "\e[96m[+] FINISHED SCANS \e[0m\n"
    printf "\e[93m#################################################################################################### \e[0m\n"
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

getUpHosts
Open_Ports_Scan
Enum_Web
Enum_Web_SSL
Intense_Nmap_UDP_Scan
Enum_SMB

Enum_SNMP() {
    cwd=$(pwd)
    # echo $cwd
    cd $cwd
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
    grep -i "161/udp   open" nmap/udp-$rhost.nmap | cut -d "/" -f 1 >udp-scan-$rhost.txt
    if (grep -q "161" udp-scan-$rhost.txt); then
        printf "\e[93m################### RUNNING SNMP-ENUMERATION ##################################################### \e[0m\n"

        echo -e "${DOPE} Running: onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $rhost | tee -a snmpenum-$rhost.log "
        onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $rhost | tee -a snmpenum-$rhost.log
        echo -e "${DOPE} Running: snmp-check -c public -v 1 -d $rhost | tee -a snmpenum-$rhost.log "
        # echo -e "${DOPE} Running: snmp-check -c public -v 2 -d $rhost | tee -a snmpenum-scan.log "
        snmp-check -c public -v 1 -d $rhost | tee -a snmpenum-$rhost.log
        # snmp-check -c public -v 2 -d $rhost
        # echo "${DOPE} Running: snmpenum $rhost public /opt/snmpenum/windows.txt | tee -a snmpenum-scan.log"
        # snmpenum $rhost public /opt/snmpenum/windows.txt | tee -a snmpenum-scan.log
    fi
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
    grep -i "162/udp   open" nmap/udp-$rhost.nmap | cut -d "/" -f 1 >udp-scan2-$rhost.txt
    if (grep -q "162" udp-scan2-$rhost.txt); then
        printf "\e[93m################### RUNNING SNMP-ENUMERATION ##################################################### \e[0m\n"

        echo -e "${DOPE} Running: onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $rhost | tee -a snmpenum-scan.log "
        onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $rhost | tee -a snmpenum-$rhost.log
        echo -e "${DOPE} Running: snmp-check -c public -v 1 -d $rhost | tee -a snmpenum-$rhost.log "
        echo -e "${DOPE} Running: snmp-check -c public -v 2 -d $rhost | tee -a snmpenum-$rhost.log "
        # snmp-check -c public -v 1 -d $rhost
        snmp-check -c public -v 2 -d $rhost | tee -a snmpenum-$rhost.log
    else
        :
    fi
}

FULL_TCP_GOOD_MEASUERE_VULN_SCAN() {
    cwd=$(pwd)
    echo -e "${DOPE} Running Full Nmap TCP port Scan For Good Measuere, just in case we missed one ;)"
    # nmap -vv -Pn -A -O -script-args=unsafe=1 -sS -p 1521 -T4 -oA nmap/full-tcp-scan-$rhost $rhost
    nmap -vv -Pn -A -O -script-args=unsafe=1 -sS -p- -T4 -oA nmap/full-tcp-scan-$rhost $rhost
    printf "\e[93m#################################################################################################### \e[0m\n"
    printf "\e[96m[+] Checking Vulnerabilities \e[0m\n"
    printf "\e[93m#################################################################################################### \e[0m\n"
    cd /opt/ReconScan && python3 vulnscan.py $cwd/nmap/full-tcp-scan-$rhost.xml
    cd - &>/dev/null
}
FULL_TCP_GOOD_MEASUERE_VULN_SCAN
Enum_SNMP

Enum_Oracle() {
    cwd=$(pwd)
    cd $cwd
    grep -w "1521/tcp open" nmap/full-tcp-scan-$rhost.nmap | cut -d "/" -f 1 >allopenports-$rhost.txt
    if (grep -i "1521" allopenports-$rhost.txt); then
        echo -e "${DOPE} Found Oracle! Running ODAT Enumeration"
        cd /opt/odat/
        ./odat.py sidguesser -s $rhost -p 1521
        ./odat.py passwordguesser -s $rhost -p 1521 -d XE --accounts-file accounts/accounts-multiple.txt
        cd - &>/dev/null
    fi
}
Enum_Oracle
# Full_TCP_Scan_All

Clean_Up() {
    cwd=$(pwd)
    cd $cwd
    rm openports-$rhost.txt
    rm openports2.txt
    rm udp-scan-$rhost.txt
    rm udp-scan2-$rhost.txt
    if [ -d $rhost-report ]; then
        find $cwd/ -maxdepth 1 -name "*$rhost*.*" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'dirsearch*.*' -exec mv {} $cwd/$rhost-report/ \;
        mv live-hosts-ip.txt $rhost-report
    else
        mkdir -p $rhost-report
        find $cwd/ -maxdepth 1 -name "*$rhost*.*" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'dirsearch*.*' -exec mv {} $cwd/$rhost-report/ \;
        mv live-hosts-ip.txt $rhost-report
    fi
}
Clean_Up

footer() {
    printf "\e[93m#################################################################################################### \e[0m\n"
    printf "\e[96m##############################    See You Space Cowboy...  ######################################### \e[0m\n"
    printf "\e[93m#################################################################################################### \e[0m\n"
}
footer

traperr() {
    echo "ERROR: ${BASH_SOURCE[1]} at about ${BASH_LINENO[0]}"
}

set -o errtrace
trap traperr ERR

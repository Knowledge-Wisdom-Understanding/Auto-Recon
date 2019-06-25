#!/usr/bin/env bash

you_dont_have_to_drive_no_fancy_car_just_for_you_to_be_a_shining_star() {
    cat <<"EOF"
                         .                               '      
                         ;                         *            '   
                     - --+- -                              *        '  
                         !                           *                  *
                         .          
             .            
             ;            
         - --+- -         
             !            
             .            
                        .               *   '*
                        ;                       *
                    - --+- -                         *
                        !                                   *
                        .                           *
                                                         *                  
                                         .                      .
                                         .                      ;
                                         :                  - --+- -
                                         !           .          !
      |\\._                              |        .             .
      |   66__                           |_         +
       \    _.P                       ,  | `.
   ,    `) (                    --- --+-<#>-+- ---  --  -
   )\   / __\__                       `._|_,'
  / /  / -._);_)                         T
 |  `\/  \ __|\                          |
  \  ;    )  / )                         !
   `\|   /__/ /__                        :         . : 
     `\______)___)                       .       *

__̴ı̴̴̡̡̡ ̡͌l̡̡̡ ̡͌l̡*̡̡ ̴̡ı̴̴̡ ̡̡͡|̲̲̲͡͡͡ ̲▫̲͡ ̲̲̲͡͡π̲̲͡͡ ̲̲͡▫̲̲͡͡ ̲|̡̡̡ ̡ ̴̡ı̴̡̡ ̡͌l̡̡̡̡.___
   *  .  . *       *    .        .        .   *    ..        .        .   *    ..
 .    *        .   ###     .      .        .            * .      .        .            *
    *.   *        #####   .     *      *        *    .  .     *      *        *    .
  ____       *  ######### *    .  *      .        .  *   .      .        .  *   .
 /   /\  .     ###\#|#/###   ..    *    .      *  .  ..   * .    *    .      *  .  ..  *
/___/  ^8/      ###\|/###  *    *            .      *   *     *  .      *   *
|   ||%%(        # }|{  #
|___|,  \\  ejm    }|{     ,            .  ,,   __̴ı̴̴̡̡̡ ̡͌l̡̡̡ ̡͌l̡*̡̡  .                ,
EOF
}
you_dont_have_to_drive_no_fancy_car_just_for_you_to_be_a_shining_star

banner1() {

    echo -e "\e[1;94m   _____________          ____    ________________                               \e[0m"
    echo -e "\e[1;94m  /___/___      \        /  / |  /___/__          \                   _____      \e[0m"
    echo -e "\e[1;94m      /  /   _   \______/__/  |______|__|_____ *   \_________________/__/  |___  \e[0m"
    echo -e "\e[1;94m   __/__/   /_\   \ |  |  \   __\/  _ \|  |       __/ __ \_/ ___\/  _ \|       | \e[0m"
    echo -e "\e[1;94m  |   |     ___    \|  |  /|  | (  |_| )  |    |   \  ___/\  \__(  |_| )   |   | \e[0m"
    echo -e "\e[1;94m  |___|____/\__\____|____/_|__|\_\____/|__|____|_  /\___  |\___  \____/|___|  /  \e[0m"
    echo -e "\e[1;94m                                             \___\/  \__\/  \___\/      \___\/   \e[0mv3.2"
    echo -e "\e[1;77m\e[45m         AUTO RECON by github.com/Knowledge-Wisdom-Understanding                        \e[0m"
    echo -e ""

}
banner1

DOPE='\e[92m[+]\e[0m'
NOTDOPE='\e[31m[+]\e[0m'
TEAL='\e[96m'
YELLOW='\e93m'
END='\e[0m'

helpFunction() {
    echo -e "${DOPE} Usage: $0 TARGET-IP"
    echo
    echo "Example: "
    echo "./$0 10.11.1.123"
    printf "\n"
    exit 1
}

if [ -z $1 ]; then helpFunction && exit; else rhost=$1; fi

if [[ $rhost =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    :
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
        gnome-terminal --zoom=0.9 --geometry 105x26-0+0 -- bash -c "nmap -v -Pn -A -O -p- --max-retries 1 -sS --max-rate 500 -T4 -v -oA nmap/hostfilescan -iL $Live_Host; exec $SHELL" &>/dev/null
    fi
}

Open_Ports_Scan() {
    echo -e "${DOPE} Scanning $rhost"
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
    nmap -vv -sT -Pn --top-ports 1000 --disable-arp-ping --max-retries 1 -oA nmap/open-ports-$rhost $rhost
}

Enum_Web() {
    grep -w "http" nmap/open-ports-$rhost.nmap | cut -d "/" -f 1 >openports-$rhost.txt
    portfilename=openports-$rhost.txt
    # echo $portfilename
    httpPortsLines=$(cat $portfilename)
    for port in $httpPortsLines; do
        wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        wordlist2="/usr/share/seclists/Discovery/Web-Content/common.txt"
        echo -e "${DOPE} Running The Following Commands"
        echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u http://$rhost:$port -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-$rhost-$port.log"
        echo -e "${DOPE} nikto -h http://$rhost:$port -output niktoscan-$port-$rhost.txt"
        echo -e "${DOPE} whatweb -a 3 http://$rhost:$port/ | tee whatweb-$rhost:$port.log"
        echo -e "${DOPE} curl -O http://$rhost:$port/robots.txt"
        echo -e "${DOPE} uniscan -u http://$rhost:$port/ -qweds"
        echo -e "${DOPE} ./EyeWitness.py --threads 5 --ocr --no-prompt --active-scan --all-protocols --web --single $rhost -d $cwd/eyewitness-report-$rhost"
        echo -e "${DOPE} Checking for Web Application Firewall... wafw00f http://$rhost:$port/"
        wafw00f http://$rhost:$port/ | tee -a wafw00f-$rhost-$port.txt
        curl -sSik http://$rhost:$port/robots.txt -m 10 -o robots-$rhost-$port.txt &>/dev/null
        gnome-terminal --zoom=0.9 --geometry 161x33--12--13 -- bash -c "gobuster -e -u http://$rhost:$port -w $wordlist2 -s '200,204,301,302,307,403' -o gobuster-$rhost-$port.txt -t 50; exec $SHELL" &>/dev/null
        gnome-terminal --zoom=0.9 --geometry 161x31--12+157 -- bash -c "python3 /opt/dirsearch/dirsearch.py -u http://$rhost:$port -t 50 -e php,asp,aspx,txt,html,json,cnf,bak -x 403 --plain-text-report dirsearch-$rhost-$port.log; exec $SHELL" &>/dev/null
        gnome-terminal --zoom=0.9 --geometry 268x31+18+16 -- bash -c "nikto -ask=no -host http://$rhost:$port -output niktoscan-$port-$rhost.txt; exec $SHELL" &>/dev/null
        gnome-terminal --zoom=0.9 --geometry 268x9+16+540 -- bash -c "whatweb -a 3 http://$rhost:$port | tee whatweb-$rhost-$port.log; exec $SHELL" &>/dev/null
        gnome-terminal --zoom=0.9 --geometry 105x31+1157+19 -- bash -c "uniscan -u http://$rhost:$port -qweds; exec $SHELL" &>/dev/null
        echo -e "${DOPE} For a more thorough Web crawl enumeration, consider Running: "
        echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u http://$rhost:$port -w $wordlist -t 50 -e php,asp,aspx,txt,html -x 403 --plain-text-report dirsearch-dlistmedium-$rhost-$port.log"
        cwd=$(pwd)
        mkdir -p eyewitness-report-"$rhost" && cd /opt/EyeWitness
        gnome-terminal --zoom=0.9 --geometry 81x34--12--13 -- bash -c "./EyeWitness.py --threads 5 --ocr --no-prompt --active-scan --all-protocols --web --single $rhost -d $cwd/eyewitness-report-$rhost; exec $SHELL" &>/dev/null
        cd - &>/dev/null
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
        wp1=$(grep -i "WordPress" whatweb-$rhost-$port.log 2>/dev/null)
        wp2=$(grep -i "wp-" nmap/http-vuln-scan.nmap)
        wp3=$(grep -i "wp-content" gobuster-$rhost-$port.txt)
        if [ "$wp1" -o "$wp2" -o "$wp3" ]; then
            echo -e "${DOPE} Found WordPress! Running wpscan --no-update --url http://$rhost:$port/ --wp-content-dir wp-content --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive | tee -a wpscan-$rhost-$port.log"
            gnome-terminal --zoom=0.9 --geometry 108x68+1908--13 -- bash -c "wpscan --no-update --url http://$rhost:$port/ --wp-content-dir wp-content --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive | tee -a wpscan-$rhost-$port.log; exec $SHELL" &>/dev/null
            Cewl() {
                # wpscan --no-update --url http://$rhost-$port/ --wp-content-dir wp-content --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive | tee wpscan-$rhost-$port.log
                wpscan_process_id() {
                    getpid=$(ps -elf | grep wpscan | grep -v grep | awk '{print $4}')
                    procid=$(echo $getpid)
                    wpscanid=$(expr "$procid" : '.* \(.*\)')
                }
                wpscan_process_id
                if [ $? -eq 0 ]; then
                    echo -e "\e[36m[+]\e[0m Waiting for WPSCAN PID $wpscanid Scan To Finish up "
                    for i in $(seq 1 50); do
                        printf "\e[93m#*\e[0m"
                    done
                    printf "\n"
                    # echo "waiting for PID $procid to finish running NMAP script"
                    while ps -p $wpscanid >/dev/null; do sleep 1; done
                else
                    :
                fi
                if [[ -n $(grep -i "User(s) Identified" wpscan-$rhost-$port.log) ]]; then
                    grep -w -A 100 "User(s)" wpscan-$rhost-$port.log | grep -w "[+]" | cut -d " " -f 2 | head -n -7 >wp-users.txt
                    # create wordlist from web-page with cewl
                    cewl http://$rhost:$port/ -m 3 -w cewl-list.txt
                    # add john rules to cewl wordlist
                    john --rules --wordlist=cewl-list.txt --stdout >john-cool-list.txt &>/dev/null
                    # brute force again with wpscan
                    wpscan --url http://$rhost:$port/ --wp-content-dir wp-login.php -U wp-users.txt -P cewl-list.txt threads 50 | tee wordpress-cewl-brute.txt
                    if [[ -z $(grep -i "[SUCCESS]" wordpress-cewl-brute.txt) ]]; then
                        wpscan --url http://$rhost:$port/ --wp-content-dir wp-login.php -U wp-users.txt -P john-cool-list.txt threads 50 | tee wordpress-john-cewl-brute.txt
                    # if password not found then run it again with fasttrack.txt
                    elif [[ -z $(grep -i "[SUCCESS]" wordpress-cewl-brute.txt) ]]; then
                        wpscan --url http://$rhost:$port/ --wp-content-dir wp-login.php -U wp-users.txt -P /usr/share/wordlists/fasttrack.txt threads 50 | tee wordpress-fasttrack-brute.txt
                    fi
                fi
            }
            gnome-terminal --zoom=0.9 --geometry 108x68+1908--13 -x bash -c "$(declare -f Cewl); Cewl; exec $SHELL" &>/dev/null
        elif grep -i "Drupal" whatweb-$rhost-$port.log 2>/dev/null; then
            echo -e "${DOPE} Found Drupal! Running droopescan scan drupal -u http://$rhost -t 32 | tee -a drupalscan-$rhost-80.log"
            droopescan scan drupal -u http://$rhost:$port/ -t 32 | tee -a drupalscan-$rhost-$port.log
        elif grep -i "Joomla" whatweb-$rhost-$port.log 2>/dev/null; then
            echo -e "${DOPE} Found Joomla! Running joomscan --url http://$rhost/ -ec | tee -a joomlascan-$rhost-$port.log"
            joomscan --url http://$rhost:$port/ -ec | tee -a joomlascan-$rhost-$port.log
        elif grep -i "WebDAV" whatweb-$rhost-$port.log 2>/dev/null; then
            echo -e "${DOPE} Found WebDAV! Running davtest -move -sendbd auto -url http://$rhost:$port/ | tee -a davtestscan-$rhost-$port.log"
            davtest -move -sendbd auto -url http://$rhost:$port/ | tee -a davtestscan-$port.log
        elif grep -i "magento" whatweb-$rhost-$port.log 2>/dev/null; then
            echo -e "${DOPE} Found Magento! Running /opt/magescan/bin/magescan scan:all http://$rhost/ | tee -a magescan-$rhost-$port.log"
            cd /opt/magescan
            bin/magescan scan:all http://$rhost:$port/ | tee -a magento-$rhost-$port.log
            cd - &>/dev/null
            echo -e "${DOPE} Consider crawling site with this wordlist: /usr/share/seclists/Discovery/Web-Content/CMS/sitemap-magento.txt"
        else
            :
        fi
    done
}

Web_Vulns() {
    grep -w "http" nmap/open-ports-$rhost.nmap | cut -d "/" -f 1 >openports-$rhost.txt
    echo -e "${DOPE} Running nmap http vuln-scan on all open http ports!"
    nmap -Pn -sV --script=http-vuln*.nse,http-enum.nse,http-methods.nse,http-title.nse -p $(tr '\n' , <openports-$rhost.txt) -oA nmap/http-vuln-enum-scan $rhost
    # nmap -Pn -sV --script=dns-brute.nse -p $(tr '\n' , <openports-$rhost.txt) -oA nmap/http-dns-script-scan $rhost
}

Enum_Web_SSL() {
    grep -w "https" nmap/open-ports-$rhost.nmap | cut -d "/" -f 1 >openportsSSL-$rhost.txt
    portfilenameSSL=openportsSSL-$rhost.txt
    # echo $portfilenameSSL
    httpPortsLinesSSL=$(cat $portfilenameSSL)
    for port in $httpPortsLinesSSL; do
        wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt"
        echo -e "${DOPE} Running The Following Commands"
        echo -e "${DOPE} gobuster -e -u https://$rhost:$port -w $wordlist -s '200,204,301,302,307,403' -o gobuster-$rhost-$port.txt -t 50 -k"
        echo -e "${DOPE} nikto -h https://$rhost:$port -output niktoscan-$port-$rhost.txt"
        echo -e "${DOPE} whatweb -a 3 https://$rhost:$port/ | tee whatweb-$rhost:$port.log"
        echo -e "${DOPE} curl -O https://$rhost:$port/robots.txt"
        echo -e "${DOPE} uniscan -u https://$rhost:$port/ -qweds"
        echo -e "${DOPE} Checking for Web Application Firewall... wafw00f https://$rhost:$port/"
        wafw00f https://$rhost:$port/ | tee -a wafw00f-$rhost-$port.txt
        curl -sSik https://$rhost:$port/robots.txt -m 10 -o robots-$rhost-$port.txt &>/dev/null
        gnome-terminal --zoom=0.9 --geometry 161x33--12--13 -- bash -c "gobuster -e -u https://$rhost:$port -w $wordlist -s '200,204,301,302,307,403' -o gobuster-$rhost-$port.txt -t 50 -k; exec $SHELL" &>/dev/null
        gnome-terminal --zoom=0.9 --geometry 268x31+18+16 -- bash -c "nikto -ask=no -host https://$rhost:$port -output niktoscan-$port-$rhost.txt; exec $SHELL" &>/dev/null
        gnome-terminal --zoom=0.9 --geometry 116x12+964+519 -- bash -c "whatweb -a 3 https://$rhost:$port | tee whatweb-$rhost-$port.log; exec $SHELL" &>/dev/null
        gnome-terminal --zoom=0.9 --geometry 268x9+16+540 -- bash -c "uniscan -u https://$rhost:$port -qweds; exec $SHELL" &>/dev/null
        gnome-terminal --zoom=0.9 --geometry 120x34+18+502 -- bash -c "sslscan https://$rhost:$port | tee sslscan-$rhost-$port.log; exec $SHELL" &>/dev/null

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
            echo -e "${DOPE} Found WordPress! Running wpscan --no-update --disable-tls-checks --url https://$rhost:$port/ --wp-content-dir wp-content --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive | tee -a wpscan2-$rhost-$port.log"
            gnome-terminal --zoom=0.9 --geometry 108x68+1908--13 -- bash -c "wpscan --no-update --disable-tls-checks --url https://$rhost:$port/ --wp-content-dir wp-content --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive | tee -a wpscan2-$rhost-$port.log; exec $SHELL" &>/dev/null
            Cewl2() {
                # wpscan --no-update --url http://$rhost-$port/ --wp-content-dir wp-content --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive | tee wpscan-$rhost-$port.log
                wpscan_process_id() {
                    getpid=$(ps -elf | grep wpscan | grep -v grep | awk '{print $4}')
                    procid=$(echo $getpid)
                    wpscanid=$(expr "$procid" : '.* \(.*\)')
                }
                wpscan_process_id
                if [ $? -eq 0 ]; then
                    printf "\e[36m[+]\e[0m Waiting for WPSCAN PID $wpscanid Scan To Finish up \n"
                    for i in $(seq 1 50); do
                        printf "\e[93m#*\e[0m"
                    done
                    printf "\n"
                    # echo "waiting for PID $procid to finish running NMAP script"
                    while ps -p $wpscanid >/dev/null; do sleep 1; done
                else
                    :
                fi
                if [[ -n $(grep -i "User(s) Identified" wpscan2-$rhost-$port.log) ]]; then
                    grep -w -A 100 "User(s)" wpscan2-$rhost-$port.log | grep -w "[+]" | cut -d " " -f 2 | head -n -7 >wp-users2.txt
                    # create wordlist from web-page with cewl
                    cewl https://$rhost:$port/ -m 3 -w cewl-list2.txt
                    # add john rules to cewl wordlist
                    john --rules --wordlist=cewl-list2.txt --stdout >john-cool-list2.txt &>/dev/null
                    # brute force again with wpscan
                    wpscan --no-update --disable-tls-checks --url https://$rhost:$port/ --wp-content-dir wp-login.php -U wp-users2.txt -P cewl-list.txt threads 50 | tee wordpress-cewl-brute2.txt
                    if [[ -z $(grep -i "[SUCCESS]" wordpress-cewl-brute2.txt) ]]; then
                        wpscan --no-update --disable-tls-checks --url https://$rhost:$port/ --wp-content-dir wp-login.php -U wp-users2.txt -P john-cool-list2.txt threads 50 | tee wordpress-john-cewl-brute2.txt
                    # if password not found then run it again with fasttrack.txt
                    elif [[ -z $(grep -i "[SUCCESS]" wordpress-cewl-brute2.txt) ]]; then
                        wpscan --no-update --disable-tls-checks --url https://$rhost:$port/ --wp-content-dir wp-login.php -U wp-users2.txt -P /usr/share/wordlists/fasttrack.txt threads 50 | tee wordpress-fasttrack-brute2.txt
                    fi
                fi
            }
            gnome-terminal --zoom=0.9 --geometry 108x68+1908--13 -x bash -c "$(declare -f Cewl2); Cewl2; exec $SHELL" &>/dev/null
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

ftp_scan() {
    grep -w "ftp" nmap/open-ports-$rhost.nmap | cut -d "/" -f 1 >openportsFTP-$rhost.txt
    portfilenameFTP=openportsFTP-$rhost.txt
    # echo $portfilenameSSL
    PortsLinesFTP=$(cat $portfilenameFTP)
    if [[ -s openportsFTP-$rhost.txt ]]; then
        for ftp_port in $PortsLinesFTP; do
            echo -e "${DOPE} Running nmap ftp script scan on port: $ftp_port"
            nmap -sV -Pn -p $ftp_port --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -v -oA nmap/ftp-enum $rhost
        done
    fi
}

# java_rmi_scan() {
#     grep -i "something" nmap/open-ports-$rhost.nmap | cut -d "/" -f 1 >openports3.txt
# }

Intense_Nmap_UDP_Scan() {
    gnome-terminal --zoom=0.9 --geometry 108x68+1908--13 -- bash -c "nmap -sUV -v --reason -T4 --max-retries 3 --max-rtt-timeout 150ms -pU:53,67-69,111,123,135,137-139,161-162,445,500,514,520,631,998,1434,1701,1900,4500,5353,49152,49154 -oA nmap/udp-$rhost $rhost; exec $SHELL" &>/dev/null
    printf "\e[93m################### RUNNING NMAP TOP UDP PORTS ##################################################### \e[0m\n"
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
        smbmap -u null -p "" -H $rhost | tee -a smb-scan-$rhost.txt
        smbmap -u null -p "" -H $rhost -R | tee -a smb-scan-$rhost.txt

        echo -e "\e[92m[+]\e[0m All checks completed Successfully" | tee -a smb-scan-$rhost.txt
    fi
}

getUpHosts
Open_Ports_Scan
Web_Vulns
ftp_scan
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
    if (grep -i "161/udp   open|filtered" nmap/udp-$rhost.nmap); then
        echo -e "${NOTDOPE} SNMP port appears to be filtered"
        return 0
    elif (grep -q "161" udp-scan-$rhost.txt); then
        printf "\e[93m################### RUNNING SNMP-ENUMERATION ##################################################### \e[0m\n"

        echo -e "${DOPE} Running: onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $rhost | tee -a snmpenum-$rhost.log "
        onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $rhost | tee -a snmpenum-$rhost.log
        echo -e "${DOPE} Running: snmp-check -c public -v 1 -d $rhost | tee -a snmpenum-$rhost.log "
        # echo -e "${DOPE} Running: snmp-check -c public -v 2 -d $rhost | tee -a snmpenum-scan.log "
        snmp-check -c public -v 1 -d $rhost | tee -a snmpenum-$rhost.log
    fi
}

FULL_TCP_GOOD_MEASUERE_VULN_SCAN() {
    cwd=$(pwd)
    echo -e "${DOPE} Running Full Nmap TCP port Scan For Good Measuere, just in case we missed one ;)"
    # nmap -vv -Pn -A -O -script-args=unsafe=1 -sS -p 1521 -T4 -oA nmap/full-tcp-scan-$rhost $rhost
    nmap -vv -Pn -A -O -script-args=unsafe=1 -sS -p- -T4 -oA nmap/full-tcp-scan-$rhost $rhost
    echo -e "${YELLOW} #################################################################################################### ${END}"
    echo -e "${TEAL} ########################### Checking Vulnerabilities  ################################################ ${END}"
    echo -e "${YELLOW} #################################################################################################### ${END}"
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
        echo -e "${DOPE} Found Oracle! Running NMAP Enumeration"
        nmap -sV -p 1521 --script oracle-enum-users.nse,oracle-sid-brute.nse,oracle-tns-version.nse -oA nmap/oracle-$rhost $rhost
        echo -e "${DOPE} Found Oracle! Running tnscmd10g Enumeration"
        tnscmd10g ping -h $rhost -p 1521 | tee -a oracle-$rhost.log
        tnscmd10g version -h $rhost -p 1521 | tee -a oracle-$rhost.log
        echo -e "${DOPE} Found Oracle! Running OSCANNER Enumeration"
        oscanner -v -s $rhost -P 1521 | tee -a oracle-$rhost.log
        cd /opt/odat/
        echo -e "${DOPE} Running ODAT Enumeration"
        ./odat.py tnscmd -s $rhost -p 1521 --ping
        ./odat.py tnscmd -s $rhost -p 1521 --version
        ./odat.py tnscmd -s $rhost -p 1521 --status
        ./odat.py sidguesser -s $rhost -p 1521
        ./odat.py passwordguesser -s $rhost -p 1521 -d XE --accounts-file accounts/accounts-multiple.txt
        cd - &>/dev/null
        rm allopenports-$rhost.txt
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
    rm openportsFTP-$rhost.txt
    if [ -d $rhost-report ]; then
        find $cwd/ -maxdepth 1 -name "*$rhost*.*" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'dirsearch*.*' -exec mv {} $cwd/$rhost-report/ \;
        mv live-hosts-ip.txt $rhost-report &>/dev/null
        cp -r eyewitness-report-$rhost $rhost-report &>/dev/null && rm -rf eyewitness-report-$rhost
    else
        mkdir -p $rhost-report
        find $cwd/ -maxdepth 1 -name "*$rhost*.*" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'dirsearch*.*' -exec mv {} $cwd/$rhost-report/ \;
        mv live-hosts-ip.txt $rhost-report &>/dev/null
        cp -r eyewitness-report-$rhost $rhost-report &>/dev/null && rm -rf eyewitness-report-$rhost
    fi

}
Clean_Up

footer() {
    echo -e "${YELLOW} #################################################################################################### ${END}"
    echo -e "${TEAL} ##############################    See You Space Cowboy...  ########################################### ${END}"
    echo -e "${YELLOW} #################################################################################################### ${END}"
}
footer

traperr() {
    echo -e "${NOTDOPE} ERROR: ${BASH_SOURCE[1]} at about ${BASH_LINENO[0]}"
}

set -o errtrace
trap traperr ERR

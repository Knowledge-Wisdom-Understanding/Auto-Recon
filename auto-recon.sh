#!/usr/bin/env bash

banner1() {

    echo -e "\e[1;94m   _____________          ____    ________________                               \e[0m"
    echo -e "\e[1;94m  /___/___      \        /  / |  /___/__          \                   _____      \e[0m"
    echo -e "\e[1;94m      /  /   _   \______/__/  |______|__|_____ *   \_________________/__/  |___  \e[0m"
    echo -e "\e[1;94m   __/__/   /_\   \ |  |  \   __\/  _ \|  |       __/ __ \_/ ___\/  _ \|       | \e[0m"
    echo -e "\e[1;94m  |   |     ___    \|  |  /|  | (  |_| )  |    |   \  ___/\  \__(  |_| )   |   | \e[0m"
    echo -e "\e[1;94m  |___|____/\__\____|____/_|__|\_\____/|__|____|_  /\___  |\___  \____/|___|  /  \e[0m"
    echo -e "\e[1;94m                                             \___\/  \__\/  \___\/      \___\/   \e[0mv4.0"
    echo -e "\e[1;77m\e[45m         AUTO RECON by github.com/Knowledge-Wisdom-Understanding                        \e[0m"
    echo -e ""

}
banner1

DOPE='\e[92m[+]\e[0m'
NOTDOPE='\e[31m[+]\e[0m'
TEAL='\e[96m'
YELLOW='\e[93m'
END='\e[0m'

helpFunction() {
    echo -e "Usage: $0 -t <Target IP>"
    echo " Scan a single host and show subnet hosts "
    echo "Arguments must be specified in the order as follows: "
    echo "options:"
    echo " "
    echo "-h, --help      Show Usage and command arguments"
    echo " "
    echo "-a, --all       Scan The Entire Subnet!"
    echo -e "Usage: $0 -a <Target IP>"
    echo -e "Usage: $0 --all <Target IP>"
    echo " "
    echo "-H, --HTB       Scan Single Target ignore nmap subnet scan"
    echo -e "Usage: $0 -H <Target IP>"
    echo -e "Usage: $0 --HTB <Target IP>"
    if [ -n "$1" ]; then
        exit "$1"
    fi
}

exitFunction() {
    echo "ERROR: Unrecognized argument: $1" >&2
    helpFunction 1
}

# Error Cases
arg=("$@")
if [ -z $1 ]; then
    exitFunction
elif [ "$#" -lt 1 ]; then
    exitFunction
elif [ "$#" -gt 2 ]; then
    exitFunction
else
    rhost=${arg[1]}
fi

if [[ $rhost =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    :
else
    echo -e "\e[31m[+]\e[0m NOT A VALID IP ADDRESS"
    exit 1
fi

# Function Definitions
getUpHosts() {
    # Live Hosts
    baseip=$(echo $rhost | cut -d "." -f1-3)
    cidr_range=$(echo $baseip".0")
    echo -e "${DOPE} Scanning Subnet..."
    nmap -sn $cidr_range/24 -oG /tmp/live-hosts.txt >/dev/null
    cat /tmp/live-hosts.txt | grep "Up" | cut -d " " -f2 >live-hosts-ip.txt
    rm /tmp/live-hosts.txt
    # Live_Host=live-hosts-ip.txt
    echo -e "${DOPE} Live Hosts Recon On $cidr_range/24 Done!"
    cat live-hosts-ip.txt
    # cat $uphostfile
}

Open_Ports_Scan() {
    echo -e "${DOPE} Scanning $rhost"
    create_nmap_dir() {
        if [ -d nmap ]; then
            :
        else
            mkdir -p nmap
        fi
    }
    create_nmap_dir
    # nmap -v -Pn -A -O -p- --max-retries 1 --max-rate 500 --max-scan-delay 20 -T4 -oN nmap/FullTCP $rhost
    #nmap -vv -sT -Pn -p- --disable-arp-ping -T4 -oA nmap/open-ports-$rhost $rhost
    nmap -vv -Pn -sV -T3 --max-retries 1 --max-scan-delay 20 --top-ports 10000 -oA nmap/top-ports-$rhost $rhost
    grep -v "filtered" nmap/top-ports-$rhost.nmap | grep open | cut -d "/" -f 1 >top-open-ports.txt
    grep -v "filtered" nmap/top-ports-$rhost.nmap | grep open >top-open-services.txt
    # grep -v "filtered" nmap/top-ports-$rhost.nmap | grep open | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | head -c-1 >nmap-top-open-ports.txt
}

Enum_Web() {
    grep -v "ssl" top-open-services.txt | grep -w "http" | cut -d "/" -f 1 >httpports-$rhost.txt
    if [[ -s httpports-$rhost.txt ]]; then
        portfilename=httpports-$rhost.txt
        # echo $portfilename
        httpPortsLines=$(cat $portfilename)
        cwd=$(pwd)
        if grep -q "|_http-title: Did not follow redirect" nmap/http-vuln-enum-scan.nmap; then
            redirect_domain=$(grep -i "|_http-title: Did not follow redirect" nmap/http-vuln-enum-scan.nmap | cut -d " " -f 7 | sed -e "s/[^/]*\/\/\([^@]*@\)\?\([^:/]*\).*/\2/")
            echo -e "${DOPE} Target is redirecting to domain: $redirect_domain"
            echo -e "${DOPE} Creating backup of /etc/hosts file in $cwd"
            cat /etc/hosts >etc-hosts-backup
            echo -e "${DOPE} Adding $redirect_domain to /etc/hosts file"
            if grep -q "$rhost" /etc/hosts; then
                :
            else
                sed -i "3i$rhost  $redirect_domain" /etc/hosts
            fi
            unset rhost
            rhost=$redirect_domain
        else
            :
        fi
        for port in $httpPortsLines; do
            wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
            # wordlist2="/usr/share/seclists/Discovery/Web-Content/common.txt"
            echo -e "${DOPE} Running The Following Commands"
            # echo -e "${DOPE} gobuster dir -u http://$rhost:$port -w $wordlist -l -t 50 -x .html,.php,.asp,.aspx,.txt -e -k | tee gobuster-$rhost-$port.txt"
            # echo -e "${DOPE} uniscan -u http://$rhost:$port/ -qweds"
            echo -e "${DOPE} whatweb -v -a 3 --color=never http://$rhost:$port/ | tee whatweb-$rhost:$port.log"
            whatweb -v -a 3 --color=never http://$rhost:$port | tee whatweb-$rhost-$port.log
            echo -e "${DOPE} Checking for Web Application Firewall... wafw00f http://$rhost:$port/"
            wafw00f http://$rhost:$port/ | tee wafw00f-$rhost-$port.log
            echo -e "${DOPE} curl -sSik http://$rhost:$port/robots.txt -m 10 -o robots-$rhost-$port.txt &>/dev/null"
            curl -sSik http://$rhost:$port/robots.txt -m 10 -o robots-$rhost-$port.txt &>/dev/null
            # gobuster dir -u http://$rhost:$port -w $wordlist -l -t 50 -x .html,.php,.asp,.aspx,.txt -e -k -o gobuster-$rhost-$port.txt 2>/dev/null
            echo -e "${DOPE} nikto -h http://$rhost:$port -output niktoscan-$rhost-$port.txt"
            nikto -ask=no -host http://$rhost:$port -output niktoscan-$rhost-$port.txt
            ####################################################################################
            mkdir -p eyewitness-report-"$rhost"-"$port" && cd /opt/EyeWitness
            echo http://"$rhost":"$port" >eyefile.txt
            echo -e "${DOPE} ./EyeWitness.py --threads 5 --ocr --no-prompt --active-scan --all-protocols --web -f eyefile.txt -d $cwd/eyewitness-report-$rhost-$port"
            ./EyeWitness.py --threads 5 --ocr --no-prompt --active-scan --all-protocols --web -f eyefile.txt -d $cwd/eyewitness-report-$rhost-$port
            cd - &>/dev/null
            ##################################################################################
            echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u http://$rhost:$port -w $wordlist -t 50 -e php,asp,aspx -x 403 --plain-text-report dirsearch-$rhost-$port.log"
            python3 /opt/dirsearch/dirsearch.py -u http://$rhost:$port -t 50 -e php,asp,aspx,txt,html,json,cnf,bak -x 403 --plain-text-report dirsearch-$rhost-$port.log
            # uniscan -u http://$rhost:$port -qweds
            echo -e "${DOPE} Further Web enumeration Commands to Run: "
            echo -e "${DOPE} uniscan -u http://$rhost:$port -qweds"
            echo -e "${DOPE} gobuster dir -u http://$rhost:$port -w $wordlist -l -t 50 -x .html,.php,.asp,.aspx,.txt -e -k -o gobuster-$rhost-$port.txt 2>/dev/null"
            wp1=$(grep -i "WordPress" whatweb-$rhost-$port.log 2>/dev/null)
            wp2=$(grep -i "wp-" nmap/http-vuln-enum-scan.nmap)
            if [ "$wp1" -o "$wp2" ]; then
                echo -e "${DOPE} Found WordPress! Running wpscan --no-update --url http://$rhost:$port/ --wp-content-dir wp-content --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive | tee -a wpscan-$rhost-$port.log"
                wpscan --no-update --url http://$rhost:$port/ --wp-content-dir wp-content --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive | tee wpscan-$rhost-$port.log
                # echo -e "${DOPE} 1 sleeping for 5 seconds to wait for wpscan process id :)"
                sleep 2
                if [[ -n $(grep -i "User(s) Identified" wpscan-$rhost-$port.log) ]]; then
                    grep -w -A 100 "User(s)" wpscan-$rhost-$port.log | grep -w "[+]" | cut -d " " -f 2 | head -n -7 >wp-users.txt
                    # create wordlist from web-page with cewl
                    cewl http://$rhost:$port/ -m 3 -w cewl-list.txt
                    sleep 10
                    # add john rules to cewl wordlist
                    echo -e "${DOPE} Adding John Rules to Cewl Wordlist!"
                    john --rules --wordlist=cewl-list.txt --stdout >john-cool-list.txt
                    # brute force again with wpscan
                    sleep 3
                    wpscan --url http://$rhost:$port/ --wp-content-dir wp-login.php -U wp-users.txt -P cewl-list.txt threads 50 | tee wordpress-cewl-brute.txt
                    # echo -e "${DOPE} 2 sleeping for 5 seconds to wait for wpscan process id :)"
                    sleep 5
                    if grep -i "No Valid Passwords Found" wordpress-cewl-brute.txt 2>/dev/null; then
                        if [ -s john-cool-list.txt ]; then
                            wpscan --url http://$rhost:$port/ --wp-content-dir wp-login.php -U wp-users.txt -P john-cool-list.txt threads 50 | tee wordpress-john-cewl-brute.txt
                        else
                            echo "john wordlist is empty :("
                        fi
                    fi
                    sleep 5
                    if grep -i "No Valid Passwords Found" wordpress-john-cewl-brute.txt 2>/dev/null; then
                        wpscan --url http://$rhost:$port/ --wp-content-dir wp-login.php -U wp-users.txt -P /usr/share/wordlists/fasttrack.txt threads 50 | tee wordpress-fasttrack-brute.txt
                    fi
                fi
            elif grep -i "Drupal" whatweb-$rhost-$port.log 2>/dev/null; then
                echo -e "${DOPE} Found Drupal! Running droopescan scan drupal -u http://$rhost -t 32 | tee drupalscan-$rhost-80.log"
                droopescan scan drupal -u http://$rhost:$port/ -t 32 | tee drupalscan-$rhost-$port.log
            elif grep -i "Joomla" whatweb-$rhost-$port.log 2>/dev/null; then
                echo -e "${DOPE} Found Joomla! Running joomscan --url http://$rhost/ -ec | tee joomlascan-$rhost-$port.log"
                joomscan --url http://$rhost:$port/ -ec | tee joomlascan-$rhost-$port.log
            elif grep -i "WebDAV" whatweb-$rhost-$port.log 2>/dev/null; then
                echo -e "${DOPE} Found WebDAV! Running davtest -move -sendbd auto -url http://$rhost:$port/ | tee davtestscan-$rhost-$port.log"
                davtest -move -sendbd auto -url http://$rhost:$port/ | tee davtestscan-$rhost-$port.log
            elif grep -i "magento" whatweb-$rhost-$port.log 2>/dev/null; then
                echo -e "${DOPE} Found Magento! Running /opt/magescan/bin/magescan scan:all http://$rhost/ | tee magescan-$rhost-$port.log"
                cd /opt/magescan
                bin/magescan scan:all http://$rhost:$port/ | tee magento-$rhost-$port.log
                cd - &>/dev/null
                echo -e "${DOPE} Consider crawling site with this wordlist: /usr/share/seclists/Discovery/Web-Content/CMS/sitemap-magento.txt"
            else
                :
            fi
        done
        if [[ -n $redirect_domain ]]; then
            unset rhost
            rhost=${arg[1]}
        else
            :
        fi
    fi
}

Web_Vulns() {
    grep -w "http" top-open-services.txt | cut -d "/" -f 1 >openports-web-$rhost.txt
    if [[ -s openports-web-$rhost.txt ]]; then
        echo -e "${DOPE} Running nmap http vuln-scan on all open http ports!"
        nmap -Pn -sV --script=http-vuln*.nse,http-enum.nse,http-methods.nse,http-title.nse -p $(tr '\n' , <openports-web-$rhost.txt) -oA nmap/http-vuln-enum-scan $rhost
    fi
}

dns_enum() {
    cwd=$(pwd)
    cat sslscan-$rhost-$port.log | grep "Subject" | awk '{print $2}' >domain.txt
    domainName=$(grep "Subject" sslscan-$rhost-$port.log | awk '{print $2}')
    wildcards=('*' '?' '|')
    for wildcard in "${wildcards[@]}"; do
        if [[ $domainName == *"${wildcard}"* ]]; then
            domainNoWildcard=$(echo "${domainName#'*.'}")
            echo -e "${DOPE} Removing wildcard from $domainName .. Setting domain to $domainNoWildcard"
            unset domainName
            domainName="$domainNoWildcard"
        else
            :
        fi
    done
    if [[ -s domain.txt ]] && [[ -n $domainName ]]; then
        set -- $domainName
        echo -e "${DOPE} Target has $domainName"
        echo -e "${DOPE} Creating backup of /etc/hosts file in $cwd"
        cat /etc/hosts >etc-hosts-backup2.txt
        if grep -q "$rhost  $domainName" /etc/hosts; then
            :
        else
            echo -e "${DOPE} Adding $domainName to /etc/hosts file"
            sed -i "3i$rhost  $domainName" /etc/hosts
        fi
        echo -e "${DOPE} Checking for Zone Transfer on $rhost:$port $domainName"
        dig axfr @$rhost $domainName | tee zone-transfer-$rhost-$port-$domainName.txt
        if grep -q "$domainName" zone-transfer-$rhost-$port-$domainName.txt; then
            grep -v ";" zone-transfer-$rhost-$port-$domainName.txt | grep -v -e '^[[:space:]]*$' >filtered-zone-transfer-$rhost-$port-$domainName.txt
            allDomains=$(cat filtered-zone-transfer-$rhost-$port-$domainName.txt | awk '{print $1}')
            domainDot=$(echo $domainName".")
            for dmain in $allDomains; do
                if [[ $domainDot == "$dmain" ]]; then
                    :
                else
                    dmainMinusDot=$(echo "${dmain:0:-1}")
                    sed -i "/$domainName/ s/$/ $dmainMinusDot/" /etc/hosts
                fi
            done
            cat /etc/hosts

        fi
        echo -e "${DOPE} Running DNSRECON!"
        dnsrecon -d $domainName | tee dnsrecon-$rhost-$domainName.log
        echo -e "${DOPE} Running Sublist3r"
        reconDir=$(echo $cwd)
        echo -e "${DOPE} Running python3 sublist3r.py -d $domainName -o $reconDir/subdomains-$rhost-$port-$domainName.log"
        cd /opt/Sublist3r && python3 sublist3r.py -d $domainName -o $reconDir/subdomains-$rhost-$port-$domainName.log
        cd - &>/dev/null
    fi
    if [[ -n "$domainName" ]]; then
        unset rhost
        rhost=$domainName
    else
        :
    fi
}

Enum_Web_SSL() {
    grep -E 'https|ssl/http|ssl/unknown' top-open-services.txt | cut -d "/" -f 1 >openportsSSL-$rhost.txt
    if [[ -s openportsSSL-$rhost.txt ]]; then
        portfilenameSSL=openportsSSL-$rhost.txt
        # echo $portfilenameSSL
        httpPortsLinesSSL=$(cat $portfilenameSSL)
        cwd=$(pwd)
        for port in $httpPortsLinesSSL; do
            set -- $port
            wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt"
            wordlist2="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
            echo -e "${DOPE} Running The Following Commands"
            echo -e "${DOPE} sslscan https://$rhost:$port | tee sslscan-$rhost-$port.log"
            sslscan https://$rhost:$port | tee sslscan-$rhost-$port.log
            dns_enum
            echo -e "${DOPE} whatweb -v -a 3 --color=never https://$rhost:$port/ | tee whatweb-$rhost-$port.log"
            whatweb -v -a 3 --color=never https://$rhost:$port | tee whatweb-ssl-$rhost-$port.log
            echo -e "${DOPE} Checking for Web Application Firewall... wafw00f https://$rhost:$port/"
            wafw00f https://$rhost:$port/ | tee wafw00f-$rhost-$port.log
            echo -e "${DOPE} curl -sSik https://$rhost:$port/robots.txt -m 10 -o robots-$rhost-$port.txt"
            curl -sSik https://$rhost:$port/robots.txt -m 10 -o robots-$rhost-$port.txt &>/dev/null
            ############## EYE-WITNESS ##########################################
            mkdir -p eyewitness-report-"$rhost"-"$port" && cd /opt/EyeWitness
            echo https://"$rhost":"$port" >eyefile.txt
            echo -e "${DOPE} ./EyeWitness.py --threads 5 --ocr --no-prompt --active-scan --all-protocols --web -f eyefile.txt -d $cwd/eyewitness-report-$rhost-$port"
            ./EyeWitness.py --threads 5 --ocr --no-prompt --active-scan --all-protocols --web -f eyefile.txt -d $cwd/eyewitness-report-$rhost-$port
            cd - &>/dev/null
            echo -e "${DOPE} gobuster dir -u https://$rhost:$port -w $wordlist -l -t 50 -x .html,.php,.asp,.aspx,.txt -e -k -o gobuster-$rhost-$port.txt"
            gobuster dir -u https://$rhost:$port -w $wordlist -l -t 50 -x .html,.php,.asp,.aspx,.txt -e -k -o gobuster-$rhost-$port.txt
            echo -e "${DOPE} nikto -h https://$rhost:$port -output niktoscan-$rhost-$port.txt"
            nikto -ask=no -host https://$rhost:$port -ssl -output niktoscan-$rhost-$port.txt
            # uniscan -u https://$rhost:$port -qweds
            echo -e "${DOPE} Further Web enumeration Commands to Run: "
            echo -e "${DOPE} uniscan -u https://$rhost:$port -qweds"
            echo -e "${DOPE} gobuster dir -u https://$rhost:$port -w $wordlist2 -l -t 50 -x .html,.php,.asp,.aspx,.txt -e -k | tee gobuster-$rhost-$port.txt"

            if [ $(grep -i "WordPress" whatweb-ssl-$rhost-$port.log 2>/dev/null) ]; then
                echo -e "${DOPE} Found WordPress! Running wpscan --no-update --disable-tls-checks --url https://$rhost:$port/ --wp-content-dir wp-content --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive | tee wpscan2-$rhost-$port.log"
                wpscan --no-update --disable-tls-checks --url https://$rhost:$port/ --wp-content-dir wp-content --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive | tee wpscan2-$rhost-$port.log
                sleep 5
                if [[ -n $(grep -i "User(s) Identified" wpscan2-$rhost-$port.log) ]]; then
                    grep -w -A 100 "User(s)" wpscan2-$rhost-$port.log | grep -w "[+]" | cut -d " " -f 2 | head -n -7 >wp-users2.txt
                    # create wordlist from web-page with cewl
                    cewl https://$rhost:$port/ -m 3 -w cewl-list2.txt
                    sleep 10
                    # add john rules to cewl wordlist
                    echo -e "${DOPE} Adding John Rules to Cewl Wordlist!"
                    john --rules --wordlist=cewl-list2.txt --stdout >john-cool-list2.txt
                    sleep 3
                    # brute force again with wpscan
                    wpscan --no-update --disable-tls-checks --url https://$rhost:$port/ --wp-content-dir wp-login.php -U wp-users2.txt -P cewl-list.txt threads 50 | tee wordpress-cewl-brute2.txt
                    sleep 5
                    if grep -i "No Valid Passwords Found" wordpress-cewl-brute2.txt; then
                        if [ -s john-cool-list2.txt ]; then
                            wpscan --no-update --disable-tls-checks --url https://$rhost:$port/ --wp-content-dir wp-login.php -U wp-users2.txt -P john-cool-list2.txt threads 50 | tee wordpress-john-cewl-brute2.txt
                        else
                            echo "John wordlist is empty :("
                        fi
                        # if password not found then run it again with fasttrack.txt
                        sleep 5
                        if grep -i "No Valid Passwords Found" wordpress-john-cewl-brute2.txt; then
                            wpscan --no-update --disable-tls-checks --url https://$rhost:$port/ --wp-content-dir wp-login.php -U wp-users2.txt -P /usr/share/wordlists/fasttrack.txt threads 50 | tee wordpress-fasttrack-brute2.txt
                        fi
                    fi
                fi
            elif grep -i "Drupal" whatweb-ssl-$rhost-$port.log 2>/dev/null; then
                echo -e "${DOPE} Found Drupal! Running droopescan scan drupal -u https://$rhost -t 32 | tee drupalscan-$rhost-$port.log"
                droopescan scan drupal -u https://$rhost:$port/ -t 32 | tee -a drupalscan.log
            elif grep -i "Joomla" whatweb-ssl-$rhost-$port.log 2>/dev/null; then
                echo -e "${DOPE} Found Joomla! Running joomscan --url https://$rhost/ -ec | tee joomlascan-$rhost-$port.log"
                joomscan --url https://$rhost:$port/ -ec | tee -a joomlascan-$rhost-$port.log
            elif grep -i "WebDAV" whatweb-ssl-$rhost-$port.log 2>/dev/null; then
                echo -e "${DOPE} Found WebDAV! Running davtest -move -sendbd auto -url https://$rhost:$port/ | tee davtestscan-$rhost-$port.log"
                davtest -move -sendbd auto -url https://$rhost:$port/ | tee -a davtestscan-$rhost-$port.log
            else
                :
            fi
        done
        if [[ -n $redirect_domain ]]; then
            unset rhost
            rhost=${arg[1]}
        elif [[ -n $domainName ]]; then
            unset rhost
            rhost=${arg[1]}
        else
            :
        fi
    fi
}

ftp_scan() {
    grep -w "ftp" top-open-services.txt | cut -d "/" -f 1 >openportsFTP-$rhost.txt
    portfilenameFTP=openportsFTP-$rhost.txt
    # echo $portfilenameSSL
    PortsLinesFTP=$(cat $portfilenameFTP)
    if [[ -s openportsFTP-$rhost.txt ]]; then
        for ftp_port in $PortsLinesFTP; do
            echo -e "${DOPE} Running nmap ftp script scan on port: $ftp_port"
            nmap -sV -Pn -p $ftp_port --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,ftp-syst -v -oA nmap/ftp-enum $rhost
        done
    fi
}

cups_enum() {
    if [[ $(grep -w "ipp" top-open-services.txt) ]] || [[ $(grep -w "631" top-open-ports.txt) ]]; then
        echo -e "${DOPE} Found ipp cups Running nmap command:"
        echo -e "${DOPE} nmap -v -sV -Pn --script=cups-info.nse,cups-queue-info.nse -p 631 -oA nmap/cups-enum-$rhost $rhost"
        nmap -v -sV -Pn --script=cups-info.nse,cups-queue-info.nse -p 631 -oA nmap/cups-enum-$rhost $rhost
    fi
}

nfs_enum() {
    grep -w "rpcbind" top-open-services.txt | cut -d "/" -f 1 >openports-nfs.txt
    if grep -q "111" openports-nfs.txt; then
        echo -e "${DOPE} nmap -v -sV -Pn -p 111 --script=nfs-ls.nse,nfs-statfs.nse,nfs-showmount.nse -oA nmap/nfs-$rhost $rhost"
        nmap -v -sV -Pn -p 111 --script=nfs-ls.nse,nfs-statfs.nse,nfs-showmount.nse -oA nmap/nfs-$rhost $rhost
    fi
}

java_rmi_scan() {
    if [[ $(grep -w "rmiregistry" top-open-services.txt) ]] || [[ $(grep -w "1099" top-open-ports.txt) ]]; then
        echo -e "${DOPE} Found Java-Rmi-Registry! Running nmap command:"
        echo -e "${DOPE} nmap -v -sV -Pn --script=rmi-vuln-classloader.nse -p 1099 -oA nmap/java-rmi-$rhost $rhost"
        nmap -v -sV -Pn --script=rmi-vuln-classloader.nse -p 1099 -oA nmap/java-rmi-$rhost $rhost
    fi
    if [[ $(grep -w "java-rmi" top-open-services.txt) ]] || [[ $(grep -w "1100" top-open-ports.txt) ]]; then
        echo -e "${DOPE} Found Java-RMI! Running nmap command:"
        echo -e "${DOPE} nmap -v -sV -Pn --script=rmi-vuln-classloader.nse -p 1099 -oA nmap/java-rmi-$rhost $rhost"
        nmap -v -sV -Pn --script=rmi-dumpregistry.nse -p 1099 -oA nmap/java-rmi-dump-$rhost $rhost
    fi

}

Intense_Nmap_UDP_Scan() {
    printf "\e[93m################### RUNNING NMAP TOP UDP PORTS ##################################################### \e[0m\n"
    nmap -sUV -v --reason -T4 --max-retries 3 --max-rtt-timeout 150ms -pU:53,67-69,111,123,135,137-139,161-162,445,500,514,520,631,998,1434,1701,1900,4500,5353,49152,49154 -oA nmap/udp-$rhost $rhost
}

Enum_SMB() {
    if [[ $(grep -i "netbios-ssn" top-open-services.txt) ]] || [[ $(grep -i "microsoft-ds" top-open-services.txt) ]]; then
        echo -e "${DOPE} Running SMBCLIENT, Checking shares" | tee -a smb-scan-$rhost.log
        smbclient -L //$rhost -U "guest"% | tee -a smb-scan-$rhost.log

        echo -e "${DOPE} Running ENUM4LINUX" | tee -a smb-scan-$rhost.log
        enum4linux -av $rhost | tee -a smb-scan-$rhost.log

        echo -e "${DOPE} Running NMBLOOKUP" | tee -a smb-scan-$rhost.log
        nmblookup -A $rhost | tee -a smb-scan-$rhost.log

        echo -e "${DOPE} Running All SMB nmap Vuln / Enum checks" | tee -a smb-scan-$rhost.log
        nmap -vv -sV -Pn -p139,445 --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse --script-args=unsafe=1 -oA nmap/smbvulns-$rhost $rhost | tee -a smb-scan-$rhost.log

        echo -e "${DOPE} Running NBTSCAN" | tee -a smb-scan-$rhost.log
        nbtscan -rvh $rhost | tee -a smb-scan-$rhost.log

        echo -e "${DOPE} Running smbmap" | tee -a smb-scan-$rhost.log
        smbmap -H $rhost | tee -a smb-scan-$rhost.log
        smbmap -u null -p "" -H $rhost | tee -a smb-scan-$rhost.log
        smbmap -u null -p "" -H $rhost -R | tee -a smb-scan-$rhost.log

        echo -e "${DOPE} All checks completed Successfully" | tee -a smb-scan-$rhost.log
    fi
}

Enum_SNMP() {
    cwd=$(pwd)
    # echo $cwd
    cd $cwd
    if grep -q "199" top-open-ports.txt; then
        printf "\e[93m################### RUNNING SNMP-ENUMERATION ##################################################### \e[0m\n"

        echo -e "${DOPE} Running: onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $rhost | tee -a snmpenum-$rhost.log "
        onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $rhost | tee -a snmpenum-$rhost.log
        echo -e "${DOPE} Running: snmp-check -c public -v 1 -d $rhost | tee -a snmpenum-$rhost.log "
        # echo -e "${DOPE} Running: snmp-check -c public -v 2 -d $rhost | tee -a snmpenum-scan.log "
        snmp-check -c public -v 1 -d $rhost | tee -a snmpenum-$rhost.log
    fi
    if ! grep -q "199" top-open-ports.txt; then
        npid
        grep -v "filtered" nmap/udp-$rhost.nmap | grep "open" | cut -d "/" -f 1 >udp-scan-$rhost.txt
        if grep -q "161" udp-scan-$rhost.txt; then
            printf "\e[93m################### RUNNING SNMP-ENUMERATION ##################################################### \e[0m\n"

            echo -e "${DOPE} Running: onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $rhost | tee -a snmpenum-$rhost.log "
            onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $rhost | tee -a snmpenum-$rhost.log
            echo -e "${DOPE} Running: snmp-check -c public -v 1 -d $rhost | tee -a snmpenum-$rhost.log "
            # echo -e "${DOPE} Running: snmp-check -c public -v 2 -d $rhost | tee -a snmpenum-scan.log "
            snmp-check -c public -v 1 -d $rhost | tee -a snmpenum-$rhost.log
        fi
    fi

}

FULL_TCP_GOOD_MEASUERE_VULN_SCAN() {
    cwd=$(pwd)
    echo -e "${DOPE} Running Full Nmap TCP port Scan For Good Measuere, just in case we missed one ;)"
    nmap -vv -Pn -sC -sV -p- -T4 -oA nmap/full-tcp-scan-$rhost $rhost
    echo -e "${YELLOW}#################################################################################################### ${END}"
    echo -e "${TEAL}########################### Checking Vulnerabilities  ############################################## ${END}"
    echo -e "${YELLOW}#################################################################################################### ${END}"
    cd /opt/ReconScan && python3 vulnscan.py $cwd/nmap/full-tcp-scan-$rhost.xml
    cd - &>/dev/null
}

vulnscan() {
    grep -v "filtered" nmap/full-tcp-scan-$rhost.nmap | grep "open" | grep -i "/tcp" | cut -d "/" -f 1 >allopenports2-$rhost.txt
    # grep -i "/tcp" nmap/full-tcp-scan-$rhost.nmap | grep -w "ssh" | cut -d "/" -f 1 >sshports-$rhost.txt
    if [[ -s allopenports2-$rhost.txt ]]; then
        echo -e "${DOPE} Running nmap VulnScan!"
        nmap -v -sV -Pn --script nmap-vulners,vulscan --script-args vulscandb=scipvuldb.csv -p $(tr '\n' , <allopenports2-$rhost.txt) -oA nmap/vulnscan-$rhost $rhost

    fi
}

Enum_Oracle() {
    cwd=$(pwd)
    cd $cwd
    # grep -w "1521/tcp open" nmap/full-tcp-scan-$rhost.nmap | cut -d "/" -f 1 >allopenports-$rhost.txt
    if grep -q "1521" allopenports2-$rhost.txt; then
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
        rm allopenports2-$rhost.txt
    else
        rm allopenports2-$rhost.txt
    fi

}

Clean_Up() {
    sleep 3
    cwd=$(pwd)
    cd $cwd
    rm udp-scan-$rhost.txt 2>/dev/null
    rm openports-nfs.txt 2>/dev/null
    rm openportsFTP-$rhost.txt 2>/dev/null
    rm openportsSSL-$rhost.txt 2>/dev/null
    rm openports-web-$rhost.txt 2>/dev/null
    rm httpports-$rhost.txt 2>/dev/null
    # rm allopenports2-$rhost.txt
    mkdir -p wordlists &>/dev/null
    find $cwd/ -maxdepth 1 -name '*-list.*' -exec mv {} $cwd/wordlists \;
    if [ -d $rhost-report ]; then
        find $cwd/ -maxdepth 1 -name "*$rhost*.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "wafw00f*.log" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'dirsearch*.*' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'whatweb*.log' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'snmpenum*.log' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'wpscan*.log' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'wordpress*.log' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'wp-users.txt' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'top-open-ports.txt' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'top-open-services.txt' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "sslscan-$rhost-$port.log" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "domain.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "etc-hosts-backup2.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "smb-scan-$rhost.log" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "*$rhost*.log" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "gobuster*.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "niktoscan*.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "robots*.txt" -exec mv {} $cwd/$rhost-report/ \;
    else
        mkdir -p $rhost-report
        find $cwd/ -maxdepth 1 -name "*$rhost*.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "wafw00f*.log" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'dirsearch*.*' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'whatweb*.log' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'snmpenum*.log' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'wpscan*.*' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'wordpress*.*' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name '*-list.*' -exec mv {} $cwd/wordlists \;
        find $cwd/ -maxdepth 1 -name 'wp-users.txt' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'top-open-ports.txt' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'top-open-services.txt' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "sslscan-$rhost-$port.log" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "domain.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "etc-hosts-backup2.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "smb-scan-$rhost.log" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "*$rhost*.log" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "gobuster*.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "niktoscan*.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "robots*.txt" -exec mv {} $cwd/$rhost-report/ \;
    fi

}

Remaining_Hosts_All_Scans() {
    echo -e "$rhost is the current RHOST!"
    grep -v $rhost live-hosts-ip.txt >remaining-hosts-to-scan.txt
    ip addr | grep -w inet | grep -v 127 | awk {'print $2'} | cut -d "/" -f 1 >myips.txt
    myipsFile=myips.txt
    gmyips=$(cat "$myipsFile")
    grep -v "$gmyips" remaining-hosts-to-scan.txt >remaininghosts.txt
    remainingHostsFileName=remaininghosts.txt
    hostsRemainingList=$(cat $remainingHostsFileName)
    baseip2=$(echo $rhost | cut -d "." -f1-3)
    cidr_range1=$(echo $baseip2".1")
    cidr_range2=$(echo $baseip2".2")
    cidr_range3=$(echo $baseip2".254")
    for target in $hostsRemainingList; do
        if [[ $target == "$cidr_range1" ]] || [[ $target == "$cidr_range2" ]] || [[ $target == "$cidr_range3" ]]; then
            :
        else
            unset rhost
            set -- "$target" "${@:3}"
            rhost=$target
            Open_Ports_Scan
            Web_Vulns
            Enum_Web
            unset rhost
            set -- "$target" "${@:3}"
            rhost=$target
            Enum_Web_SSL
            unset rhost
            set -- "$target" "${@:3}"
            rhost=$target
            ftp_scan
            nfs_enum
            Intense_Nmap_UDP_Scan
            Enum_SMB
            cups_enum
            java_rmi_scan
            FULL_TCP_GOOD_MEASUERE_VULN_SCAN
            Enum_SNMP
            vulnscan
            Enum_Oracle
            Clean_Up
        fi

    done
    rm myips.txt
    rm remaining-hosts-to-scan.txt
    rm remaininghosts.txt
}

you_dont_have_to_drive_no_fancy_car_just_for_you_to_be_a_shining_star() {
    cat <<"EOF"
    
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
|___|,  \\  cyou    }|{     ,            .  ,,   __̴ı̴̴̡̡̡ ̡͌l̡̡̡ ̡͌l̡*̡̡  .                ,
EOF
}
# you_dont_have_to_drive_no_fancy_car_just_for_you_to_be_a_shining_star
echo ""

# Pre-process options to:
# - expand -xyz into -x -y -z
# - expand --longopt=argument into --longopt argument
ARGV=()
END_OF_OPT=
while [[ $# -gt 0 ]]; do
    argument="$1"
    shift
    case "${END_OF_OPT}${argument}" in
    --)
        ARGV+=("$argument")
        END_OF_OPT=1
        ;;
    --*=*) ARGV+=("${argument%%=*}" "${argument#*=}") ;;
    --*)
        ARGV+=("$argument")
        END_OF_OPT=1
        ;;
    -*) for i in $(seq 2 ${#argument}); do ARGV+=("-${argument:i-1:1}"); done ;;
    *) ARGV+=("$argument") ;;
    esac
done

# Apply pre-processed options
set -- "${ARGV[@]}"

# Parse options
END_OF_OPT=
POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "${END_OF_OPT}${1}" in
    -h | --help)
        helpFunction
        0
        ;;
    -t | --target)
        shift
        rhost="$1"
        getUpHosts 0
        Open_Ports_Scan 0
        Web_Vulns 0
        Enum_Web 0
        Enum_Web_SSL 0
        ftp_scan 0
        nfs_enum 0
        Intense_Nmap_UDP_Scan 0
        Enum_SMB 0
        cups_enum 0
        java_rmi_scan 0
        FULL_TCP_GOOD_MEASUERE_VULN_SCAN 0
        Enum_SNMP 0
        vulnscan 0
        Enum_Oracle 0
        Clean_Up 0
        you_dont_have_to_drive_no_fancy_car_just_for_you_to_be_a_shining_star 0
        ;;
    -a | --all)
        shift
        rhost="$1"
        getUpHosts 0
        Open_Ports_Scan 0
        Web_Vulns 0
        Enum_Web 0
        Enum_Web_SSL 0
        ftp_scan 0
        nfs_enum 0
        Intense_Nmap_UDP_Scan 0
        Enum_SMB 0
        cups_enum 0
        java_rmi_scan 0
        FULL_TCP_GOOD_MEASUERE_VULN_SCAN 0
        Enum_SNMP 0
        vulnscan 0
        Enum_Oracle 0
        Clean_Up 0
        Remaining_Hosts_All_Scans 0
        you_dont_have_to_drive_no_fancy_car_just_for_you_to_be_a_shining_star 0
        ;;
    -H | --HTB)
        shift
        rhost="$1"
        Open_Ports_Scan 0
        Web_Vulns 0
        Enum_Web 0
        Enum_Web_SSL 0
        ftp_scan 0
        nfs_enum 0
        Intense_Nmap_UDP_Scan 0
        Enum_SMB 0
        cups_enum 0
        java_rmi_scan 0
        FULL_TCP_GOOD_MEASUERE_VULN_SCAN 0
        Enum_SNMP 0
        vulnscan 0
        Enum_Oracle 0
        Clean_Up 0
        you_dont_have_to_drive_no_fancy_car_just_for_you_to_be_a_shining_star 0
        ;;
    -*)
        exitFunction "$@"
        shift 1
        ;;
    *)
        exitFunction "$@"
        shift 1
        ;;
    esac
    shift
done

set -- "${POSITIONAL[@]}"

if [[ "$#" -gt 2 ]]; then
    exitFunction
fi

traperr() {
    echo -e "${NOTDOPE} ERROR: ${BASH_SOURCE[1]} at about ${BASH_LINENO[0]}"
}

set -o errtrace
trap traperr ERR

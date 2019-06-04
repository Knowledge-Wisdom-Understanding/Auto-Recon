#!/bin/bash

if [ -z $1 ]; then echo "Usage: ./all_smb.sh RHOST" && exit; else rhost=$1; fi
echo -e "\e[92m[+]\e[0m Running SMBCLIENT, Checking shares" | tee -a smb-scan-$rhost.txt
smbclient -L //$rhost -U "guest"% | tee -a smb-scan-$rhost.txt

echo -e "\e[92m[+]\e[0m Running ENUM4LINUX" | tee -a smb-scan-$rhost.txt
enum4linux -av $rhost | tee -a smb-scan-$rhost.txt

echo -e "\e[92m[+]\e[0m Running NMBLOOKUP" | tee -a smb-scan-$rhost.txt
nmblookup -A $rhost | tee -a smb-scan-$rhost.txt

# create an nmap directory if one doesn't exist
create_nmap_dir(){
    if [ -d nmap ]; then
        echo "nmap directory exists"
    else
        echo "creating nmap directory"
        mkdir -p nmap
    fi
}
create_nmap_dir

echo -e "\e[92m[+]\e[0m Running All SMB nmap Vuln / Enum checks" | tee -a smb-scan-$rhost.txt
nmap -vv -sV -Pn -p139,445 --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse --script-args=unsafe=1 -oA nmap/smbvulns-$rhost $rhost | tee -a smb-scan-$rhost.txt

echo -e "\e[92m[+]\e[0m Running NBTSCAN" | tee -a smb-scan-$rhost.txt
nbtscan -rvh $rhost | tee -a smb-scan-$rhost.txt

echo -e "\e[92m[+]\e[0m Running smbmap" | tee -a smb-scan-$rhost.txt
smbmap -H $rhost | tee -a smb-scan-$rhost.txt

echo -e "\e[92m[+]\e[0m All checks completed Successfully" | tee -a smb-scan-$rhost.txt

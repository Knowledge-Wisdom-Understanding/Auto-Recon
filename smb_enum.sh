#!/bin/bash

if [ -z $1 ]; then echo "Usage: ./all_smb.sh RHOST" && exit; else rhost=$1; fi
echo -e "\e[92m[+]\e[0m Running SMBCLIENT, Checking shares" | tee -a smbvuln-scan.txt
smbclient -L //$rhost -U "anonymous"%"anonymous" | tee -a smbvuln-scan.txt

echo -e "\e[92m[+]\e[0m Running ENUM4LINUX" | tee -a smbvuln-scan.txt
enum4linux -av $rhost | tee -a smbvuln-scan.txt

echo -e "\e[92m[+]\e[0m Running NMBLOOKUP" | tee -a smbvuln-scan.txt
nmblookup -A $rhost | tee -a smbvuln-scan.txt

echo -e "\e[92m[+]\e[0m Running All SMB nmap Vuln / Enum checks" | tee -a smbvuln-scan.txt
nmap -vv -sV -Pn -p139,445 --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse --script-args=unsafe=1 -oA smbvulns $rhost | tee -a smbvuln-scan.txt

echo -e "\e[92m[+]\e[0m Running NBTSCAN" | tee -a smbvuln-scan.txt
nbtscan -rvh $rhost | tee -a smbvuln-scan.txt

echo -e "\e[92m[+]\e[0m Running smbmap" | tee -a smbvuln-scan.txt
smbmap -H $rhost | tee -a smbvuln-scan.txt

echo -e "\e[92m[+]\e[0m All checks completed Successfully" | tee -a smbvuln-scan.txt

#!/bin/bash

NICE='\e[92m[+]\e[0m'
NOTNICE='\e[91m[+]\e[0m'

smb_vuln_scan() {

    echo -e "${NICE} Running SMBCLIENT, Checking shares" | tee -a smb-scan-$host.txt
    smbclient -L //$host -U "guest"% | tee -a smb-scan-$host.txt

    echo -e "${NICE} Running ENUM4LINUX" | tee -a smb-scan-$host.txt
    enum4linux -av $host | tee -a smb-scan-$host.txt

    echo -e "${NICE} Running NMBLOOKUP" | tee -a smb-scan-$host.txt
    nmblookup -A $host | tee -a smb-scan-$host.txt

    # create an nmap directory if one doesn't exist
    create_nmap_dir() {
        if [ -d nmap ]; then
            :
        else
            echo "creating nmap directory"
            mkdir -p nmap
        fi
    }
    create_nmap_dir

    echo -e "${NICE} Running All SMB nmap Vuln / Enum checks" | tee -a smb-scan-$host.txt
    nmap -vv -sV -Pn -p139,445 --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse --script-args=unsafe=1 -oA nmap/smbvulns-$host $host | tee -a smb-scan-$host.txt

    echo -e "${NICE} Running NBTSCAN" | tee -a smb-scan-$host.txt
    nbtscan -rvh $host | tee -a smb-scan-$host.txt

    echo -e "${NICE} Running smbmap" | tee -a smb-scan-$host.txt
    smbmap -H $host | tee -a smb-scan-$host.txt

    echo -e "${NICE} All checks completed Successfully" | tee -a smb-scan-$host.txt
}

if [ -z $1 ]; then
    echo -e "${NOTNICE} Must specify a host file. EX: ./$0 smb-hosts.txt" && exit
else
    smb_host_file=$1
    smb_hosts=$(cat $1)
fi

if [ -n "$smb_hosts" ]; then
    for host in $smb_hosts; do
        smb_vuln_scan
    done
    cwd=$(pwd)
    mkdir -p SMB-SCAN-REPORT
    find $cwd/ -maxdepth 1 -name "*$host*.*" -exec mv {} $cwd/SMB-SCAN-REPORT/ \;
fi
echo -e "${NICE} All SMB scans finished!"

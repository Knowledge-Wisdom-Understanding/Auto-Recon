# AUTO-RECON

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/e41306320cc3461497c787e13b41df21)](https://app.codacy.com/app/Knowledge-Wisdom-Understanding/Auto-Recon?utm_source=github.com&utm_medium=referral&utm_content=Knowledge-Wisdom-Understanding/Auto-Recon&utm_campaign=Badge_Grade_Settings)

## Quickly Enumerate a Target in Kali Linux

<img src="https://github.com/Knowledge-Wisdom-Understanding/Auto-Recon/blob/master/recon.gif" />

### INSTALLATION
```
cd /opt
git clone https://github.com/Knowledge-Wisdom-Understanding/Auto-Recon.git
cd Auto-Recon
chmod +x setup.sh
./setup.sh
```

### Usage:
```
./auto-recon.sh -h [--help]
./auto-recon.sh -t [--target] RHOST ...Scan single target IP
./auto-recon.sh -a [--all] RHOST ...check up hosts in subnet then enumerate ALL UP hosts
./auto-recon.sh -H [--HTB] RHOST ...enumerate single target + thorough hack the box dns checks
./auto-recon.sh -f [--file] RHOST ...enumerate all target IP addresses in a file
```
If you notice a bug or have a feature request. Please submit an issue. Thanks!
Gobuster is now using version 3 syntax, upgrade to the latest version!

### Recon Script
#!/bin/bash

domain=$1
wordlist=https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS --Download and add path here..
ressolvers="add txt file of all ip that u want to resolve"

domain_enum(){

mkdir -p $domain $domain/sources $domain/Recon/ 
#Passive Enumeration
subdinder -d domain=$1 -o $domain/sources/subfinder.txt
assestfinder -subs-only domain=$1 | tee $domain/sources/hackerone.txt
amass enum -passive domain=$1 -o $domain/sources/passive.txt

#Active Enumeration using brutefoorce
shuffledns -d $domain -w $wordlist -r $resolvers -o $domain/sources/suffledns.txt

cat $domain/sources/*.txt > $domain/sources/all.txt

}
domain_enum


resolving_domains(){

suffledns -d $domain  -list $domain/sources/all.txt -o $domain/domain.txt -r $ressolvers


}
resolving_domains


http_prob(){
cat $domain/domain.txt | httpx -thread 50 -o $domain/Recon/httpx.txt
}
http_prob

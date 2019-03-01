# AUTO-RECON
## Easy to use Recon script for Enumeration in Kali Linux

recon.sh requires dirsearch to be installed in the /opt folder.
### To install Dependencies, simply run this command in your /opt folder:
``` 
cd /opt
git clone https://github.com/maurosoria/dirsearch.git
```
Also, if you don't already have it installed, you can use gobuster instead of dirsearch.
```
apt-get install gobuster
```

This script is very easy to customize to your liking.
For instance: If you don't want to run a full TCP nmap scan, delete -p- from line 44 etc...

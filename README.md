# AUTO-RECON
## Easy to use script for Information-Gathering in Kali Linux

![alt text](https://github.com/Knowledge-Wisdom-Understanding/Auto-Recon/blob/master/auto-recon.PNG)


recon.sh requires dirsearch to be installed in the /opt folder.
### To install Dependencies, simply run these commands in your /opt folder:
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

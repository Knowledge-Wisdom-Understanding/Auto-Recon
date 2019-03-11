# AUTO-RECON
## Easy to use script to quickly scan a Target in Kali Linux

![alt text](https://github.com/Knowledge-Wisdom-Understanding/Auto-Recon/blob/master/auto-recon.PNG)


### INSTALLATION
```
cd /opt
git clone https://github.com/Knowledge-Wisdom-Understanding/Auto-Recon.git
cd Auto-Recon
chmod +x recon.sh
```
recon.sh requires the following tools to be cloned and installed in the /opt folder.
### To install Dependencies, run these commands in your /opt folder:
``` 
cd /opt
git clone https://github.com/maurosoria/dirsearch.git
```

```
cd /opt
git clone https://github.com/DanMcInerney/pentest-machine.git
./setup.sh
```
```
cd /opt
git clone https://github.com/DanMcInerney/net-creds.git
pip install -r requirements.txt
```

TODO: create setup.sh script to install all tools and dependencies.

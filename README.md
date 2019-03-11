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
### To manually install Dependencies, run these commands in your /opt folder:
``` 
cd /opt
git clone https://github.com/maurosoria/dirsearch.git
```

```
cd /opt
git clone https://github.com/DanMcInerney/pentest-machine.git && cd pentest-machine
./setup.sh
```
```
cd /opt
git clone https://github.com/DanMcInerney/net-creds.git
pip install -r requirements.txt
```

Or just run the setup.sh install script in the auto-recon folder
```
./setup.sh
```

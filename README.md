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

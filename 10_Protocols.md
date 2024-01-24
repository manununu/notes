# SMTP
## Enumerate users
```
nc -nv 10.10.10.10 25
VRFY root
252 2.0.0 root
VRFY idontexist
550 5.1.1 <idontexist>: Recipient address rejected: User unknown in local 
```

## Extract Mails from Server using Telnet (Authenticated, IMAP)
```
telnet <IP or Hostname> 143
a1 LOGIN <username> <password>
a2 LIST '' '\*'
a3 EXAMINE INBOX
a4 FETCH 1 BODY[]
a5 FETCH 2 BODY[]
```

# DNS
## Basic Examples
```
host domain.com
host -t mx domain.com
host -t txt domain.com
host -t ns domain.com
host 10.10.10.10
```

## DNS Recon
``` bash
dnsrecon -r 127.0.0.1/24 -n <IP of DNS Server>
dnsrecon -d domain -t axfr # zone transfer
dnsrecon -d domain -D ~/list.txt -t brt # bruteforce subdomains

# check with nmap what IP listen on port 53, then try one after another and specify it with -n
dnsrecon -r 192.168.175.0/24 -n 192.168.175.149
```

**query dns server with nslookup:**
```
nslookup
# set dns server
> server 10.10.10.13                                                                                                                                                     
Default server: 10.10.10.13
Address: 10.10.10.13#53               
# lookup ip
> 10.10.10.13                        
13.10.10.10.in-addr.arpa        name = ns1.cronos.htb
```

## DNSenum
```
dnsenum zonetransfer.me
```

## Zone transfer
**Dig:**
```
[16:18:50]-[kali@kali]-[~/hackthebox/boxes/cronos] » dig axfr cronos.htb @ns1.cronos.htb                                                                            10 ↵

; <<>> DiG 9.16.6-Debian <<>> axfr cronos.htb @ns1.cronos.htb
;; global options: +cmd
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
cronos.htb.             604800  IN      NS      ns1.cronos.htb.
cronos.htb.             604800  IN      A       10.10.10.13
admin.cronos.htb.       604800  IN      A       10.10.10.13
ns1.cronos.htb.         604800  IN      A       10.10.10.13
www.cronos.htb.         604800  IN      A       10.10.10.13
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
;; Query time: 95 msec
;; SERVER: 10.10.10.13#53(10.10.10.13)
;; WHEN: Wed Dec 23 16:19:03 CET 2020
;; XFR size: 7 records (messages 1, bytes 203)

```
**Host:**
```
host -l domain.com ns1.domain.com
# always use -a flag due to the fact that sometimes the TXT record is not shown otherwise
host -l -a domain.com <ip ns>

```

## DNSRecon
```
dnsrecon -d domain -t axfr 
```

# SSH
## SSH issues
no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
```
-oKexAlgorithms=+diffie-hellman-group1-sha1
```
no matching host key type found. Their offer: ssh-rsa,ssh-dss
```
oHostKeyAlgorithms=+ssh-dss
```

## Crack Passphrase for given SSH-Key
* [John The Ripper](https://github.com/openwall/john)
* [ssh2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/ssh2john.py)
```
python3 ssh2john.py id_rsa > id_rsa.hash
john id_rsa.hash --wordlist=<wordlist>
john --rules --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT
```
# SMB
## /etc/samba/smb.conf
Add the following to the global section 
```
client min protocol = CORE
client max protocol = SMB3
```

## List shares
```
smbclient -L \\10.10.10.3\
smbmap -H 10.10.10.3
```

## Connect to share
```
smbclient \\\\10.10.10.3\\sharename
smbclient //10.10.10.3/tmp # different syntax 
smbclient -N //10.10.10.3/tmp --option='client min protocol=NT1' # for using insecure protocol if negotiation failed
```


# SNMP
```bash
snmpwalk
snmpwalk -c public -v2c 10.10.10.116
snmp-check
```

## Bruteforce Community Strings
```
echo public > community
echo private >> community
echo manager >> community

for ip in $(seq 1 254); do echo 10.10.10.$ip; done > ips

onesixtyone -c community -i ips
```

## Enumerate Windows users
```
snmpwalk -c public -v1 10.10.10.10 1.3.6.1.4.1.77.1.2.25
```

## Enumerate Windows processes
```
snmpwalk -c public -v1 10.10.10.10 1.3.6.1.2.1.25.4.2.1.2
```

## Enumerate Open TCP Ports
```
snmpwalk -c public -v1 10.10.10.10 1.3.6.1.2.1.6.13.1.3
```

## Enumerate Installed Software
```
snmpwalk -c public -v1 10.10.10.10 1.3.6.1.2.1.25.6.3.1.2
```

# POP3
Connect to port 110 and retreive mails (authenticated)
```
USER username
PASS password
LIST # list all mails
RETR 1 # retreive mail 1
```

# NFS
Mount the share
```
mount -t nfs -o port=4445 127.0.0.1:/srv/Share /tmp/pe -o nolock
```
Create directory and copy bash into it
```
mkdir /tmp/pe
cd /tmp/pe
cp /bin/bash .
```
set SUID
```
chmod +s bash
```
run as user
```
./bash -p
```

# Kerberos

## kerbrute
A tool to quickly bruteforce and enumerate valid Active Directory accounts through Kerberos Pre-Authentication

See https://github.com/ropnop/kerbrute

Download:
```
git clone https://github.com/ropnop/kerbrute.git
```

Edit Makefile and add architecture to the line ``ARCHS=amd64 386`` (e.g. arm64


```
make linux
cd dist
./kerbrute_linux_arm64
```

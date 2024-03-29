# Port Scanning

``` bash
nmap -sC -sV -oA outfiles 192.168.1.0/24
nmap --top-ports=1000 -sT -Pn 10.10.10.10,11,12 --open
nmap -Pn -n -p21,22,139,445,3632 --script vuln -sV -oN nmap/vuln_scan 10.10.10.3
nmap -T4 -Pn -p- 10.10.10.10 -o tmp.nmap > /dev/null
nmap -sC -sV -o portscan.nmap -p $(cat tmp.nmap | grep open | cut -d\t -f1 | sed 's/\///g' | paste -sd, ) 10.10.10.10 > /dev/null
for i in `nmap -T4 -p- 192.168.67.133 |grep open |cut -f 1 -d /` ; do nmap -T4 -p$i -A 192.168.67.133; done
nmap -sU 10.10.10.116 # UDP
```

# Web Application Enumeration

## BurpSuite
Go to "Target" > "Site map" > right click on host > "Spider this host" 

## Directory Enumeration
```
gobuster dir -k -u https://10.10.10.7/ -w usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt	
wfuzz -z file,/usr/share/seclists/Fuzzing/special-chars.txt -d "name=FUZZ" -u http://10.10.10.10/test
ffuf -w wordlist.txt -u https://example.org/FUZZ -mc all -fs 42 -c -v
```

Install golang and add the following two lines to ~/.bashrc (or ~/.profiles)

```
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin		
```

## Parameter Fuzzing
See [arjun](https://www.kali.org/tools/arjun/)

Assume URL "http://internal.analysis.htb/users/list.php"
Fuzz potential parameters by using arjun. Example:

```
arjun -u "http://internal.analysis.htb/users/list.php"
    _
   /_| _ '
  (  |/ /(//) v2.2.1
      _/      

[*] Probing the target for stability
[*] Analysing HTTP response for anomalies
[*] Analysing HTTP response for potential parameter names
[*] Logicforcing the URL endpoint
[✓] parameter detected: name, based on: body length
[+] Parameters found: name

```


# Vulnerability Scan
## Nessus
```
sudo /etc/init.d/nessus start 
# http://localhost:8834

```
## Nikto
Installation:
```
sudo apt install nikto
```
Usage:
```
nikto -h <hostname/IP>
nikto -h <hostname/IP> -port 80,443
```
# Fuzz subdomains
```
wfuzz -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://shoppy.htb -H "Host: FUZZ.shoppy.htb" --hh 169
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://shoppy.htb -H "Host: FUZZ.shoppy.htb" --fs 169
gobuster dns -d mydomain.com -w ...
gobuster dns -d analysis.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r analysis.htb
```

# SQL Enumeration
Connect remotely to mysql database:
```
mysql --host=10.10.10.10 --port=1234 --user=db_user -p
```
Show privileges
```
SHOW Grants;
show variables;
```
# [Assetfinder](https://github.com/tomnomnom/assetfinder)

```
go get -u github.com/tomnomnom/assetfinder
```

:information_source: also see [amass](https://github.com/OWASP/Amass)

# [Httprobe](https://github.com/tomnomnom/httprobe) (find alive domains)

```
go get -u github.com/tomnomnom/httprobe
```

# [GoWitness](https://github.com/sensepost/gowitness) (Screenshotting Websites)

```
go get -u github.com/sensepost/gowitness
```

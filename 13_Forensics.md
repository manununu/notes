# Memory Analysis
## msfpescan
* Search for jump equivalent instruction
* Search for pop+pop+ret combinations
* Search for regex match

## Get Function Address
```
objdump -d my.exe | grep func1
nm -A my.exe | grep func1
```

## .dmp file
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
# Reverse Engineering
## gdb
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

## .NET assembly decompiler
* [ILSpy](https://github.com/icsharpcode/ILSpy)
* [dotPeek](https://www.jetbrains.com/decompiler/)

## radare2 (r2)
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

## Malware Analysis
* [REMNux](https://remnux.org/)


# System Images
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

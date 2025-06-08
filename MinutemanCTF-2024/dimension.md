# Dimension (rev, hard)

## Initial Analysis

We are given a "dimension.py" file which contains an EXTREMELY long obfuscated byte string (10151687 bytes), followed by some python code. The string seems to be encoded with base64 and then compressed with zlib as shown by the last line of code. Nothing seems to happen when we run it though.

```py
s=b'eJwUm7VitdwWRR/nFhS4FbfA5eAOHe7uPP2fr0yT5Oy115xjQLL/P/tfqd7+u...'

from zlib import decompress
from base64 import b64decode
import sys
sys.tracebacklimit = 0
sys.setrecursionlimit(65000)
getch = lambda: sys.stdin.read(1)
exec(decompress(b64decode(s)).decode())
```

When we look inside the decompressed/decoded text, we see yet another EXTREMELY long but slightly shorter byte string (10051315 bytes), but the code at the bottom is different. Seems like if we keep going, we'll eventually reach an end and hopefully the flag with it.

```py
s=b'eJwUmre2smoURR/nFhTkVNyCnDNI6MhJcubpf0+pYxyPfOy91pzq9n/...'
exit(0) if len(ch:=getch())!=1 or ord(ch)!=84 else exec(decompress(b64decode(s)).decode())
```

The exec/decompress/decode part at the end is the same, but now we see an exit(), getch() from "dimension.py", and an ord(), all followed by a number. We don't know what these mean yet, but let's try decompressing the string again.

```py
s=b'eJwUm7d2q1oURT/nFRTkVLyCnDMSoSMnkTNff3FvDetw9l5rToa9/p/+V6jnp...'
exit(1) if len(ch:=getch())!=1 or ord(ch)!=104 else exec(decompress(b64decode(s)).decode())
```

Starting to get a sense of deja vu here... The structure looks exactly the same as the previous text, but the exit() number has been incremented by 1. The getch() number still stays 1, which makes sense because it's reading 1 byte from stdin. Interestingly, the ord() number changed a bit more. ord() is used to get the ascii code of a character, so maybe this might be a clue to getting our flag. Let's try one more time just to be sure.

```py
s=b'eJwUmbXWs0oYRi/nFBS4FafACe7W4RJcA1f/87XJWiQz887z7J1s/2f/...'
exit(2) if len(ch:=getch())!=1 or ord(ch)!=101 else exec(decompress(b64decode(s)).decode())
```

Here we see that the exit() number still increments and ord() still changes.

## Decoding the Entire File

With this information we can try repeatedly decoding each iteration of text and see what it leads us to. We assume that the structure from now on will always be the encoded byte string `s` followed by the ternary exit or decode line, except for the final iteration. This means we should specifically stop when the file doesn't start with the `s` string.

```py
from zlib import decompress
from base64 import b64decode

code = ""
with open(f"dimension.py", "r") as f:
   code = f.read()

i = 1
while True:
   # extract s
   start = 4  # `s=b'`
   end = code.find("'", start)
   if start == -1 or end == -1:
       print("no s str")
       break
   encoded_str = code[start:end]
   decoded = decompress(b64decode(encoded_str)).decode()
   # save each iteration
   with open(f"txt/{i}.py", "w") as f:
       f.write(decoded)
   i += 1

   # done decoding
   if "s=b'" not in decoded:
      print(decoded)
      break

   # next iteration
   code = decoded
```

This code extracts the s string which always starts with `s=b'` and ends with a single quote. Then, it decodes and decompresses the string, repeating the process until the s string isn't found, meaning that we reached the end of the loop. At each step the decoded text is saved to a file for future analysis.

With this, we get 660 files generated and the final decoded message just contains `print('Congrats')`.

## Extracting Text from ord()

Unfortunately, it seems like the CTF devs thought putting the flag here would've been too easy. However, remember when we said that the ord() number changes every iteration? What if we saved those values and converted them to ascii?

```py
from zlib import decompress
from base64 import b64decode
import re

code = ""
with open(f"dimension.py", "r") as f:
   code = f.read()
# matches "ord(ch)!=#", where # is a 1+ digit number
ord_pattern = re.compile(r"ord\(ch\)!=([0-9]+)")
nums = []
i = 1
while True:
   # extract s
   start = 4  # `s=b'`
   end = code.find("'", start)
   if start == -1 or end == -1:
       print("no s str")
       break
   encoded_str = code[start:end]
   decoded = decompress(b64decode(encoded_str)).decode()

   # each file has 2-3 digit number in `ord(ch)!=...`, prob ascii
   ord_match = ord_pattern.search(decoded)
   if ord_match:
       # extracts number from ([0-9]+)
       num = ord_match.group(1)
       nums.append(num)

   # save each iteration
   # with open(f"txt/{i}.py", "w") as f:
   #     f.write(decoded)
   # i += 1

   # done decoding
   if "s=b'" not in decoded:
       print(decoded)
       # convert nums to ascii text
       with open("ascii.txt", "w") as f:
           conv = "".join(chr(int(num)) for num in nums)
           f.write(conv)
       break

   # next iteration
   code = decoded
```

Here we added code that saves each ord() number to an array, converts them to ascii, and saves them into a file called "ascii.txt".

```
The consistency paradox or grandfather paradox occurs when the past is changed in any way, thus creating a contradiction. A common example given is traveling to the past and intervening with the conception of one's ancestors (such as causing the death of the parent beforehand), thus affecting the conception of oneself. If the time traveler were not born, then it would not be possible for the traveler to undertake such an act in the first place. Therefore, the ancestor lives to offspring the time traveler's next-generation ancestor, and eventually the time traveler. There is thus no predicted outcome to this.


STAY


MINUTEMAN{38.8355556,-104.6975000}
```

At the bottom of the text is our flag, `MINUTEMAN{38.8355556,-104.6975000}`.

## Final Thoughts

I liked this challenge because it didn't require any particularly niche knowledge, just an understanding of Python and a bit of patience. Props to the organizers for making this a fun experience!

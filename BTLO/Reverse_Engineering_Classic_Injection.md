# Malicious PowerShell Analysis

Link: [BTLO](https://blueteamlabs.online/home/challenge/reverse-engineering-a-classic-injection-9791a9b784)

## Requirements

- IDA Sysinternals

## Questions

### What is the name of the compiler used to generate the EXE? (1 points)

Open the file in CFF Explorer. Interesting fact is that DIE doesn't return the same result.

`Microsoft Visual C++ 8`

### This malware, when executed, sleeps for some time. What is the sleep time in minutes? (1 points)

Let's open it in the Ida and follow the entry point.

```
push    2BF20h          ; dwMilliseconds
call    ds:Sleep

2BF20h = 180000 -> / 1000 -> / 60 = 3 minutes
```

`3`

### After the sleep time, it prompts for user password, what is the correct password? (1 points)

![Alt text](data/Reverse_Engineering_Classic_Injection/sleep.png?raw=true "Hidden column")

```
mov     edx, offset asc_40320C ; "?\n"
mov     ecx, ds:?cout@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A ; std::basic_ostream<char,std::char_traits<char>> std::cout
call    sub_4015F0
mov     ecx, ds:?cin@std@@3V?$basic_istream@DU?$char_traits@D@std@@@1@A ; std::basic_istream<char,std::char_traits<char>> std::cin
lea     edx, [ebp+Block]
call    sub_401A40
cmp     [ebp+var_1F0], 10h
lea     ecx, [ebp+Block]
mov     edi, [ebp+Block]
mov     edx, 4
mov     esi, [ebp+var_1F4]
cmovnb  ecx, edi
cmp     esi, edx
cmova   esi, edx
mov     edx, offset aBtlo ; "btlo"
```

`btlo`

### What is the size of the shellcode? (1 points)

When following the decompiled code, you will find the call to allocate memory, which is used for loading the shellcode.

![Alt text](data/Reverse_Engineering_Classic_Injection/size.png?raw=true "Hidden column")

```
push    40h ; '@'       ; flProtect
push    3000h           ; flAllocationType
push    1D9h            ; dwSize
push    0               ; lpAddress
push    [ebp+ProcessInformation.hProcess] ; hProcess
call    ds:VirtualAllocEx
```

`1D9h -> 473`

[Process injection](https://www.ired.team/offensive-security/code-injection-process-injection/process-injection)
[Process injection Primer](https://sevrosecurity.com/2020/04/08/process-injection-part-1-createremotethread/#process_injection_primer)

### Shellcode injection involves three important windows API. What is the name of the API Call used? (2 points)

`CreateRemoteThread`

### What is the name of the victim process? (1 points)

`nslookup.exe`

### What is the file created by the sample (1 points)

`C:\Windows\Temp\btlo.txt`

### What is the message in the created file (1 points)

`Welcome to BTLO!`

### What is the program that the shellcode used to create and write this file (1 points)

![Alt text](data/Reverse_Engineering_Classic_Injection/powershell.png?raw=true "Hidden column")

`powershell.exe`

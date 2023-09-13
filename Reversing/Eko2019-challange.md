# Eko2019 Challange

As a part of my preparation to take OSED Certification from Offsec I decided to find some CTF challenges which were based on reverse engineering and exploit creation and test my newly gained skillz.

## Initial analysis

The challenge had no description, it just provided `eko2019.exe` executable, so I guess for CTF it was running code (poping calc) but for my training I would rather do a reverse shell.

The binary itself is a portable 64bit exe. That is something new for me as the whole course is based on 32bit, so I am curious if that pose an extra challenge to me.

!!!Screenshot from CFF

Running the binary gives following output:

```
[+] Ekoparty 2019 - BFS challenge
[+] Server listening
[+] Waiting for client connections
```

Now the programs hangs as it is waiting for incoming connection - based on the text. Let's verify it in IDA and WinDBG.

Opening the executable in IDA Pro show that this basic logic is implemented in main function. There is several checks around opening sockets, printing of the information messages and the `accept` function at address `eko2019+1524` which hangs and wait for the incoming connection.

Based on the code preceding this we see that the bind is attaching to address `0.0.0.0` and port `431h` which is `54321` for TCP protocol- all visible at address `eko2019+14BB`. The port could be also found by dynamic analysis with TCPDump or Process Explorer.

!!! Screenshot of bind function

The recieved data are then forwarded to a function at address `eko2019+1555`. In my case it is function `sub_1400011E0`.

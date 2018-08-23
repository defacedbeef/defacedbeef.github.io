---
layout: post
title: libfuzzer - quick starter
tags: [ fuzzing, libfuzzer ]
---

# libFuzzer intro



## Makefile

```
#defs
DSO		= libtest.so
SRC		= test.cpp

#targets
lib: CFLAGS+=-fPIC -shared
lib:
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(SRC) -o $(DSO) $(LDFLAGS)

######################################################################
#fuzzy addendun
FUZZSRC		= fuzz-target.cpp
FUZZERFLAGS	= -fsanitize=fuzzer -g
FUZZOUT		= libfuzzer

libfuzzer: CFLAGS+=$(FUZZERFLAGS)
libfuzzer: CXX=clang++
libfuzzer: lib
	$(CXX) $(CXXFLAGS) $(CFLAGS) $(FUZZSRC) -o $(FUZZOUT) ./$(DSO)
	mkdir -p fuzzer/libfuzzer
	mv $(FUZZOUT) fuzzer/libfuzzer
	mv $(DSO) fuzzer/libfuzzer
```

## Faulty-lib-under-test

```
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
extern "C" int Q_API(const char* message) {
	if(strlen(message) > 1024) {
		abort();
	}
	return 0;
}
```

## Fuzzy target

```
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

extern "C" int Q_API(const char* message);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	if(size == 0) {
		return 0;
	}
	Q_API((const char*)data);
	return 0;
}
```

## build

```
$ make libfuzzer
clang++  -fsanitize=fuzzer -g -fPIC -shared test.cpp -o libtest.so 
# create fuzz target
clang++  -fsanitize=fuzzer -g fuzz-target.cpp -o libfuzzer ./libtest.so
mkdir -p fuzzer/libfuzzer
mv libfuzzer fuzzer/libfuzzer
mv libtest.so fuzzer/libfuzzer
$
```

## run

```
cd fuzzer/libfuzzer
$ ./libfuzzer 
INFO: Seed: 3197253394
INFO: Loaded 2 modules   (5 inline 8-bit counters): 2 [0x7f391e500048, 0x7f391e50004a), 3 [0x67f020, 0x67f023), 
INFO: Loaded 2 PC tables (5 PCs): 2 [0x7f391e500050,0x7f391e500070), 3 [0x46ede0,0x46ee10), 
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
#2	INITED cov: 4 ft: 5 corp: 1/1b exec/s: 0 rss: 32Mb
#1048576	pulse  cov: 4 ft: 5 corp: 1/1b exec/s: 524288 rss: 32Mb
#2097152	pulse  cov: 4 ft: 5 corp: 1/1b exec/s: 524288 rss: 32Mb
#4194304	pulse  cov: 4 ft: 5 corp: 1/1b exec/s: 466033 rss: 32Mb
#8388608	pulse  cov: 4 ft: 5 corp: 1/1b exec/s: 466033 rss: 32Mb
#16777216	pulse  cov: 4 ft: 5 corp: 1/1b exec/s: 479349 rss: 32Mb
==31654== ERROR: libFuzzer: deadly signal
    #0 0x460cc3  (/home/defacedbeef/projects/misc/libFuzzer/fuzzer/libfuzzer/libfuzzer+0x460cc3)
    #1 0x417b66  (/home/defacedbeef/projects/misc/libFuzzer/fuzzer/libfuzzer/libfuzzer+0x417b66)
    #2 0x417bbf  (/home/defacedbeef/projects/misc/libFuzzer/fuzzer/libfuzzer/libfuzzer+0x417bbf)
    #3 0x7f391dd5488f  (/lib/x86_64-linux-gnu/libpthread.so.0+0x1288f)
    #4 0x7f391d36be96  (/lib/x86_64-linux-gnu/libc.so.6+0x3ee96)
    #5 0x7f391d36d800  (/lib/x86_64-linux-gnu/libc.so.6+0x40800)
    #6 0x7f391e2ff927  (libtest.so+0x927)
    #7 0x4632bb  (/home/defacedbeef/projects/misc/libFuzzer/fuzzer/libfuzzer/libfuzzer+0x4632bb)
    #8 0x4182a7  (/home/defacedbeef/projects/misc/libFuzzer/fuzzer/libfuzzer/libfuzzer+0x4182a7)
    #9 0x422b14  (/home/defacedbeef/projects/misc/libFuzzer/fuzzer/libfuzzer/libfuzzer+0x422b14)
    #10 0x42417f  (/home/defacedbeef/projects/misc/libFuzzer/fuzzer/libfuzzer/libfuzzer+0x42417f)
    #11 0x41353c  (/home/defacedbeef/projects/misc/libFuzzer/fuzzer/libfuzzer/libfuzzer+0x41353c)
    #12 0x406422  (/home/defacedbeef/projects/misc/libFuzzer/fuzzer/libfuzzer/libfuzzer+0x406422)
    #13 0x7f391d34eb96  (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)
    #14 0x406479  (/home/defacedbeef/projects/misc/libFuzzer/fuzzer/libfuzzer/libfuzzer+0x406479)

NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
MS: 5 InsertRepeatedBytes-InsertRepeatedBytes-CopyPart-CopyPart-CopyPart-; base unit: adc83b19e793491b1c6ea0fd8b46cd9f32e592fc
artifact_prefix='./'; Test unit written to ./crash-593ae351a9a3cff359c9ea8ca2a0d4b302a72f4b
$ wc -c < crash-593ae351a9a3cff359c9ea8ca2a0d4b302a72f4b 
1230
$
```

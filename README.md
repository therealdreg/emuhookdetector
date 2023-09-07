# emuhookdetector
hook detector using emulation and comparing static with dynamic outputs

Plese, consider make a donation: https://github.com/sponsors/therealdreg

Warning!!: the code is bullshit (is only a beta prototype).

MIT LICENSE - Copyright (c) emuhookdetector 0.1Beta-crap - January 2016
by: David Reguera Garcia aka Dreg - dreg@fr33project.org
https://github.com/David-Reguera-Garcia-Dreg
http://www.fr33project.org

## Usage
Generate the dynamic link exe report:

```
./emuhookdetector_dynamic
mv report.txt report_dynamic.txt
```

Generate the static link exe report:
```
 ./emuhookdetector_static
 mv report.txt report_static.txt
```

The ldd output in a non hooked machine should be:
```
root@ubuntu:~/emuhookdetector# ldd emuhookdetector_static
        not a dynamic executable
root@ubuntu:~/emuhookdetector# ldd emuhookdetector_dynamic
        linux-vdso.so.1 =>  (0x00007ffe37b1c000)
        libunicorn.so.1 => /usr/lib/libunicorn.so.1 (0x00007f01ab045000)
        libcapstone.so.3 => /usr/lib/libcapstone.so.3 (0x00007f01aab97000)
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f01aa978000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f01aa598000)
        libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f01aa242000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f01ab549000)
```

The static report in a non hooked machine can be like this:

```
root@ubuntu:~/emuhookdetector# cat report_static.txt
** RIP = 0x1000000 (converted: 0x573640) ***:
        41 55
                                                                push            r13
*** RIP = 0x1000002 (converted: 0x573642) ***:
        41 54
                                                                push            r12
*** RIP = 0x1000004 (converted: 0x573644) ***:
        49 89 fd
                                                                mov             r13, rdi
*** RIP = 0x1000007 (converted: 0x573647) ***:
        55
                                                                push            rbp
*** RIP = 0x1000008 (converted: 0x573648) ***:
        53
                                                                push            rbx
*** RIP = 0x1000009 (converted: 0x573649) ***:
        be 01 00 00 00
                                                                mov             esi, 1
*** RIP = 0x100000e (converted: 0x57364e) ***:
        31 c0
                                                                xor             eax, eax
*** RIP = 0x1000010 (converted: 0x573650) ***:
        48 83 ec 08
                                                                sub             rsp, 8
*** RIP = 0x1000014 (converted: 0x573654) ***:
        48 c7 c5 b8 ff ff ff
                                                                mov             rbp, -0x48
*** RIP = 0x100001b (converted: 0x57365b) ***:
        64 44 8b 65 00
                                                                mov             r12d, dword ptr fs:[rbp]
```

The dynamic report in a non hooked machine should be very similar to static report.

Example: Compare the results & ldd output in a machine infected by vlany rootkit: https://github.com/mempodippy/vlany/

The ldd output in a hooked machine by vlany rootkit is:

```
root@ubuntu:~/emuhookdetector# ldd emuhookdetector_static
        linux-vdso.so.1 =>  (0x00007ffffbdc2000)
        libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007fb512217000)
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007fb511ff8000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb511c18000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fb51294c000)
root@ubuntu:~/emuhookdetector# ldd emuhookdetector_dynamic
        linux-vdso.so.1 =>  (0x00007ffc10b6c000)
        libunicorn.so.1 => /usr/lib/libunicorn.so.1 (0x00007f726348f000)
        libcapstone.so.3 => /usr/lib/libcapstone.so.3 (0x00007f7262fe1000)
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f7262dc2000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f72629e2000)
        libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f726268c000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f7263993000)
```

As you can see the static exe should be empty, but is linked!

You also should compare the results of both reports to check if there are changes in the flow instructions (then can be hooked).

# Compilation

## Compile & install deps

```
apt-get install git
apt-get install python2.7 # or try: apt-get install python or apt-get install python27
git clone https://github.com/unicorn-engine/unicorn.git
cd unicorn
UNICORN_STATIC=yes UNICORN_SHARED=yes UNICORN_ARCHS="x86" UNICORN_QEMU_FLAGS="--python=/usr/bin/python2.7" ./make.sh
make install
cd ..
git clone https://github.com/aquynh/capstone.git
cd capstone/
CAPSTONE_ARCHS="x86" CAPSTONE_STATIC=yes CAPSTONE_SHARED=yes ./make.sh
make install
cd ..
```

## Compile emuhookdetector

```
git clone https://github.com/David-Reguera-Garcia-Dreg/emuhookdetector.git
cd emuhookdetector
make
```

The output should of ldd should be something like:

```
root@ubuntu:~/emuhookdetector# ldd emuhookdetector_dynamic
        linux-vdso.so.1 =>  (0x00007ffe1fd95000)
        libunicorn.so.1 => /usr/lib/libunicorn.so.1 (0x00007f85523aa000)
        libcapstone.so.3 => /usr/lib/libcapstone.so.3 (0x00007f8551efc000)
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f8551cdd000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f85518fd000)
        libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f85515a7000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f85528ae000)
root@ubuntu:~/emuhookdetector# ldd emuhookdetector_static
        not a dynamic executable
```

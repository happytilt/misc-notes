from pwn import *

print(cyclic(50))
print(cyclic_find('laaa'))

print(shellcraft.sh())
print(hexdump(asm(shellcraft.sh())))

#on linux, create /bin/sh process for a bash shell
p = process('cmd.exe')
p.sendline('notepad.exe')
p.interactive()

#im on windows so i use ncat instead of netcat
#run this on host: ncat -l -p 7777
r = remote('127.0.0.1', 7777)
r.sendline('gurt: yo')
r.close()

#going to revist since Python 101 covers Linux processes and CLI
#will try and mirror notes for Windows hosts
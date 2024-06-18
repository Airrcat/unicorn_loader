from pe_loader.pe_loader import  *
from ctypes import *
from unicorn import *
import capstone as cs
check = 0
boom = 0
def trace(mu: Uc, address, size, data):
    global check
    global boom
    EIP = mu.reg_read(unicorn.x86_const.UC_X86_REG_EIP)
    CODE = [i for i in md.disasm(mu.mem_read(address, size), size)][0]
    #print(">>> EIP : %x" % (EIP),hex(int.from_bytes(mu.mem_read(address, size),"big"))[2:], CODE.mnemonic, CODE.op_str)
    if EIP == 0x19:
        mu.reg_write(unicorn.x86_const.UC_X86_REG_DL,boom)
    if EIP == 0x1f:
        a = mu.reg_read(unicorn.x86_const.UC_X86_REG_FLAGS)
        b = mu.reg_read(unicorn.x86_const.UC_X86_REG_FLAGS)&(2**6)
        if mu.reg_read(unicorn.x86_const.UC_X86_REG_FLAGS)&(2**6)==(2**6):
                check = 1
                #print(boom)
                mu.emu_stop()
                return
    if EIP > 0x30:
        mu.emu_stop()
def emu_do(pe:pe_loader):
    #
    pass
anwsers = [0]*1010
count = 0
for suffix in range(0,1009):
    path = "attachment/binaries/"
    prefix = "binary"
    if suffix == 993:
        continue
    loader = pe_loader(path + prefix+ str(suffix),UC_MODE_32)
    sections = loader.get_sections()
    vaddr = 0
    vsize = 0xdf - 0xb0
    raddr = 0xb0
    rsize = 0xdf - 0xb0
    content = 0
    #print("try find .text")
    for s in sections:
        if '.text' in s.Name:
            vaddr = s.VirtualAddress
            vsize = s.SizeOfRawData
            raddr = s.PointerToRawData
            rsize = s.SizeOfRawData
            content = loader.image[vaddr:vaddr + vsize]
    content = loader.image[raddr:raddr + rsize]
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
    #print(md.disasm(content))
    BASE_ADDR = vaddr
    CODE_LEN = vsize

    uc = unicorn.Uc(UC_ARCH_X86,UC_MODE_32)
    uc.mem_map(BASE_ADDR,32*1024)
    uc.mem_write(BASE_ADDR,b'\x00'*32*1024)
    STACK = b'\x00' * 1024
    STACK_POINT = 30 * 1024
    uc.reg_write(unicorn.x86_const.UC_X86_REG_SP,STACK_POINT)
    uc.mem_write(unicorn.x86_const.UC_X86_REG_SP + 0x10, b'\x50')
    #uc.mem_write(unicorn.x86_const.UC_X86_REG_SP+0x10,b'\x00')
    #uc.reg_write(unicorn.x86_const.UC_X86_REG_EAX,)
    CODE = content
    uc.mem_write(BASE_ADDR,CODE)
    uc.hook_add(UC_HOOK_CODE, trace)
    #print("start")
    for i in range(0,0xff):
        if check == 1:
            #print(boom)
            anwsers[count] = boom
            count += 1
            check = 0
            break
        try:
            boom = i
            #uc.mem_write(0x50, bytes(i))
            uc.emu_start(BASE_ADDR, rsize)
        except UcError as e:
            print("ERROR ", e)
    uc.mem_unmap(BASE_ADDR,32*1024)
    import gc
    del uc
    gc.collect()
print(anwsers)
print(bytes(anwsers))
with open("attachment/binaries/anwser.txt","wb") as f:
    f.write(bytes(anwsers))
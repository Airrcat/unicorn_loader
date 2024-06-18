from pe_loader.pe_loader import  *
from unicorn import *
import capstone as cs
check = 0
boom = 0
def trace(mu: Uc, address, size, data):
    global check
    global boom
    EIP = mu.reg_read(unicorn.x86_const.UC_X86_REG_EIP)
    if EIP == 0x19:
        mu.reg_write(unicorn.x86_const.UC_X86_REG_DL,boom)
    if EIP == 0x1f:
        if mu.reg_read(unicorn.x86_const.UC_X86_REG_FLAGS)&(2**6)==(2**6):
                check = 1
                mu.emu_stop()
                return
    if EIP > 0x30:
        mu.emu_stop()
anwsers = [0]*1010
count = 0
for suffix in range(0,1009):
    path = "attachment/binaries/"
    prefix = "binary"
    if suffix == 993:
        continue
    loader = pe_loader(path + prefix+ str(suffix),UC_MODE_32)
    vaddr = 0
    vsize = 0xdf - 0xb0
    raddr = 0xb0
    rsize = 0xdf - 0xb0
    content = loader.image[raddr:raddr + rsize]

    CODE = content
    BASE_ADDR = vaddr
    CODE_LEN = vsize

    uc = unicorn.Uc(UC_ARCH_X86,UC_MODE_32)
    # 整体内存空间的初始化
    uc.mem_map(BASE_ADDR,32*1024)
    uc.mem_write(BASE_ADDR,b'\x00'*32*1024)
    # 栈空间初始化，因为内存刚刚整体写了，这里其实可以不用。
    STACK = b'\x00' * 1024
    STACK_POINT = 30 * 1024
    # 栈初始化
    uc.reg_write(unicorn.x86_const.UC_X86_REG_SP,STACK_POINT)

    uc.mem_write(BASE_ADDR,CODE)
    uc.hook_add(UC_HOOK_CODE, trace)
    for i in range(0,0xff):
        if check == 1:
            anwsers[count] = boom
            count += 1
            check = 0
            break
        try:
            boom = i
            uc.emu_start(BASE_ADDR, rsize)
        except UcError as e:
            print("ERROR ", e)
    uc.mem_unmap(BASE_ADDR,32*1024)
    import gc
    del uc
    gc.collect()

with open("attachment/binaries/anwser.txt","wb") as f:
    f.write(bytes(anwsers))
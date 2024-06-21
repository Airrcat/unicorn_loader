import unicorn

from pe_loader.pe_loader import *
from unicorn import *
def load(path:str,mode:int,arch:int) -> (Uc,pe_loader):
    # 自动解析pe，装载所有段。
    pe = pe_loader(path,mode)
    sections = pe.get_sections()
    uc = Uc(arch,mode)
    for section,image in sections:
        #image = pe.image[section.PointerToRawData:section.PointerToRawData+section.SizeOfRawData]
        uc.mem_map(section.VirtualAddress, section.VirtualSize)
        uc.mem_write(section.VirtualSize,image)
    return uc,pe
    #print("loaded.")
"./attachment/upx.exe"
import unicorn.unicorn_const


class pe_loader(object):
    image = b''
    IMAGE_SIZEOF_SIGNATURE = 4
    IMAGE_SIZEOF_FILE_HEADER = 20

    def __init__(self, filename: str, mode: int):

        try:
            f = open(filename, "rb")
        except Exception as e:
            print("file error occurs : %s" % e)
            return
        if mode == unicorn.UC_MODE_32 or mode == unicorn.UC_MODE_64:
            self.mode = mode
            #print("target : %s | mode code %s:" % (filename, mode))
        else:
            print("mode para error! just recv UC_MODE_32 and UC_MODE_64")

        self.image = f.read()
        #print("target read finish")
        if mode == unicorn.UC_MODE_32:
            self.pe_dos_header = pe32_dos_header(self.image)
            self.pe_nt_header = pe32_nt_header(self.image[int.from_bytes(self.pe_dos_header.e_lfanew, 'little'):])
            self.pe_optional_header = pe32_optional_header(
                self.image[int.from_bytes(self.pe_dos_header.e_lfanew, 'little') + 0x18:])
            offset_of_section_header = int.from_bytes(self.pe_dos_header.e_lfanew, 'little') + \
                                 self.IMAGE_SIZEOF_SIGNATURE + \
                                 self.IMAGE_SIZEOF_FILE_HEADER + \
                                 int.from_bytes(self.pe_nt_header.SizeOfOptionalHeader, 'little')
            self.pe_section_header = pe32_section_header(
                self.image[offset_of_section_header:offset_of_section_header + int.from_bytes(self.pe_nt_header.NumberOfSections,
                                                                                  'little') * 40],
                int.from_bytes(self.pe_nt_header.NumberOfSections, 'little'))
        #print("pe loaded.")
        f.close()
        pass

    def get_sections(self):
        section_num = int.from_bytes(self.pe_nt_header.NumberOfSections,'little')
        section_list = []
        for i in range(section_num):
            raw_address = int.from_bytes(self.pe_section_header.section_table[i].PointerToRawData,'little')
            section = pe32_section(self.image[raw_address::])
            section_list.append(section)
            #section.Name = self.image[raw_address:raw_address+4]
            #section.VirtualSize = self.image[raw_address]
        #print("sections get.")
        return section_list
        pass

class pe32_dos_header:

    def __init__(self, image: bytes):
        self.e_magic = image[0:2]
        self.e_cblp = image[2:4]
        self.e_cp = image[4:6]
        self.e_crlc = image[6:8]
        self.e_cparhdr = image[8:10]
        self.e_minalloc = image[10:12]
        self.e_maxalloc = image[12:14]
        self.e_ss = image[14:16]
        self.e_sp = image[16:18]
        self.e_csum = image[18:20]
        self.e_ip = image[20:22]
        self.e_cs = image[22:24]
        self.e_lfarlc = image[24:26]
        self.e_ovno = image[26:28]
        self.e_res = []
        self.e_oemid = image[36:38]
        self.e_oeminfo = image[40:42]
        self.e_res2 = []
        self.e_lfanew = image[60:64]


class pe32_nt_header:
    # image请给到以nt_header为起始地址
    def __init__(self, image: bytes):
        self.DosStub = image[0:4]
        self.Machine = image[4:6]
        self.NumberOfSections = image[6:8]
        self.TimeDataStamp = image[8:12]
        self.PointerToSymbolTable = image[12:16]
        self.NumberOfSymbols = image[16:20]
        self.SizeOfOptionalHeader = image[20:22]
        self.Characteristics = image[22:24]


class pe32_optional_header:
    byte = 1
    word = 2
    dword = 4
    ulonglong = 8
    offset = {
        'Magic': 0,
        'MajorLinkerVersion': 2,
        'MinorLinkerVersion': 3,
        'SizeOfCode': 4,
        'SizeOfInitializedData': 8,
        'SizeOfUninitializedData': 0xc,
        'AddressOfEntryPoint': 0x10,
        'BaseOfCode': 0x14,
        'BaseOfData': 0x18,
        'ImageBase': 0x1c,
        'SectionAlignment': 0x20,
        'FileAlignment': 0x24,
        'MajorOperatingSystemVersion': 0x28,
        'MinorOperatingSystemVersion': 0x2a,
        'MajorImageVersion': 0x2c,
        'MinorImageVersion': 0x2e,
        'MajorSubsystemVersion': 0x30,
        'MinorSubsystemVersion': 0x32,
        'Win32VersionValue': 0x34,
        'SizeOfImage': 0x38,
        'SizeOfHeaders': 0x3c,
        'CheckSum': 0x40,
        'SubSystem': 0x44,
        'DllCharacteristics': 0x46,
        'SizeOfStackReserve': 0x48,
        'SizeOfStackCommit': 0x4c,
        'SizeOfHeapReserve': 0x50,
        'SizeOfHeapCommit': 0x54,
        'LoaderFlags': 0x58,
        'NumberOfRvaAndSizes': 0x5c
    }

    def __init__(self, image: bytes):
        self.Magic = image[:self.offset['Magic'] + self.word]
        self.MajorLinkerVersion = image[self.offset['MajorLinkerVersion']:self.offset['MajorLinkerVersion'] + self.byte]
        self.MinorLinkerVersion = image[self.offset['MinorLinkerVersion']:self.offset['MinorLinkerVersion'] + self.byte]
        self.SizeOfCode = image[self.offset['SizeOfCode']:self.offset['SizeOfCode'] + self.dword]
        self.SizeOfInitializedData = image[self.offset['SizeOfInitializedData']:self.offset[
                                                                                    'SizeOfInitializedData'] + self.dword]
        self.SizeOfUninitializedData = image[self.offset['SizeOfUninitializedData']:self.offset[
                                                                                        'SizeOfUninitializedData'] + self.dword]
        self.AddressOfEntryPoint = image[
                                   self.offset['AddressOfEntryPoint']:self.offset['AddressOfEntryPoint'] + self.dword]
        self.BaseOfCode = image[self.offset['BaseOfCode']:self.offset['BaseOfCode'] + self.dword]
        self.BaseOfData = image[self.offset['BaseOfData']:self.offset['BaseOfData'] + self.dword]
        self.ImageBase = image[self.offset['ImageBase']:self.offset['ImageBase'] + self.dword]
        self.SectionAlignment = image[self.offset['SectionAlignment']:self.offset['SectionAlignment'] + self.dword]
        self.FileAlignment = image[self.offset['FileAlignment']:self.offset['FileAlignment'] + self.dword]
        self.MajorOperatingSystemVersion = image[self.offset['MajorOperatingSystemVersion']:self.offset[
                                                                                                'MajorOperatingSystemVersion'] + self.word]
        self.MinorOperatingSystemVersion = image[self.offset['MinorOperatingSystemVersion']:self.offset[
                                                                                                'MinorOperatingSystemVersion'] + self.word]
        self.MajorImageVersion = image[self.offset['MajorImageVersion']:self.offset['MajorImageVersion'] + self.word]
        self.MinorImageVersion = image[self.offset['MinorImageVersion']:self.offset['MinorImageVersion'] + self.word]
        self.MajorSubsystemVersion = image[self.offset['MajorSubsystemVersion']:self.offset[
                                                                                    'MajorSubsystemVersion'] + self.word]
        self.MinorSubsystemVersion = image[self.offset['MinorSubsystemVersion']:self.offset[
                                                                                    'MinorSubsystemVersion'] + self.word]
        self.Win32VersionValue = image[self.offset['Win32VersionValue']:self.offset['Win32VersionValue'] + self.dword]
        self.SizeOfImage = image[self.offset['SizeOfImage']:self.offset['SizeOfImage'] + self.dword]
        self.SizeOfHeaders = image[self.offset['SizeOfHeaders']:self.offset['SizeOfHeaders'] + self.dword]
        self.CheckSum = image[self.offset['CheckSum']:self.offset['CheckSum'] + self.dword]
        self.SubSystem = image[self.offset['SubSystem']:self.offset['SubSystem'] + self.word]
        self.DllCharacteristics = image[self.offset['DllCharacteristics']:self.offset['DllCharacteristics'] + self.word]
        self.SizeOfStackReserve = image[
                                  self.offset['SizeOfStackReserve']:self.offset['SizeOfStackReserve'] + self.dword]
        self.SizeOfStackCommit = image[self.offset['SizeOfStackCommit']:self.offset['SizeOfStackCommit'] + self.dword]
        self.SizeOfHeapReserve = image[self.offset['SizeOfHeapReserve']:self.offset['SizeOfHeapReserve'] + self.dword]
        self.SizeOfHeapCommit = image[self.offset['SizeOfHeapCommit']:self.offset['SizeOfHeapCommit'] + self.dword]
        self.LoaderFlags = image[self.offset['LoaderFlags']:self.offset['LoaderFlags'] + self.dword]
        self.NumberOfRvaAndSizes = image[
                                   self.offset['NumberOfRvaAndSizes']:self.offset['NumberOfRvaAndSizes'] + self.dword]


class pe32_section_header:
    section_table = []
    _word = 2
    _dword = 4
    _offset = {
        "Name": 0,
        "Misc": 8,
        "VirtualAddress": 0xc,
        "SizeOfRawData": 0x10,
        "PointerToRawData": 0x14,
        # //0X18 DWORD   PointerToRelocations;    //重定位偏移(obj中使用)
        # //0X1C DWORD   PointerToLinenumbers;    //行号表偏移(调试用)
        # //0X20 WORD    NumberOfRelocations;     //重定位项目数(obj中使用)
        # //0X22 WORD    NumberOfLinenumbers;		//行号表中行号的数目
        "Characteristics": 0x24
    }

    def __init__(self, image: bytes, number: int):
        for i in range(number):
            pos = i * 40
            section = pe32_section(image)
            section.Name = self.read_section_name(image[pos:])
            section.VirtualAddress = image[pos + self._offset["VirtualAddress"]:pos + self._offset[
                "VirtualAddress"] + self._dword]
            section.SizeOfRawData = image[pos + self._offset["SizeOfRawData"]:pos + self._offset[
                "SizeOfRawData"] + self._dword]
            section.PointerToRawData = image[pos + self._offset["PointerToRawData"]:pos + self._offset[
                "PointerToRawData"] + self._dword]
            section.Characteristics = image[pos + self._offset["Characteristics"]:pos + self._offset[
                "Characteristics"] + self._dword]
            self.section_table.append(section)

        pass

    @staticmethod  # 可能加上确认段格式？
    def read_section_name(image: bytes):
        # pos = image.find(0)
        # return image[:pos]
        return image[:8]  # 定长八字节
        pass


class pe32_section:

    def __init__(self,image:bytes):
        self.Name = image[:8]
        self.VirtualSize = image[8:12]
        self.VirtualAddress = image[12:16]
        self.SizeOfRawData = image[16:20]
        self.PointerToRawData = image[20:24]
        self.PointerToRelocations = image[24:28]
        self.PointerToLinenumbers = image[28:32]
        self.NumberOfRelocations = image[32:34]
        self.NumberOfLinenumbers = image[34:36]
        self.Characteristics = image[36:40]
        pass


#pe = pe_loader("../attachment/1.exe", unicorn.UC_MODE_32)
#pe.get_sections()
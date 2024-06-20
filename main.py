import unicorn

from pe_loader.pe_loader import *
from unicorn import *

pe = pe_loader("./attachment/upx.exe",UC_MODE_64)
print("loaded.")
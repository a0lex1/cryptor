from enum import Flag

class SecMemChars(Flag):
  ###disabled for simplicity
  ###IMAGE_SCN_MEM_DISCARDABLE = 0x02000000 #The section can be discarded as needed.
  ###IMAGE_SCN_MEM_NOT_CACHED = 0x04000000 #The section cannot be cached.
  ####IMAGE_SCN_MEM_NOT_PAGED = 0x08000000 #The section cannot be paged.
  ####IMAGE_SCN_MEM_SHARED = 0x10000000 #The section can be shared in memory.
  IMAGE_SCN_MEM_EXECUTE = 0x20000000 #The section can be executed as code.
  IMAGE_SCN_MEM_READ    = 0x40000000 #The section can be read.
  IMAGE_SCN_MEM_WRITE   = 0x80000000 #The section can be written to.
 # msdn 12 may 2023



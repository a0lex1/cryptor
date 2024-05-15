import os, sys

from c2.evp.page_prot import PageProt
from c2.evp.sec_mem_chars import SecMemChars


def getprot(sec_char:SecMemChars) -> PageProt:
  membits = sec_char.value & 0xE0000000
  idx = membits // 0x20000000
  #print(f'getprot({sec_char.value=:x}): {idx=:x}')

  # IMAGE_SCN_MEM_READ is ignored by windows loader, e.g. always readable, -> IMAGE_SCN_MEM_WRITE converts to read-write, etc.
  #
  gkProtmap = [
    PageProt.PAGE_NOACCESS,         # 0x01    # by -                                  (0x00000000)
    PageProt.PAGE_EXECUTE,          # 0x10    # by MEM_EXECUTE                        (0x20000000)
    PageProt.PAGE_READONLY,         # 0x02    # by MEM_READ                           (0x40000000)
    PageProt.PAGE_EXECUTE_READ,     # 0x20    # by MEM_EXECUTE|MEM_READ               (0x60000000)
    PageProt.PAGE_READWRITE,        # 0x04    # by MEM_WRITE                          (0x80000000)
    PageProt.PAGE_EXECUTE_READWRITE,# 0x40    # by MEM_EXECUTE|MEM_WRITE              (0xA0000000)
    PageProt.PAGE_READWRITE,        # 0x04    # by MEM_READ|MEM_WRITE                 (0xC0000000)
    PageProt.PAGE_EXECUTE_READWRITE # 0x40    # by MEM_READ|MEM_WRITE|MEM_EXECUTE     (0xE0000000)
  ]
  return PageProt(gkProtmap[idx])


def _test(sec_char:SecMemChars, expect_pageprot:PageProt, dry=False):
  pageprot = getprot(sec_char)
  if not dry:
    if pageprot != expect_pageprot:
      #print(f'{sec_char=} : got: {pageprot}, expected: {expect_pageprot}')
      raise RuntimeError(f'{sec_char=} : got: {pageprot}, expected: {expect_pageprot}')

def test_getprot(argv):
  dry = False
  _test(SecMemChars(0), PageProt.PAGE_NOACCESS, dry=dry)
  _test(SecMemChars.IMAGE_SCN_MEM_EXECUTE, PageProt.PAGE_EXECUTE, dry=dry)
  _test(SecMemChars.IMAGE_SCN_MEM_WRITE, PageProt.PAGE_READWRITE, dry=dry)
  _test(SecMemChars.IMAGE_SCN_MEM_EXECUTE | SecMemChars.IMAGE_SCN_MEM_WRITE, PageProt.PAGE_EXECUTE_READWRITE, dry=dry)
  _test(SecMemChars.IMAGE_SCN_MEM_READ, PageProt.PAGE_READONLY, dry=dry)
  _test(SecMemChars.IMAGE_SCN_MEM_READ | SecMemChars.IMAGE_SCN_MEM_EXECUTE, PageProt.PAGE_EXECUTE_READ, dry=dry)
  _test(SecMemChars.IMAGE_SCN_MEM_READ | SecMemChars.IMAGE_SCN_MEM_WRITE, PageProt.PAGE_READWRITE, dry=dry)
  _test(SecMemChars.IMAGE_SCN_MEM_READ | SecMemChars.IMAGE_SCN_MEM_WRITE | SecMemChars.IMAGE_SCN_MEM_EXECUTE,
        PageProt.PAGE_EXECUTE_READWRITE, dry=dry)


if __name__ == '__main__':
  test_getprot(sys.argv[1:])



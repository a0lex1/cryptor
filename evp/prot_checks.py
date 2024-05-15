from typing import List

from c2.evp.sec_mem_chars import SecMemChars
from c2.evp.page_prot import PageProt
from c2.evp.getprot import getprot

# sec_prot cannot contain flags like PAGE_GUARD
def is_enough_prot_for_scn(sec_char:SecMemChars, sec_prot:PageProt) -> bool:
  # write-copy is enough for read
  assert(type(sec_char) == SecMemChars and type(sec_prot) == PageProt)
  PP = PageProt

  prots_execute = [PP.PAGE_EXECUTE, PP.PAGE_EXECUTE_READ, PP.PAGE_EXECUTE_READWRITE, PP.PAGE_EXECUTE_WRITECOPY]
  prots_read = [PP.PAGE_EXECUTE_READ, PP.PAGE_EXECUTE_READWRITE, PP.PAGE_READONLY, PP.PAGE_EXECUTE_WRITECOPY, PP.PAGE_READWRITE, PP.PAGE_WRITECOPY]
  prots_write = [PP.PAGE_EXECUTE_READWRITE, PP.PAGE_EXECUTE_WRITECOPY, PP.PAGE_READWRITE, PP.PAGE_WRITECOPY]

  allowed_prots = prots_execute + prots_read + prots_write + [PP.PAGE_NOACCESS]
  if sec_prot not in allowed_prots:
    raise RuntimeError(f'unknown {sec_prot}; sure you didn\'t put flags like PAGE_GUARD in it?')

  if sec_char & SecMemChars.IMAGE_SCN_MEM_EXECUTE:
    if not sec_prot in prots_execute:
      return False
  if sec_char & SecMemChars.IMAGE_SCN_MEM_READ:
    if not sec_prot in prots_read:
      return False
  if sec_char & SecMemChars.IMAGE_SCN_MEM_WRITE:
    if not sec_prot in prots_write:
      return False

  return True

#def is_enough_scn_for_scn(sec_char:SecMemChars,) #could be


def check_prot_match_secchars(prots, sec_chars, protlogic_opts):
  for nsec in range(len(prots)):
    sec_char = sec_chars[nsec]
    prot = prots[nsec]
    if protlogic_opts['exact']:
      actual_prot = getprot(sec_char)
      if actual_prot != prot:
        raise RuntimeError()
    else:
      if not is_enough_prot_for_scn(sec_char, prot):
        raise RuntimeError()
  return



def _test(sec_char:SecMemChars, allowed_prots:List[PageProt], expect_truthiness=True):
  nprot = 0
  for prot in allowed_prots:
    actual_enough = is_enough_prot_for_scn(sec_char, prot)
    if expect_truthiness:
      if not actual_enough:
        raise RuntimeError(f'{nprot=}: expected Enough, but Not enough: {prot=} for {sec_char=}')
    else:
      if actual_enough:
        raise RuntimeError(f'{nprot=}: expected Not enough, but Enough: {prot=} for {sec_char=}')
    nprot += 1


def test_is_enough_prot_for_scn(argv):
  PP = PageProt

  _test(SecMemChars(0), [PP.PAGE_NOACCESS, PP.PAGE_EXECUTE, PP.PAGE_EXECUTE_READ, PP.PAGE_EXECUTE_READWRITE, PP.PAGE_EXECUTE_WRITECOPY, PP.PAGE_NOACCESS, PP.PAGE_READONLY, PP.PAGE_READWRITE, PP.PAGE_WRITECOPY])
  _test(SecMemChars(0), [], expect_truthiness=False)

  _test(SecMemChars.IMAGE_SCN_MEM_EXECUTE, [PP.PAGE_EXECUTE, PP.PAGE_EXECUTE_READ, PP.PAGE_EXECUTE_READWRITE])
  _test(SecMemChars.IMAGE_SCN_MEM_EXECUTE, [PP.PAGE_NOACCESS, PP.PAGE_READONLY, PP.PAGE_READWRITE, PP.PAGE_WRITECOPY], expect_truthiness=False)

  _test(SecMemChars.IMAGE_SCN_MEM_WRITE, [PP.PAGE_EXECUTE_READWRITE, PP.PAGE_EXECUTE_WRITECOPY, PP.PAGE_READWRITE, PP.PAGE_WRITECOPY])
  _test(SecMemChars.IMAGE_SCN_MEM_WRITE, [PP.PAGE_EXECUTE, PP.PAGE_EXECUTE_READ, PP.PAGE_NOACCESS, PP.PAGE_READONLY], expect_truthiness=False)

  _test(SecMemChars.IMAGE_SCN_MEM_EXECUTE | SecMemChars.IMAGE_SCN_MEM_WRITE, [PP.PAGE_EXECUTE_READWRITE, PP.PAGE_EXECUTE_WRITECOPY])
  _test(SecMemChars.IMAGE_SCN_MEM_EXECUTE | SecMemChars.IMAGE_SCN_MEM_WRITE, [PP.PAGE_EXECUTE, PP.PAGE_EXECUTE_READ, PP.PAGE_NOACCESS, PP.PAGE_READWRITE, PP.PAGE_READWRITE, PP.PAGE_WRITECOPY], expect_truthiness=False)

  _test(SecMemChars.IMAGE_SCN_MEM_READ, [PP.PAGE_EXECUTE_READ, PP.PAGE_EXECUTE_READWRITE, PP.PAGE_READONLY, PP.PAGE_READWRITE])
  _test(SecMemChars.IMAGE_SCN_MEM_READ, [PP.PAGE_EXECUTE, PP.PAGE_NOACCESS], expect_truthiness=False)

  _test(SecMemChars.IMAGE_SCN_MEM_READ | SecMemChars.IMAGE_SCN_MEM_EXECUTE,  [PP.PAGE_EXECUTE_READ, PP.PAGE_EXECUTE_READWRITE])
  _test(SecMemChars.IMAGE_SCN_MEM_READ | SecMemChars.IMAGE_SCN_MEM_EXECUTE,  [PP.PAGE_EXECUTE, PP.PAGE_NOACCESS, PP.PAGE_READONLY, PP.PAGE_READWRITE, PP.PAGE_WRITECOPY], expect_truthiness=False)

  _test(SecMemChars.IMAGE_SCN_MEM_READ | SecMemChars.IMAGE_SCN_MEM_WRITE, [PP.PAGE_EXECUTE_READWRITE, PP.PAGE_READWRITE])
  _test(SecMemChars.IMAGE_SCN_MEM_READ | SecMemChars.IMAGE_SCN_MEM_WRITE, [PP.PAGE_EXECUTE, PP.PAGE_EXECUTE_READ, PP.PAGE_NOACCESS, PP.PAGE_READONLY], expect_truthiness=False)

  _test(SecMemChars.IMAGE_SCN_MEM_READ | SecMemChars.IMAGE_SCN_MEM_WRITE | SecMemChars.IMAGE_SCN_MEM_EXECUTE, [PP.PAGE_EXECUTE_READWRITE])
  _test(SecMemChars.IMAGE_SCN_MEM_READ | SecMemChars.IMAGE_SCN_MEM_WRITE | SecMemChars.IMAGE_SCN_MEM_EXECUTE, [PP.PAGE_EXECUTE, PP.PAGE_EXECUTE_READ, PP.PAGE_NOACCESS, PP.PAGE_READONLY, PP.PAGE_READWRITE, PP.PAGE_WRITECOPY], expect_truthiness=False)



if __name__ == '__main__':
  test_is_enough_prot_for_scn(None)



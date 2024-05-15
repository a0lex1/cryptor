from c2.evp.page_prot import PageProt
from c2.evp.sec_mem_chars import SecMemChars


def prot2memscn(prot:PageProt) -> SecMemChars:
  return SecMemChars.IMAGE_SCN_MEM_XXX


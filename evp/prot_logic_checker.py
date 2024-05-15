from typing import List

from c2.evp.prot_checks import check_prot_match_secchars
from c2.evp.sec_mem_chars import SecMemChars


class ProtLogicChecker:
  def __init__(self, sec_chars: List[SecMemChars], logic, protlogic_opts):
    self.__sec_chars = sec_chars
    self.__logic = logic
    self.__protlogic_opts = protlogic_opts

  def check(self, sec_names=None):
    self.__emulate(sec_names)

  def __is_secidx_pageprot_tups_ordered(self) -> bool:
    # check order
    prev_idx = None
    for sec_idx, sec_prot in self.__logic.secidx_pageprot_tups:
      if prev_idx != None:
        if sec_idx < prev_idx:
          return False
      prev_idx = sec_idx
    return True

  def __emulate(self, sec_names=None):
    num_sec = len(self.__logic.secidx_pageprot_tups)

    if not self.__protlogic_opts['shuffle']:
      if not self.__is_secidx_pageprot_tups_ordered():
        raise RuntimeError(f'wrong order in secidx_pageprot_tups but shuffling disabled')

    # fill all with initial prot
    initprots = [self.__logic.initial_pageprot for _ in range(len(self.__sec_chars))]
    prots = initprots.copy()

    # apply prots
    for nsec in range(num_sec):
      sec_idx, sec_prot = self.__logic.secidx_pageprot_tups[nsec]
      prots[sec_idx] = sec_prot

    #for nsec in range(len(prots)): # decided to implement logging in class SecProtLogicGen
    #  sec_name = sec_names[nsec] if sec_names != None else ''
    #  print(f'{nsec=}  initial={initprots[nsec].name}  actual={prots[nsec].name}   sec_name={sec_name.decode()}')

    # check
    check_prot_match_secchars(prots, self.__sec_chars, self.__protlogic_opts)



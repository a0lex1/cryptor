from typing import List

from prettytable import PrettyTable

from c2.evp.page_prot import PageProt, PAGE_PROT_SHORTCUTS
from c2.evp.sec_mem_chars import SecMemChars
from c2.evp.prot_checks import is_enough_prot_for_scn
from c2.evp.getprot import getprot
from c2.evp.prot_logic import SecProtLogic


# Expects logic.initial_pageprot to be initialized by caller
# Prints log if |prnfn|
class SecProtLogicGen:
  def __init__(self, logic:SecProtLogic, sec_chars:List[SecMemChars], protlogic_opts, rng):
    self.__logic = logic # output
    self.__sec_chars = sec_chars
    self.__protlogic_opts = protlogic_opts
    self.__rng = rng

    self.prnfn = None # public
    self.sec_names = None # public, logging labels


  def generate(self):
    # Got:                     _MEM_READ    _MEM_WRITE    _MEM_EXECUTE   (prot=)
    #   |self.__sec_char|  -> [  +                             +         PAGE_EXECUTE_READ     # .text   nsec=0
    #                            +              +                        PAGE_READWRITE        # .data   nsec=1
    #                          ...
    #                         ]
    #
    # Need to pick some |initial_pageprot| and then
    # generate (+mix order) :
    #                              nsec
    #   |secidx_pageprot_tups| -> [(6, PAGE_READWRITE),                 # dwProt for sec6
    #                              (2, PAGE_EXECUTE_READ),              # dwProt for sec2 .data
    #                              ...
    #                             ]
    #

    available_initprot_strs = self.__protlogic_opts['initial_prots'].split(',')
    available_initprots = [PAGE_PROT_SHORTCUTS[p] for p in available_initprot_strs]
    # disallow wx (PAGE_EXECUTE_WRITECOPY), cuz VirtualAlloc fails
    permitted_initprots = ['rw', 'rwx']
    illegal_initprots = set(available_initprot_strs) - set(permitted_initprots)
    if illegal_initprots:
      print(f'{available_initprot_strs=}')
      print(f'{illegal_initprots=}')
      raise RuntimeError(f'available_initprots contain illegal_initprots, see log')

    self.__logic.initial_pageprot = self.__rng.choice(available_initprots)
    self.__logic.secidx_pageprot_tups = []

    if self.prnfn:
      print(f'chosen initial prot: {self.__logic.initial_pageprot.name}')
      tbl = PrettyTable()
      tbl.field_names = ['nsec', 'sec_name', 'sec_scn', 'status', 'dice', 'chosen', 'choice_from']

    for nsec in range(len(self.__sec_chars)):
      sec_scn = self.__sec_chars[nsec] # section |nsec| 's characteristics

      initprot = self.__logic.initial_pageprot
      do_reprotect = False

      # logging
      reprot_status = '' # text label
      dice = None
      possible_prots = None
      chosen_prot = None

      if not is_enough_prot_for_scn(sec_scn, initprot):
        do_reprotect = True
        reprot_status = f'not_enough(initprot={initprot.name})'
      elif self.__protlogic_opts['exact'] and getprot(sec_scn) != self.__logic.initial_pageprot:
        do_reprotect = True
        reprot_status = f'enough,but_exact_required(initprot={initprot.name})'
      else:
        # enough protect; exact disabled; this is our `unnecessary' case, check its probability
        _probab = self.__protlogic_opts['probab_unnecess_reprot']
        dice = self.__rng.randint(1, 100)
        if dice < _probab:
          do_reprotect = True
          reprot_status = f'unnecess_dice_won({dice}<{_probab})'
        else:
          reprot_status = f'unnecess_dice_loose({dice}>={_probab})'

      if do_reprotect:
        if self.__protlogic_opts['exact']:
          possible_prots = None
          chosen_prot = getprot(sec_scn)
        else:
          possible_prots = self.__make_possible_prots(sec_scn)
          chosen_prot = self.__rng.choice(possible_prots)

        self.__logic.secidx_pageprot_tups.append( (nsec, chosen_prot) )

      if self.prnfn:
        sec_name = self.sec_names[nsec].decode() if self.sec_names != None else ''
        _poss = [p.name for p in possible_prots] if possible_prots else ''
        _posss = ','.join(_poss)
        _chprt = chosen_prot.name if chosen_prot != None else ''
        tbl.add_row([nsec, sec_name, sec_scn,  reprot_status, dice, _chprt, _posss])

      # to next section
      pass

    if self.prnfn:
      # print table
      self.prnfn(str(tbl))

    # all sections processed
    if self.__protlogic_opts['shuffle']:
      self.__rng.shuffle(self.__logic.secidx_pageprot_tups)


  def __make_possible_prots(self, sec_scn:SecMemChars) -> List[PageProt]:
    reads, writes, executes = [True], [True], [True]
    if not sec_scn & SecMemChars.IMAGE_SCN_MEM_READ:
      reads += [False]
    if not sec_scn & SecMemChars.IMAGE_SCN_MEM_WRITE:
      writes += [False]
    if not sec_scn & SecMemChars.IMAGE_SCN_MEM_EXECUTE:
      executes += [False]
    ret_list = []
    for read in reads:
      for write in writes:
        for execute in executes:
          scn = SecMemChars(0)
          if read:
            scn |= SecMemChars.IMAGE_SCN_MEM_READ
          if write:
            scn |= SecMemChars.IMAGE_SCN_MEM_WRITE
          if execute:
            scn |= SecMemChars.IMAGE_SCN_MEM_EXECUTE

          prot = getprot(scn)

          ret_list.append(prot)

    return ret_list



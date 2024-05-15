from dataclasses import dataclass
from typing import List, Tuple

from c2.evp.page_prot import PageProt


@dataclass
class SecProtLogic:
  initial_pageprot : PageProt = None
  secidx_pageprot_tups : List[Tuple[int, PageProt]] = None # see example below














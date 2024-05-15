from dataclasses import dataclass
from typing import List

from c2.sprayer.ccode.node import Node


@dataclass
class FuncAST:
  stmtlist: List[Node]=None


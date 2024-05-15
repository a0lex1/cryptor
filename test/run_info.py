from dataclasses import dataclass
from typing import List, Tuple


# [('whoami', expect), ('whoami', 0), ]
@dataclass
class RunInfo:
  shell_cmd_tups: List[Tuple[str, int]]

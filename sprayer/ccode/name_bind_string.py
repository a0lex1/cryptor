from dataclasses import dataclass
from typing import List

from c2.sprayer.ccode.var import Var, VarNameTable


@dataclass
class NameBindString:
  format_string: str = None
  argument_list: List = None


# lala $1 lala $2      , [ v0, v132 ]
# lala v0 lala v132
def eval_name_bind_string(sgl:NameBindString, vnt:VarNameTable):
  s = sgl.format_string
  for i in range(len(sgl.argument_list)):
    a = sgl.argument_list[i]
    assert(type(a) == Var)
    repl = vnt.get_var_name(a)
    s = s.replace(f'${i+1}', repl)
  return s

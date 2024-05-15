import random

from c2._internal_config import get_tmp_dir
from c2.sprayer.gens.dfstmtgen import DFStmtGen, DFStmtForm, get_includes_for_dfstmtfor
from c2.sprayer.vp.var_picker2 import RWVarValueRangePicker
from c2.sprayer.ccode.var import *
from c2.sprayer.ccode.node import *
from c2.sprayer.ccode.textualizer import Textualizer
from c2.sprayer.test.helper_main_cpp import HelperMainCPP
from c2.sprayer.test.srcexec import srcexec


def test_df_stmt_gen():
  vl0 = [Var(VT.i8, [1,2,3,4,5,6,7,8]), Var(VT.u16, [10, 20]), Var(VT.i32, [0, 15, 25, 39])]
  vl1 = [Var(VT.u32, [55, 66, 77, 88, 99]), Var(VT.i8, [230, 240])]
  vls = [vl0, vl1]
  vp = RWVarValueRangePicker(vls, random.Random(), use_random_rwirange_picker=True)
  dfgen = DFStmtGen(vp, vls)
  stmtlist = node_stmtlist()
  used_dfstmtforms = set()
  for i in range(1000):
    stmt = dfgen.gen_stmt(DFStmtForm.MEMCPY)
    used_dfstmtforms.add(DFStmtForm.MEMCPY)
    stmtlist.children.append(stmt)

  vl_g = []
  vl_a = [*vl0]
  vl_l = [*vl1]
  vtbl = VarNameTable(vl_g, vl_a, vl_l)
  texer = Textualizer(lambda v: vtbl.get_var_name(v))
  code_text = texer.visit(stmtlist)

  glob_decls = decl_varlist(vtbl.vl_g, vtbl.names_g, line_prefix='static ', valprn=ValPrintType.WITH_VALUE)
  loc_decls = decl_varlist(vtbl.vl_l, vtbl.names_l, tabs=1, valprn=ValPrintType.WITH_VALUE)
  arg_decls = decl_arglist(vtbl.vl_a, vtbl.names_a)
  #call_args = ', '.join([f'({type_names[v.typ]})0x{v.values[0]:x}' for v in vtbl.vl_a])
  call_args = '&std::vector<i8>(8)[0], &std::vector<u16>(2)[0], &std::vector<i32>(4)[0]'

  # generate cpp template
  RET_CODE = 4930430
  include_headers = [get_includes_for_dfstmtfor(dfstmtform) for dfstmtform in used_dfstmtforms]
  include_headers += ['vector']
  helper_cpp = HelperMainCPP(include_headers,
                             '\n'.join(glob_decls),
                             '\n'.join(loc_decls),
                             ', '.join(arg_decls),
                             call_args,
                             code_text,
                             RET_CODE)
  # execute generated cpp template
  print(f'executing helper cpp...')

  prjdir = get_tmp_dir() + '/test_dfstmtgen'
  srcexec(prjdir, 'test_exprgen', helper_cpp, RET_CODE)
  

if __name__ == '__main__':
  test_df_stmt_gen()

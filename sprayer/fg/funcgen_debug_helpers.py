from c2.sprayer.fg.func_ast import FuncAST
from c2.sprayer.fg.var_storage import *
from c2.sprayer.ccode.var import VarNameTable
from c2.sprayer.ccode.textualizer import Textualizer
from c2.common.graph import *

# Inherited to FuncGen* classes to add eye-debug functionality
class FuncGenAstDebugHelpers:
  def _print_ast(self):
    text = self.__textualize_ast()
    print(text)

  def _view_graph(self):
    labelnodes(self._skel.G, self._skeldata);
    save_graph(self._skel.G, '.', 'fgfull')

  def _notepad_ast(self):
    text = self.__textualize_ast()
    fname = f'fg{self.__class__.__name__}_ast.txt'
    open(fname, 'w').write(text)
    import os
    os.system(f'notepad {fname}')

  def __textualize_ast(self):
    vnt = VarNameTable(sum(get_globvar_vls(self._varstor), []),
                       sum(get_argvar_vls(self._varstor), []),
                       sum(get_locvar_vls(self._varstor), []))
    texer = Textualizer(lambda v: vnt.get_var_name(v))
    text = texer.visit(self._get_func_ast().stmtlist)
    return text

  # override in derived to provide your AST to our helpers
  def _get_func_ast(self) -> FuncAST:
    raise NotImplementedError()




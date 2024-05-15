from c2.common.execcmd import execcmd

from c2.pg.intermed import ProgramIntermed

# detail class. Options cannot be controlled from pgopts. Proggen officially supports only Cppparts kind of output.
# generates: ProgramIntermed -> program.cpp, act_xxx*, etc.
# resposible for checking if the |pi| is .conceptually_empty to take proper actions
class PGOutputGen:
  def __init__(self, pi:ProgramIntermed, out_dir:str, pgopts:dict):
    self._pi = pi
    self._out_dir = out_dir
    self.opts = pgopts

  def execute(self):
    raise NotImplementedError()


class PGOutputGenCppparts(PGOutputGen):
  def execute(self):
    self.
    if self._pi.conceptually_empty:
      program_cpp_text = 'int ProgramEntry() { return 13; }'
      open(f'{self._out_dir}/program.cpp', 'w').write(program_cpp_text)
    else:
      raise RuntimeError('TODO: now only empty ProgramIntermed is supported')
    self._make_hardlinks_to_depfiles()

  def _make_hardlinks_to_depfiles(self):
    for depfile in self._pi.cached_depfiles:
      depfile_fullp = f'{_pg_cpp_dir}/{depfile}'
      target_fullp = f'{self._out_dir}/{depfile}'
      execcmd(f'mklink /h {_slashes(target_fullp)} {_slashes(depfile_fullp)}')


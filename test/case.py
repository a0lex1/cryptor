from dataclasses import dataclass
from collections import OrderedDict


# prj2runinfo -> {'virlib': RunInfo(), 'virprog': RunInfo([('rundll32 x', 0), ()]), } # target_projects determined by prj2runinfo
@dataclass
class Case:
  title: str = None
  pay_info: dict = None
  file_path: str = None
  prj2runinfo: 'OrderedDict[str, RunInfo]' = None

  def __repr__(self):
    s = self
    pi = self.pay_info
    pay_info = self.payinfo_str(pi)
    #return f'({pistr}, {s.target_configs}, {len(s.prj2runinfo)} tests, {s.file_path}, `{s.title}`)'
    return f'(TITLE: {s.title}  {pay_info=}, {len(s.prj2runinfo)} cmd(s), {s.file_path})'

  def payinfo_str(self, pi):
    postfnrva = pi['postfn_rva'] if 'postfn_rva' in pi else '-'
    frommain = 'YES' if pi['dll_evil_from_dllmain'] else 'NO'
    return f'{pi["bin_type"]} {pi["cpu"]} {postfnrva=} {frommain=}'


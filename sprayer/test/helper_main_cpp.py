import os
from typing import List
from dataclasses import dataclass

from c2.common.replace_all import replace_all

_sd = os.path.dirname(__file__)

@dataclass
class HelperMainCPP:
  includes:List[str]=None
  glob_vars:str=None
  loc_vars:str=None
  args_funcdecl:str=None
  args_funccall:str=None
  code:str=None
  retcode:int=None
  predefs:str=None

  def produce(self):
    includes = self.includes
    if includes == None:
      includes = []
    templ = open(os.path.join(_sd, f'{_sd}/helper_main.cpp.tmpl'), 'r').read()
    incls = [f'#include <{f}> //  |includes|' for f in includes]
    templ = replace_all(templ, '%%%includes%%%', '\n'.join(incls))
    templ = replace_all(templ, '%%%glob_vars%%%', self.glob_vars)
    templ = replace_all(templ, '%%%loc_vars%%%', self.loc_vars)
    templ = replace_all(templ, '%%%args_funcdecl%%%', self.args_funcdecl)
    templ = replace_all(templ, '%%%args_funccall%%%', self.args_funccall)
    templ = replace_all(templ, '%%%code%%%', self.code)
    templ = replace_all(templ, '%%%retcode%%%', str(self.retcode))
    predefs = ''
    if self.predefs != None:
      predefs = self.predefs
    templ = replace_all(templ, '%%%predefs%%%', predefs)
    return templ



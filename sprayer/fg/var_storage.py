from enum import Enum
from typing import List

from c2.sprayer.ccode.var import Var

# VarList Indices
# Can't use Enum because we can't use enums as indices to vls. Python will say 'list indices must be ints, not ...'
VLI_A = 0
VLI_G = 1
VLI_L_CTL = 2
VLI_L_TRASH = 3
VLI_L_CTL_U = 4
VLI_L_TRASH_U = 5

LAST_VLI = VLI_L_TRASH_U

vli_table = { VLI_A: 'A', VLI_G: 'G',
              VLI_L_CTL: 'L_CTL', VLI_L_TRASH: 'L_TRASH',
              VLI_L_CTL_U: 'L_CTL_U', VLI_L_TRASH_U: 'L_TRASH_U'}

argvar_vli_list = [VLI_A]
globvar_vli_list = [VLI_G]
locvar_vli_list = [VLI_L_CTL, VLI_L_TRASH, VLI_L_CTL_U, VLI_L_TRASH_U]

# VarStorage consists of |vls| as a public member and some conventional operations over it.
# Examples of use: vls[VL.A], vls[VL.L_CTL_U], etc.
class VarStorage:
  def __init__(self, vls=None):
    self.vls = vls  # List[List[Var]], example:  [ [Var(), Var(), ], [Var(), ], ]

  # |vls| = single vl for every VLI
  def validate(self):
    return len(self.vls) == LAST_VLI+1 # +1 since we're counting from 0

  def set_comments_to_vars(self):
    vli2vliname = {f'VL__{vli}' for vli in vli_table.values()}
    for vli in vli2vliname.keys():
      vliname = vli2vliname[vli]
      for v in self.__vls[vli]:
        v.cmnt = f'// {vliname}'


def get_argvar_vls(varstor:VarStorage):
  return [varstor.vls[vli] for vli in argvar_vli_list]

def get_globvar_vls(varstor:VarStorage):
  return [varstor.vls[vli] for vli in globvar_vli_list]

def get_locvar_vls(varstor:VarStorage):
  return [varstor.vls[vli] for vli in locvar_vli_list]

# A helper to enumerate the VLI(s) as args explicitly to prevent mistakes
def make_var_storage(vl_a=None, vl_g=None, vl_l_ctl=None, vl_l_trash=None, vl_l_ctl_u=None, vl_l_trash_u=None) -> VarStorage:
  if vl_a == None:
    vl_a = []
  if vl_g == None:
    vl_g = []
  if vl_l_ctl == None:
    vl_l_ctl = []
  if vl_l_trash == None:
    vl_l_trash = []
  if vl_l_ctl_u == None:
    vl_l_ctl_u = []
  if vl_l_trash_u == None:
    vl_l_trash_u = []
  return VarStorage([vl_a, vl_g, vl_l_ctl, vl_l_trash, vl_l_ctl_u, vl_l_trash_u])


### TEST CODE ###

def _test_vls():
  vl_a = []
  vl_g = []
  vl_l_ctl = []
  vl_l_trash = []
  vl_l_ctl_u = []
  vl_l_trash_u = []
  vs = make_var_storage(vl_a, vl_g, vl_l_ctl, vl_l_trash, vl_l_ctl_u, vl_l_trash_u)
  vs.validate()
  assert(vs.vls[VLI_A] is vl_a)
  assert(vs.vls[VLI_G] is vl_g)
  assert(vs.vls[VLI_L_CTL] is vl_l_ctl)
  assert(vs.vls[VLI_L_TRASH] is vl_l_trash)
  assert(vs.vls[VLI_L_CTL_U] is vl_l_ctl_u)
  assert(vs.vls[VLI_L_TRASH_U] is vl_l_trash_u)

def _test_set_comments_to_vars():
  pass

def test_var_storage():
  _test_vls()
  _test_set_comments_to_vars()

if __name__ == '__main__':
  test_var_storage()




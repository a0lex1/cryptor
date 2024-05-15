import re, random, os, sys
from typing import List, Dict, Tuple

from c2._internal_config import get_tmp_dir
from c2.sprayer.ctools.split_c_var_decl import split_c_var_decl
from c2.common.execcmd import execcmd
from c2.common.ensure_known_shell_program import ensure_known_shell_program


class StructReorderer:
  def __init__(self, structs:List[str], struct_fields:Dict[str, List[str]]):
    self.structs = structs # input and output
    self.struct_fields = struct_fields
    self._total_swapped = None

  def do_reorder(self):
    self._total_swapped = 0
    while True:
      swapped = self._reorder_structs()
      if swapped == 0:
       break
      self._total_swapped += swapped

  def _reorder_structs(self):
    swapped = 0
    structs = self.structs
    struct_fields = self.struct_fields
    for nstruct in range(len(structs)):
      structname = structs[nstruct]
      fields = struct_fields[structname]
      nstruct_CUR = nstruct # will be updated in loop
      for field in fields:
        typedecl, vardecl, arrdecl = split_c_var_decl(field)
        if typedecl in structs:
          typeind = structs.index(typedecl)
          if typeind > nstruct_CUR:
            #swap
            old = structs[typeind]
            structs[typeind] = structs[nstruct_CUR]
            structs[nstruct_CUR] = old
            swapped += 1
            nstruct_CUR = typeind

    return swapped


# Welcome. Our retarted zoo intro-fucking-duces: a happy food family for experiments. They all eat shit probably. The test will show.
_PIECE_OF_spraytab = {
  "structs": [
    "MAN",
    "WOMAN",
    "INFANT",
    "CAT",
    "DOG",
    "MICE",
    "FOODPLATE",
    "FOOD",

    "SIDEGIRL",
    "SIDEDOG"
  ],
  "struct_fields": {
    "MAN": [
      "int hand1;",
      "int hand2;",
      "WOMAN woman;",
      "int afterwoman;",
      "int afterwoman2;"
    ],
    "WOMAN": [
      "int crooked_hand1;",
      "int crooked_hand2;",
      "INFANT infant;"
    ],
    "INFANT": [
      "int bla;",
      "CAT cat;",
      "DOG dog;",
      "MICE mice;"
    ],
    "CAT": [
      "FOODPLATE cat_foodplate;",
      "SIDEDOG secret_lover;"
    ],
    "DOG": [
      "FOODPLATE dog_foodplate;"
    ],
    "MICE": [
      "FOODPLATE mice_foodplate;"
    ],
    "FOODPLATE": [
      "int shit1;",
      "FOOD food;",
      "int shit2;"
    ],

    "SIDEGIRL": [
      "int handA;",
      "FOOD stolen_food;",
      "int handB;"
    ],
    "SIDEDOG": [
      "int footA;",
      "FOODPLATE super_plate;",
      "int footB;"
    ],

    "FOOD": [
      "int carrot;",
      "int cucumber;"
    ],
  },
  #"struct_opts": {}
}

def _form_c_struct_def(structs:List[str], struct_fields:Dict[str, List[str]]):
  buf = ''
  for structname in structs:
    buf += 'struct ' + structname + ' {\n'
    for field in struct_fields[structname]:
      buf += '  '+field+'\n'
    buf += '};\n'
    buf += '\n'
  return buf

def _form_c_text(structs:List[str], struct_fields:Dict[str, List[str]], ret_code:int):
  buf = ''
  buf += _form_c_struct_def(structs, struct_fields)
  buf += f'int main(){{return {ret_code};}}\n'
  return buf

_sd = os.path.dirname(__file__)
_tmpdir = f'{get_tmp_dir()}/test_struct_reorderer'

def _execsrc(title, c_text, exe_expect_ret):
  cpp = f'{_tmpdir}/{title}.cpp'
  exe = f'{_tmpdir}/{title}.exe'
  obj = f'{_tmpdir}/{title}.obj'
  open(cpp, 'w').write(c_text)
  execcmd(f'cl.exe {cpp} /Fo{obj} /Fe{exe}')
  execcmd(exe, expect_ret=exe_expect_ret)


def _test_shuffle_and_reorder():
  ensure_known_shell_program('cl.exe')
  os.makedirs(_tmpdir, exist_ok=True)
  rng = random.Random()# #NonDeterministicTest
  for niter in range(10):

    # Copy existing and shuffle them
    struct_fields = _PIECE_OF_spraytab['struct_fields']
    new_structs = _PIECE_OF_spraytab['structs'].copy()
    rng.shuffle(new_structs)

    # Reorder copied&shuffled
    sr = StructReorderer(new_structs, struct_fields)
    sr.do_reorder()
    print('StructReorderer total swapped:', sr._total_swapped, 'times')
    print(new_structs)
    ret_code = 555189
    c_text = _form_c_text(new_structs, struct_fields, ret_code)
    print(f'Executing cpp program text (retcode will be {ret_code}):')
    print(c_text)
    _execsrc('test_struct_reorderer', c_text, ret_code)


def test_struct_reorderer(argv):
  _test_shuffle_and_reorder()


if __name__ == '__main__':
  test_struct_reorderer(sys.argv[1:])









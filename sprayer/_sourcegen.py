import os, io, sys, random
from typing import List, Dict
from datetime import datetime

from c2.sprayer.ccode.var import Var, VarNameTable, decl_varlist, decl_arglist, ValPrintType
from c2.sprayer.ccode.node import Node
from c2.sprayer.ccode.textualizer import Textualizer

class SourceCode:
  def __init__(self, tabchar='  '):
    self.tabchar = tabchar
    self.gened_code_cpp = None
    self.gened_code_h = None
    self.gened_substitutions_h = None
  def write_to_dir(self, dirpath):
    open(os.path.join(dirpath, 'gened_code.cpp'), 'w').write(self.gened_code_cpp)
    open(os.path.join(dirpath, 'gened_substitutions.h'), 'w').write(self.gened_substitutions_h)
    if self.gened_code_h != None:
      open(os.path.join(dirpath, 'gened_code.h'), 'w').write(self.gened_code_h)

# after __init__, set_defs() must be called
class SourceGen:
  def __init__(self, spraytab, vl_g, orig_idxes, holders, sgheaders_dir, rng):
    self._tabchar = '  '
    self.spraytab = spraytab
    self.vl_g = vl_g
    self.spraytab_procidxes = orig_idxes
    self.with_holders = holders
    self.sgheaders_dir = sgheaders_dir
    self._rng = rng
    self._funcs = []
    self._spraytab_var_lines = None
    self.defs = None
    self._privdefs = None
    self._fixed_var_names = None
    self._zvar_lines = {}
    self._structs = None
    self._struct_fields = None
    self._separate_gened_code_header = True
    self._specific_lines = None
    self._raw_lines = None
    self._lib_lines = None

  def enable_separate_gened_code_header(self, enable:bool):
    self._separate_gened_code_header = enable

  def set_zvar_lines(self, zvar_lines:List[str]):
    self._zvar_lines = zvar_lines

  def set_specific_lines(self, lines:List[str]):
    self._specific_lines = lines

  def set_raw_lines(self, raw_lines:List[str]):
    self._raw_lines = raw_lines

  def set_lib_lines(self, lib_lines:List[str]):
    self._lib_lines = lib_lines

  # dict of dicts (module -> def1:v1,def2:v2, ...; module2 -> def1:v1,...
  # must be called
  def set_defs(self, defs:Dict[str, Dict[str, str]]):
    if self.with_holders:
      define_call = '(*(decltype(F##_ENTRY)*)ObfDecode(F##_ENTRY_Holder))'
    else:
      define_call = 'F##_ENTRY'

    self.defs = {
      type(self).__name__: {
        'C(F)': define_call,
        'noinl': '__declspec(noinline)'
      }
    }
    self.defs = dict(self.defs, **defs)
    self._check_defs()

  def set_fixed_var_names(self, fixed_var_names:dict):
    # fixed_var_names -> {Var( ): 'aaa', ... }
    self._fixed_var_names = fixed_var_names

  def set_spraytab_static_vars_linelist(self, spraytab_static_vars_lines:List[str]):
    # Fix lines: add ; if not. This is to support both variants.
    self._spraytab_var_lines = []
    for line in spraytab_static_vars_lines:
      line = line.rstrip()
      if not line.endswith(';'):
        line = line+';'
      self._spraytab_var_lines.append(line)
    assert(len(self._spraytab_var_lines) == len(spraytab_static_vars_lines))

  def set_structs(self, structs:List[str], struct_fields:Dict[str, List[str]]):
    self._structs = structs
    self._struct_fields = struct_fields

  # privdefs are special part of spraytab
  def set_privdefs(self, privdefs:dict):
    self._privdefs = privdefs

  def allocate_funcs(self, num_funcs):
    self._funcs = [None for _ in range(num_funcs)]

  def set_func(self, nfunc, name, vl_a, vl_l, func:Node): #func->node_stmtlist
    self._funcs[nfunc] = (name, vl_a, vl_l, func)

  def get_funcs(self):
    return self._funcs

  def num_funcs(self):
    return len(self._funcs)

  def gen_src(self, src: SourceCode):
    self._ensure_all_funcs_set()
    fio = io.StringIO()
    if self._separate_gened_code_header:
      self._write_banner(fio)
      self._write_h_cap(fio)
      self._write_privdefs(fio)
      self._write_struct_fowrards(fio)
      self._write_structs(fio)
      self._write_zvars_struct(fio)
      self._write_zvars_hdecl(fio)
      src.gened_code_h = fio.getvalue()
      fio = io.StringIO()
      self._write_banner(fio)
      self._write_cpp_cap(fio)
      self._write_forwards(fio)
      self._write_zvars_cppimpl(fio)
      self._write_gened_static_vars(fio)
      self._write_holders(fio)
      self._write_code(fio)
    else:
      self._write_banner(fio)
      self._write_cpp_cap(fio)
      self._write_privdefs(fio)
      self._write_struct_fowrards(fio)
      self._write_structs(fio)
      self._write_forwards(fio)
      self._write_zvars_struct(fio)
      self._write_zvars_cppimpl(fio)
      self._write_gened_static_vars(fio)
      self._write_holders(fio)
      self._write_code(fio)
    src.gened_code_cpp = fio.getvalue()

    fio = io.StringIO()
    self._write_defs(fio)
    src.gened_substitutions_h = fio.getvalue()


  def _ensure_all_funcs_set(self):
    for nfunc in range(len(self._funcs)):
      if self._funcs[nfunc] == None:
        raise RuntimeError(f'func #{nfunc} is not set')

  def _write_banner(self, fio):
    fio.write(f'// Auto-generated with: {" ".join(sys.argv)} at {str(datetime.now())};\n')

  def _write_h_cap(self, fio):
    fio.write('#pragma once\n\n')
    fio.write('#include "spraygen.h"\n\n')

  def _write_cpp_cap(self, fio):
    if self._separate_gened_code_header:
      fio.write('#include "gened_code.h"\n\n')
    else:
      fio.write(f'#include "spraygen.h"\n\n')

    if self._specific_lines: # None or []
      fio.write('// Specific lines\n')
      for spec_line in self._specific_lines:
        fio.write(spec_line+'\n')
    fio.write('\n')

    if self._raw_lines:
      fio.write('// Raw lines\n')
      for raw_line in self._raw_lines:
        fio.write(raw_line+'\n')
    fio.write('\n')

    if self._lib_lines:
      fio.write('// LIB lines\n')
      for lib_line in self._lib_lines:
        fio.write(lib_line+'\n')
    fio.write('\n')


  def _write_struct_fowrards(self, fio):
    f = fio.write
    if not self._structs:
      return
    f('// Struct forwards\n')
    for structname in self._structs:
      f(f'struct  {structname};\n')
    f('\n')

  def _write_structs(self, fio):
    f = fio.write
    if not self._structs:
      return
    f('// Structs\n')
    for structname in self._structs:
      f(f'struct  {structname} {{\n')
      if self._struct_fields:
        fieldlist = self._struct_fields[structname]
        assert(type(fieldlist) == list)
        for field in fieldlist:
          f(field + '\n')
      f('};\n\n')

  # we call them defs, they call them subs...
  def _write_defs(self, fio):
    f = fio.write
    self._check_defs()
    f(f'// !Autogenerated with {" ".join(sys.argv)} ;\n\n')
    f('\n')
    for k in self.defs.keys():
      f(f'// Module {k}\n')
      for d in self.defs[k].keys():
        v = self.defs[k][d]
        f(f'#define {d} {v}\n')
      f('\n')
    f('\n')

  def _write_forwards(self, fio):
    spraytab = self.spraytab
    f = fio.write
    f('// Forward definitions\n')
    for nfunc in range(len(self._funcs)):
      if nfunc in self.spraytab_procidxes:
        n = self.spraytab_procidxes.index(nfunc)
        fn = self.spraytab['procs'][n]
        is_from_decl = fn in spraytab['proc_opts'] \
                       and 'is_from_decl' in spraytab['proc_opts'][fn]
        if is_from_decl:
          funcdecl = f'{fn}_DECL()'
        else:
          funcdecl = self._get_def_decl(nfunc)
      else:
        funcdecl = self._get_def_decl(nfunc)
      f(f'{funcdecl};\n')
    f('\n')

  def _write_zvars_struct(self, fio):
    f = fio.write
    f('// ZVars\n')
    f('struct ZVARS {\n')
    zvars = []
    if self._zvar_lines:
      zvars += self._zvar_lines
    self._rng.shuffle(zvars)
    for zvarname in zvars:
      f(self._tabchar + zvarname + '\n')
    f('};\n')
    f('\n')

  def _write_zvars_hdecl(self, fio):
    fio.write('extern ZVARS* g_pzvars;\n')
    fio.write('\n')

  def _write_zvars_cppimpl(self, fio):
    fio.write('static ZVARS g_zvars;\n')
    fio.write('ZVARS* g_pzvars = &g_zvars;\n')
    fio.write('\n')

  def _write_gened_static_vars(self, fio):
    # mix real static vars with vl_g
    f = fio.write
    f('// Static vars (mixed)\n')
    vnt = VarNameTable(self.vl_g, None, None, fixed_var_names=self._fixed_var_names)
    vl = []
    if len(self.vl_g):
      vl = decl_varlist(self.vl_g, vnt.names_g, valprn=ValPrintType.WITH_VALUE)
    if self._spraytab_var_lines:
      stvfiltered = [v for v in self._spraytab_var_lines if len(v) and not v.startswith('//')]
      vl += stvfiltered

    self._rng.shuffle(vl)

    for av in vl:
      f(av+'\n')
    f('\n')

  def _write_holders(self, fio):
    f = fio.write
    spraytab = self.spraytab
    if self.with_holders:
      f('// Proc addr holders globals for calls to be indirect\n\n')
      l = 0
      for proc in spraytab['procs']:
        if proc in spraytab['proc_opts'] and 'is_from_decl' in spraytab['proc_opts'][proc]:
          continue  # skip /decl procs in holders
        f(f'decltype(&{proc}_ENTRY)* {proc}_ENTRY_Holder = ObfEncode(&{proc}_ENTRY);\n');
        l += 1
    else:
      #f('// Holders not used\n')
      pass
    f('\n')

  def _write_privdefs(self, fio):
    f = fio.write
    spraytab = self.spraytab
    if self._privdefs:
      f('// Privdefs\n')
      for k in self._privdefs.keys():
        v = self._privdefs[k]
        f(f'#define {k} {v}\n')
    f('\n')

  def _write_code(self, fio):
    f = fio.write
    f('// --- Generated code ---\n\n')
    i = 0
    for tup in self._funcs:
      self._func(fio, i, tup)
      i += 1

  def _get_def_decl(self, nfunc):
    funcname, vl_a, _, _ = self._funcs[nfunc]
    vnt = VarNameTable(None, vl_a, fixed_var_names=self._fixed_var_names)
    argsdecl = ','.join(decl_arglist(vl_a, vnt.names_a))
    return f'static noinl void {funcname}({argsdecl})'

  def _func(self, fio, nfunc, tup):
    f = fio.write
    spraytab = self.spraytab
    _, vl_a, vl_l, func_stmtlist = tup
    vnt = VarNameTable(self.vl_g, vl_a, vl_l, fixed_var_names=self._fixed_var_names) # : need vl_g, cuz stmtlist can reference glob vars
    is_from_decl = False
    if nfunc in self.spraytab_procidxes:
      orig_funcname = self.spraytab['procs'][self.spraytab_procidxes.index(nfunc)]
    else:
      orig_funcname = None
    if orig_funcname != None:
      is_from_decl = orig_funcname in spraytab['proc_opts']\
                     and 'is_from_decl' in spraytab['proc_opts'][orig_funcname]
      if is_from_decl:
        assert(len(vl_a) == 0)
        f(f'// proc from decl entry -- {orig_funcname}_DECL\n')
        f(f'{orig_funcname}_DECL() {{\n')
        f(f'  {orig_funcname}_PRE();\n')
      else:
        f(f'// proc entry -- {orig_funcname}\n')
        f(f'{self._get_def_decl(nfunc)} {{\n')
    else:
      f(f'// generated func {nfunc}\n')
      f(f'{self._get_def_decl(nfunc)} {{\n')

    # loc vars
    locdecl = decl_varlist(vl_l, vnt.names_l, tabs=1, valprn=ValPrintType.WITH_VALUE)
    if locdecl != []:
      f('\n'.join(locdecl))

    texer = Textualizer(vnt.get_var_name)
    texer.tabs = 0 # will be 1 tab because of node_stmtlist

    func_text = texer.visit(func_stmtlist)
    if len(func_text) != 0 and locdecl != []:
      f('\n') # between locvars and code

    f(func_text)

    if is_from_decl:
      f(f'  {orig_funcname}_POST();\n')

    f('}\n\n')


  def _check_defs(self):
    all_keys = []
    for k in self.defs.keys():
      for e in self.defs[k].keys():
        if e in all_keys:
          raise RuntimeError(f'mod {k} def {e} already in table')
        all_keys.append(e)





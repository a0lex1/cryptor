import os,sys, re, jsonschema, copy
from c2.infra.unischema import Unischema, unischema_load, UnischemaException

# this is opt validation for c2/*.opts, validation tests for sprayer is supposed to be in sprayer/test/test_opt_validation.py or something like this


_sd = os.path.dirname(__file__)
_UNI_pay_info = unischema_load(f'{_sd}/../pay_info.UNISCHEMA', None)
_DEFINST_pay_info = _UNI_pay_info.make_default_config()

def _try_field(field_name:str, field_value):
  inst = copy.deepcopy(_DEFINST_pay_info)
  inst[field_name] = field_value
  try:
    _UNI_pay_info.validate_instance(inst)
    return True
  except UnischemaException as e:
    print(f'_try_field: UNEXPECTED UnischemaException: {e}')
    raise RuntimeError('unexpected UnischemaException')
  except jsonschema.exceptions.ValidationError as e:
    #print(f'_try_field: ValidationError: {e}')
    return False


def _test_export_name():
  assert(_try_field('export_name', ''))
  assert(_try_field('export_name', 'a'))
  assert(_try_field('export_name', 'aB'))
  assert(_try_field('export_name', 'aB'))
  assert(_try_field('export_name', 'aB1'))
  assert(_try_field('export_name', '_aB01'))
  assert(not _try_field('export_name', '.'))
  assert(not _try_field('export_name', '..'))
  assert(not _try_field('export_name', '/'))
  assert(not _try_field('export_name', '/a..aE9_.._3/'))
  assert(not _try_field('export_name', 'aaa$a'))
  assert(not _try_field('export_name', 'aa aa')) # e.g. spaces
  assert(not _try_field('export_name', 'aaa!a'))
  assert(not _try_field('export_name', 'aaa#a'))
  assert(not _try_field('export_name', 'aaa@a'))
  assert(not _try_field('export_name', 'aaa.a'))
  assert(not _try_field('export_name', 'aa\\a'))
  assert(not _try_field('export_name', 'aaa/a'))
  assert(not _try_field('export_name', 'aaa`a'))
  assert(not _try_field('export_name', 'aaa a'))
  assert(not _try_field('export_name', 'aaa"a'))
  assert(not _try_field('export_name', 'aaa\'a'))
  assert(not _try_field('export_name', 'x.x'))
  assert(not _try_field('export_name', 'x|x'))


def _test_postfn_rva():
  assert(_try_field('postfn_rva', ''))
  assert(not _try_field('postfn_rva', ' '))
  assert(_try_field('postfn_rva', '1'))
  assert(_try_field('postfn_rva', 'A'))
  assert(_try_field('postfn_rva', '1A'))
  assert(_try_field('postfn_rva', '0x'))
  assert(not _try_field('postfn_rva', '0x1a '))
  assert(not _try_field('postfn_rva', ' 123'))
  assert(not _try_field('postfn_rva', ' 123 '))
  assert(not _try_field('postfn_rva', '1 3'))
  assert(_try_field('postfn_rva', 'fafafafa0xdadada'))
  assert(not _try_field('postfn_rva', '"')) # shellcmd escape #SecurityLogic
  assert(not _try_field('postfn_rva', '\''))
  assert(not _try_field('postfn_rva', '`'))
  assert(not _try_field('postfn_rva', '#'))
  assert(not _try_field('postfn_rva', '='))
  #special cases
  assert(not _try_field('postfn_rva', 'aa"aa')) # shellcmd escape #SecurityLogic
  assert(not _try_field('postfn_rva', 'aa\'aa'))
  assert(not _try_field('postfn_rva', 'aa`aa'))
  assert(not _try_field('postfn_rva', 'aa#aa'))
  assert(not _try_field('postfn_rva', 'aa=aa'))
  assert(not _try_field('postfn_rva', 'a|a'))


# they all now use same 'pattern' in unischema
def _test_args(args_field_name):
  assert(_try_field(args_field_name, ''))  # empty args are ok
  assert(_try_field(args_field_name, '`')) # this is converted to \" because some args need "string"
  assert(_try_field(args_field_name, 'aa`aa'))
  assert(_try_field(args_field_name, 'aa`a`a'))
  assert(_try_field(args_field_name, 'aa``aa'))
  assert(_try_field(args_field_name, '`aaaa'))
  assert(_try_field(args_field_name, '`a`aaa'))
  assert(_try_field(args_field_name, '`aa`'))
  assert(_try_field(args_field_name, '````'))

  assert(_try_field(args_field_name, ' '))
  assert(_try_field(args_field_name, 'a'))
  assert(_try_field(args_field_name, ' a'))
  assert(_try_field(args_field_name, 'a123 '))
  assert(_try_field(args_field_name, 'a, b, c'))
  assert(_try_field(args_field_name, 'const int& abc, int e'))
  assert(_try_field(args_field_name, 'abc()'))
  assert(_try_field(args_field_name, 'abc(,)'))

  assert(not _try_field(args_field_name, '$'))
  assert(not _try_field(args_field_name, '"')) # shellcmd escape #SecurityLogic
  assert(not _try_field(args_field_name, '\''))
  assert(not _try_field(args_field_name, '#'))
  assert(not _try_field(args_field_name, '='))
  # special cases! forget ^..$ in pattern?
  assert(not _try_field(args_field_name, 'aa$aa'))
  assert(not _try_field(args_field_name, 'aa"aa')) # shellcmd escape #SecurityLogic
  assert(not _try_field(args_field_name, 'aa\'aa'))
  assert(not _try_field(args_field_name, 'aa#aa'))
  assert(not _try_field(args_field_name, 'aa=aa'))
  assert(not _try_field(args_field_name, 'a|a'))
  assert(not _try_field(args_field_name, 'FALSE, L""')) # this won't work, use ` character, cool , right?



def _test_all_args():
  _test_args('postfn_decl_args')
  _test_args('postfn_fromdll_call_args')
  _test_args('postfn_fromexe_call_args')
  _test_args('export_decl_args')
  _test_args('export_def_call_args')

def test_opt_validation(argv):
  _test_export_name()
  _test_postfn_rva()
  _test_all_args()

if __name__ == '__main__':
  test_opt_validation(sys.argv[1:])



import jsonschema, json, argparse, sys, os
from pprint import pprint

from c2.infra.jif_resolver import JIFResolver
from c2.infra.jen import jen_type2typcod, jen_value_to_str
from c2.common.schema2instance import schema2instance, SchemaVarInitType
from c2.common.includeable_dict_resolver import IncludeableDictResolver  # only for includeable_unischema_load
from c2.common.jpath import *


class UnischemaException(Exception): pass


class UnischemaExcessiveOpt(UnischemaException): pass


class UnischemaNotAllValuesPresent(UnischemaException): pass


def unischema_load(unischema_path, root_path) -> 'Unischema':
  loader = UnischemaLoader(root_path)
  unidict = loader.load_unischema(unischema_path)
  return Unischema(unidict)


'''

Postulates.

!) Unischema's raw dict is ok to be passed to CLIConfig, look: CC = CLIConfig(UNI_some_thing.schema, ...)
   [1]The schema contains 'default' for some fields and $jXxxTest jcx lists
   All of this stuff is ignored by CLIConfig's add_to_argparser() (it doesn't set default= to argparse's parser). UPD: no more default:, it's now addargument_kwargs; something may have changed
   [2]All $jif`s are combined, all present and available to override

!) In Unischema, $jif must be in $j (the `extra prop`) node. So it's copied to doc when instantiating that schema.
   In doc, it will be just at place, $j is eliminated

!) Reasonable to use Unischema with additionalProperties:false EVERYWHERE, e.g. a fool protection

?) Reasonable to use "minProperties": X to require all properties

!) We defining required opts as opts that don't have default value in unischema
   Those are required to be set by user (through cmdline/file/etc.)
   

Examples (some JSON fields were cut to simplify).

# UNISCHEMA -> INSTANCE(JEN), 'default' is from defkey, (must be already wrapped). Supports $jif
make_dynjen_doc() ->
{'lemon_opts': {'$jif': ['market.fruit', 'lemon'], 'acid': ['$jcb', 'true', 'false']},
 'market': {'amount': ['$jcn', '50', '100'], 'fruit': ['$jcs', 'qiwi', 'orange', 'lemon'], 'recipe': ['$jcs', 'food', 'ice']},
 'qiwi_opts': {'$jif': ['market.fruit', 'qiwi'], 'qiwi_country': ['$jcs', 'africa', 'costarica'], 'qiwi_size': ['$jcn', '10', '20', '30']}}


# Unischema -> INSTANCE(JEN), 'default' is from 'default', wrapped in ['$jcX', ]
make_dynjen_single() ->
{'lemon_opts': {'$jif': ['market.fruit', 'lemon'], 'acid': '<no_default_in_schema>'},
 'market': {'amount': '<no_default_in_schema>', 'fruit': '<no_default_in_schema>', 'recipe': ['$jcs', 'ice']},
 'qiwi_opts': {'$jif': ['market.fruit', 'qiwi'], 'qiwi_country': '<no_default_in_schema>', 'qiwi_size': ['$jcn', '20']}}


# Unischema -> SCHEMA, with NO 'default's AND all types are 'array'. Good for using with CLIConfig
make_jen_schema_for_cli() ->
{'properties': {'lemon_opts': {'$j': {'$jif': ['market.fruit', 'lemon']}, 'properties': {'acid': {'type': 'array'}}, 'type': 'object'},
                'market': {'properties': {'amount': {'type': 'array'}, 'fruit': {'type': 'array'}, 'recipe': {'type': 'array'}}, 'type': 'object'},
                'qiwi_opts': {'$j': {'$jif': ['market.fruit', 'qiwi']}, 'properties': {'qiwi_country': {'type': 'array'}, 'qiwi_size': {'type': 'array'}}, 'type': 'object'}},
 'type': 'object'}


# Unischema -> INSTANCE of document, 'default' is from 'default', not wrapped. Note: supports $jif
# The result has no traits of JEN anymore
make_default_instance() ->
{'lemon_opts': {'acid': '<no_default_in_schema>'}, 'market': {'amount': '<no_default_in_schema>', 'fruit': '<no_default_in_schema>', 'recipe': 'ice'},
 'orange_opts': {'orangeness': '<no_default_in_schema>'},
 'qiwi_opts': {'qiwi_country': '<no_default_in_schema>', 'qiwi_size': 20}}

'''


# Trivial. There is includeable_unischema_load so there is unischema_load which is a highliter. This is NON-includeable load.
# def unischema_load(file_path) -> 'Unischema':
#  return Unischema(json.load(open(file_path, 'r')))


class Unischema:
  DEFKEY = 'default'
  JDEFKEY = '$jdefault'
  EXTRA_PROP_KEY = '$j'

  def __init__(self, schema: dict, all_reqiured_mode=True):
    self.schema = schema
    self.all_required_mode = all_reqiured_mode  # behavior

  def validate_instance(self, inst: dict):
    # additionalProperties
    jsonschema.validate(inst, self.schema)
    # validate $jifs by schema
    self._validate_jif_truthiness_by_schema(inst)
    if self.all_required_mode:
      # presence of all fields are required
      self._validate_all_presence_by_schema(inst)
    # leave old validation too (why not?) however, it is useless in cases where |inst| contains no $jif(s)
    self._validate_jifs(inst)

  # UNISCHEMA -> INSTANCE(JEN), 'default' is from defkey, (must be already wrapped). Supports $jif
  def make_dynjen_doc(self, defkey=JDEFKEY, extra_prop_key=EXTRA_PROP_KEY):
    return self._make_dynjen_worker(defkey, False, extra_prop_key)

  # Unischema -> INSTANCE(JEN), 'default' is from 'default', wrapped in ['$jcX', ]
  def make_dynjen_single(self):
    return self._make_dynjen_worker(defkey='default', wrap_jcxes=True)

  # Unischema -> SCHEMA, with NO 'default's AND all types are 'array'. Good for using with CLIConfig
  def make_jen_schema_for_cli(self):
    jen_cli_schema = {}
    self._mkclischema(self.schema, jen_cli_schema, defkey_to_wrap_jcx=None)
    return jen_cli_schema

  # Instantiate configs with this
  def make_default_config(self) -> dict:
    # $jif(s) will be copied AND THEN resolved so there will be no $jif(s) in output
    return self.make_def_inst(copy_jifs=True, resolve_jifs=True)

  # Generic worker
  # copy_jifs, THEN resolve_jifs (so they're maybe removed)
  def make_def_inst(self, copy_jifs: bool, resolve_jifs: bool, styp=SchemaVarInitType.DefaultValues,
                    resolve_referee_inst=None):
    if resolve_jifs:
      assert (copy_jifs)
    inst = {}
    extra_prop_key = Unischema.EXTRA_PROP_KEY if copy_jifs else None
    schema2instance(styp, self.schema, inst,
                    'default' if styp == SchemaVarInitType.DefaultValues else None,
                    extra_prop_key=extra_prop_key,
                    fn_nodefault_fallback=None  # we need error if no 'default' in some node
                    )
    inst_new = {}
    if resolve_jifs:
      res = JIFResolver()
      rescnts = JIFResolver._ResolveCounters()
      res.resolve_jifs(inst, inst_new, rescnts, resolve_referee_inst)
    else:
      inst_new = inst
    return inst_new

  # Unischema -> INSTANCE of document, values are always null
  # NOT TESTED
  def make_null_instance(self):
    cli_schema = {}
    schema2instance(SchemaVarInitType.NullValues, self.schema, cli_schema, None, '$j')
    return cli_schema

  # Ensures every $jif ($jif(s) are from scheme, not from inst) is True
  # jif_schema_validator.py=>
  def _validate_jif_truthiness_by_schema(self, inst):
    # if |inst| does not have $jifs, we don't care cuz |self.schema| does
    # we

    paths_schema_keys, paths_inst_keys, paths_inst_values = [], [], []
    jpath_enum_l(self.schema, paths_schema_keys, JPathEnumFlag.ENUM_SUBKEYS)
    jpath_enum_l(inst, paths_inst_keys, JPathEnumFlag.ENUM_SUBKEYS)
    jpath_enum_l(inst, paths_inst_values, JPathEnumFlag.ENUM_VALUES)

    for inst_path in paths_inst_keys:
      _schema_path_for_inst = []
      for path_elem in inst_path:
        _schema_path_for_inst += ['properties', path_elem]
      jif_path_to_try = _schema_path_for_inst + ['$j', '$jif']  # possible path in schema

      try:
        jif_cond_node = jpath_get_l(self.schema, jif_path_to_try)
      except JPathKeyNotFound as e:
        continue
      # JIF node exists. Process it.
      assert (type(jif_cond_node) == list and len(jif_cond_node) == 2)
      comparand_path, comparand_value = jif_cond_node
      current_value = jpath_get_s(inst, comparand_path)
      if comparand_value != current_value:
        raise UnischemaExcessiveOpt(
          f'the presence of {".".join(inst_path)} requires field {comparand_path} to be `{comparand_value}`, but now it\'s `{current_value}`')

      pass

  def _validate_all_presence_by_schema(self, inst):
    # Make stencil for validating - an instance initialized with Nones, containing ALL POSSIBLE fields from schema,
    # except whose $jif(s) are False.
    def_inst = self.make_def_inst(copy_jifs=True, resolve_jifs=True, styp=SchemaVarInitType.NullValues,
                                  resolve_referee_inst=inst)
    required_paths = []
    jpath_enum_s(def_inst, required_paths, JPathEnumFlag.ENUM_VALUES)
    not_found_paths = []
    for required_path in required_paths:
      try:
        v = jpath_get_s(inst, required_path)
      except JPathKeyNotFound as e:
        not_found_paths.append(required_path)
    if len(not_found_paths):
      print('Unischema: not found paths:', not_found_paths)
      raise UnischemaNotAllValuesPresent(f'the instance lacks of options - {not_found_paths}')
    pass

  # obsolete by _validate_jifs_by_schema TODO: REMOVE
  def _validate_jifs(self, inst: dict):
    jr = JIFResolver()
    new_inst = {}
    rescnts = JIFResolver._ResolveCounters()
    jr.resolve_jifs(inst, new_inst, rescnts)
    if rescnts.nnotfound != 0:
      raise RuntimeError('inst has UNKNOWN $jif(s)')
    if rescnts.nfoundneq != 0:
      raise RuntimeError('inst has KNOWN, BUT NOT-EQ $jif(s)')
    pass

  # generic make dynjen proc, either default+wrap or jdefault
  def _make_dynjen_worker(self, defkey=JDEFKEY, wrap_jcxes=False, extra_prop_key=EXTRA_PROP_KEY):
    # func for wrapping default value in [$jcX, <this value>]
    def convert_value(typ, val):
      c = jen_type2typcod[typ]
      # If we just str(val), then in case of bool, False will be 'False' and this is wrong.
      # We need to convert properly with jen_value_to_str()
      x = jen_value_to_str(val)
      return [f'$jc{c}', x]

    fn_convertvalue = convert_value if wrap_jcxes else None
    fn_nodefault_fallback = lambda node: node['default'] if 'default' in node else '<NO_DEFAULT_IN_SCHEMA>'
    jendoc = {}
    schema2instance(SchemaVarInitType.DefaultValues, self.schema, jendoc,
                    defkey,
                    extra_prop_key,
                    fn_convertvalue=fn_convertvalue,
                    fn_nodefault_fallback=fn_nodefault_fallback)
    return jendoc

  # This func is now internal. defkey_to_wrap_jcx is passed None. However it's still can be used for wrapping single value with jcx.
  # Copies $jif and other fields to destination too.
  # If defkey_to_wrap_jcx not None and it's not found, ['$jcs' 'None'] is placed.
  #
  def _mkclischema(self, in_schema: dict, out_schema: dict, defkey_to_wrap_jcx=None, type2typcod=None):
    _RECURSE = self._mkclischema
    if type2typcod == None:
      type2typcod = jen_type2typcod

    for in_key in in_schema.keys():
      in_val = in_schema[in_key]
      if type(in_val) == dict:
        if 'type' in in_val and in_val['type'] in type2typcod:
          # known type for jen
          if defkey_to_wrap_jcx:
            defval = in_val[defkey_to_wrap_jcx] if defkey_to_wrap_jcx in in_val else None
            tc = type2typcod[in_val['type']]
            defval2 = defval
            if type(defval) != str:
              defval2 = str(defval)
            defval_jc_list = [f'$jc{tc}', defval2, ]
            out_schema[in_key] = {"type": "array", "default": defval_jc_list}

          else:

            out_schema[in_key] = {"type": "array"}

          continue

        else:
          # unknown type for jen
          out_val = {}
          out_schema[in_key] = out_val
          _RECURSE(in_val, out_val, defkey_to_wrap_jcx, type2typcod)
      else:
        # in_val is not dict, just copy it
        out_schema[in_key] = in_val
    return


class UnischemaLoader:
  def __init__(self, root_path):
    self.root_path = root_path
    self._dic_copy = None

  # Important: returns dict (unischema's carrier dict), not instance of class Unischema. Construct your class Unischema instance yourself with that dict. Unischema is enough to be described by just dict
  def load_unischema(self, file_path: str) -> dict:
    return self.load_unischema_from_dict(json.load(open(file_path, 'r')))

  # |dic| is not changed, but copied
  def load_unischema_from_dict(self, dic: dict) -> dict:
    # 1. why copy dic? cuz it will be changed
    # 2. why to save to _dic_copy? cuz _dictresolver_copy_cbk needs access to it
    self._dic_copy = copy.deepcopy(dic)
    dictres = IncludeableDictResolver(self._dic_copy, self.root_path, self._fn_afterload)
    while True:
      n = dictres.resolve_once()
      if n == 0:
        break
      # pprint(dictres.subject)
    self._dic_copy = None  # clear
    return dictres.subject

  def _fn_afterload(self, jpath_l, node):
    # Fix $jif(s) - convert jpaths in $jif(s) to absolute (append |jpath_l| at the beginning)
    self._fix_jifs(jpath_l, node)

  # Separate class jif fixer
  def _fix_jifs(self, jpath_l, node):
    _RECURSE = self._fix_jifs
    for key in node.keys():
      value = node[key]
      if type(value) == dict:
        if '$j' in value:
          if '$jif' in value['$j']:
            jifnode = value['$j']['$jif']
            assert (type(jifnode) == list and len(jifnode) == 2 and type(jifnode[0]) == str)
            # at beginning, append current path as string joined by '.' (standard JPath syntax)

            # We're visiting schema, not instance. So our paths contains '.properties.' elements
            # But we need to fix instance paths, not schema paths
            # Therefore from 'properties.xxx.properties.yyy...' we need to callect only 'xxx.yyy'
            assert (len(jpath_l) % 2 == 0)
            inst_path = [jpath_l[i] for i in range(1, len(jpath_l), 2)]

            jifnode[0] = '.'.join(inst_path) + '.' + jifnode[0]
            # only for test. must ALWAYS succeed because unischema always has all the opts, including conditional opts ($jif(s)-ed nodes)
            # print(jifnode[0])
            # _v = jpath_get_l(self._dic_copy, jpath_l)
            pass

        _RECURSE(jpath_l, value)
      else:
        # no interest in values
        pass


def _main():
  if len(sys.argv) != 3:
    print('Usage: prog <your.UNISCHEMA> <root_path>')
    exit(1)
  u = unischema_load(sys.argv[1], sys.argv[2])
  inst = u.make_default_config()
  pprint(inst)


if __name__ == '__main__':
  _main()

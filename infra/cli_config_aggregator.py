import argparse, json, os, sys, copy
from collections import namedtuple, OrderedDict
from indexed import IndexedOrderedDict

from c2.common.iteration_generator import IterationGeneratorPositional, IterationGeneratorDiagonal
from c2.infra.cli_config import CLIConfig
from c2.infra.jif_resolver import JIFResolver
from c2.infra.unischema import Unischema
from c2.common.jpath import *
from c2.common.get_schema_props import get_schema_props


class CLIConfigAggregatorException(Exception): pass

# Mechanism:
# Pass opts through CLI. When set back, apply resolve_jifs to remove nodes with $jif(s)=FALSE and save it to self._cfg_dicts
# Manages  --{id}_jen_order, --{id}_jen_diagonal, --{id}_jen_reverse, --{id}_single  modes
#
class CLIConfigAggregator:
  _Record = namedtuple('Record', ['unischema', 'is_required', 'jen_tag']) # example records =>
  #             Unischema(crp_opts.UNISCHEMA)  False          crp_opts
  #             Unischema(rnd_opts.UNISCHEMA)  False          rnd_opts

  def __init__(self):
    self._records = OrderedDict()
    self._cliconfs = {} # { 'opts1': CLIConfig(...), } # (values are objects of class CLIConfig)
    self._cfg_dicts = {} # { 'opts1': {...}, }
    self._jen_orders = {} # { 'opts1': ['root','field'], }
    self._jen_isdiagonals = {} # { 'opts1': False, }  # mutually exclusive with _jen_orders (Jen design)
    self._jen_isreverses = {} # { 'opts1': True, } # reverse values, not fields

  # unischema_file -> path/to/your.UNISCHEMA
  # jen_tag ENABLES JEN mode
  # in non-gen mode, unischema MUST contain default: values (the RULE of class CLIConfigAggregator)
  # is_required seems not to be used anywhere yet; we're keeping this mechanism for it's happiness in future
  def add_config(self, id:str, u:Unischema, is_required=False, jen_tag:str=None):
    #assert(len(self._records) == len(self._cliconfs))#not anymore
    #assert((not id in self._records and not id in self._cliconfs or (id in self._records and id in self._cliconfs))) # if not already added (+sanity check) / bad case if already added (+sanity check)#not anymore
    if id in self._records:
      raise CLIConfigAggregatorException(f'config with id {id} is already added')
    self._records[id] = CLIConfigAggregator._Record(u, is_required, jen_tag)

    if jen_tag != None:
      schema_for_cli = u.make_jen_schema_for_cli()
    else:
      # TODO: #AggregatorJen Question: Really? Maybe schema_for_cli = u.make_xxxx_() ?
      schema_for_cli = u.schema
    cc = CLIConfig(schema_for_cli, id, use_filearg_prefix=True)

    self._cliconfs[id] = cc
    # don't set default config to cc, set it later, so we can choose: if |single|, make_dynjen_single(), otherwise, make_dynjen_doc()
    pass

  def add_to_argparser(self, parser:argparse.ArgumentParser):
    #if self._
    for id in self.config_ids():
      rec = self._records[id]
      cc = self._cliconfs[id]
      cc.add_to_argparser(parser, rec.is_required)
      if rec.jen_tag:
        _group = parser.add_mutually_exclusive_group(required=False)
        _group.add_argument(f'--{id}_jen_order', nargs='*', action='append', required=False)
        _group.add_argument(f'--{id}_jen_diagonal', action='store_true')
        parser.add_argument(f'--{id}_jen_reverse', action='store_true', help=f'Reversed JEN value order (value, not field order which is controlled by {id}_jen_order!)')
        parser.add_argument(f'--{id}_single', action='store_true', help='Single JEN mode for better control (use `default:` from unischema)')

  def set_parsed_args(self, args):
    for id in self.config_ids():
      cfg_rec = self._records[id]
      cfg_cliconf = self._cliconfs[id]

      _s_jo = f'{id}_jen_order'
      _s_jd = f'{id}_jen_diagonal'
      _s_jr = f'{id}_jen_reverse'
      _s_si = f'{id}_single'
      jen_order = []
      jen_diagonal = False
      jen_reverse = False
      single = False

      if _s_jo in args.__dict__ and args.__dict__[_s_jo] != None: # seems these two are both required conds
        jen_order = sum(args.__dict__[_s_jo], [])

      if _s_jd in args.__dict__ and args.__dict__[_s_jd] != None:
        jen_diagonal = args.__dict__[_s_jd]
        assert(type(jen_diagonal) == bool)

      if _s_jr in args.__dict__ and args.__dict__[_s_jr] != None:
        jen_reverse = args.__dict__[_s_jr]
        assert(type(jen_reverse) == bool)

      if _s_si in args.__dict__ and args.__dict__[_s_si] != None:
        single = args.__dict__[_s_si]


      self._check_jen_order(cfg_rec.unischema, jen_order)

      self._jen_orders[id] = jen_order
      self._jen_isdiagonals[id] = jen_diagonal
      self._jen_isreverses[id] = jen_reverse

      # 1) set default config
      if cfg_rec.jen_tag:
        if single:
          # JEN MODE - SINGLE
          def_conf = cfg_rec.unischema.make_dynjen_single()
        else:
          # JEN MODE
          def_conf = cfg_rec.unischema.make_dynjen_doc(defkey=cfg_rec.jen_tag)
        cfg_cliconf.set_jen_conf(def_conf)
      else:
        # STANDARD (NON-JEN) MODE
        if single:
          raise RuntimeError('JEN order can\'t be combined with SINGLE mode by design')
        def_conf = cfg_rec.unischema.make_def_inst(copy_jifs=True, resolve_jifs=False)
        # #CLIConfigOptionalRequiedOpts. Don't validate because some opts can be None, due to a lack of the default value in schema.
        # These ops are called "required"
        cfg_cliconf.set_conf(def_conf, no_validate=True)

      # 2) set parsed args and apply file, then cmdline
      cfg_cliconf.set_parsed_args(args) #TODO: cfg_cliconf.set_parsed_args(ParsedArgsFrom(args, mentioned_args))
      cfg_cliconf.apply_file_conf()
      cfg_cliconf.apply_cmdline()

      # 3) remove $jif(s) that have false conds
      jif_resolver = JIFResolver()
      new_conf = {}
      jif_resolver.resolve_jifs(cfg_cliconf.conf(), new_conf, resolve_counters=None)

      # 3.5) #CLIConfigOptionalRequiedOpts
      # check if all "required" options are specified in cmdline ("required" = has no default value in schema)
      self._ensure_required_opts_present(new_conf)

      # 4) [if not jen mode] now, after we removed $jif(s) with false conds, we can validate; JENs can't be validated, cuz their fields have arrays, not normal values
      if not cfg_rec.jen_tag:
        cfg_rec.unischema.validate_instance(new_conf)

      # 5) save this new conf
      self._cfg_dicts[id] = new_conf

    assert(len(self._records) == len(self._cliconfs))
    assert(len(self._records) == len(self._cfg_dicts))
    return


  def config_ids(self):
    return self._records.keys()

  def config(self, id) -> dict:
    #return self._cliconfs[id].conf() #< this is now the underlying confs. they were used to form our final self._cfg_dicts
    return self._cfg_dicts[id]

  def get_unischema(self, id) -> Unischema:
    return self._records[id].unischema

  ### for jen mode (if jen_tag)
  def get_jen_order(self, id:str) -> List[str]:
    return self._jen_orders[id]

  def is_diagonal_jen(self, id:str) -> bool:
    return self._jen_isdiagonals[id]

  def is_reverse_jen(self, id:str) -> bool:
    return self._jen_isreverses[id]

  def get_jen_itergen_class(self, id:str):
    assert(self._records[id].jen_tag)
    if self.is_diagonal_jen(id):
      return IterationGeneratorDiagonal
    else:
      return IterationGeneratorPositional


  def _ensure_required_opts_present(self, conf):
    paths = []
    jpath_enum_s(conf, paths, JPathEnumFlag.ENUM_VALUES)
    unresolved_opts = []
    for path in paths:
      v = jpath_get_s(conf, path)
      if v == None:
        unresolved_opts.append(path)
    if len(unresolved_opts):
      raise RuntimeError(f'Required opt(s) not present: {unresolved_opts=}')


  def _check_jen_order(self, unischema:Unischema, jen_order:List[str]):
    # To ensure path is present in schema, get schema props and ensure every jen_order item is present in those props
    schema_props = IndexedOrderedDict()
    get_schema_props(unischema.schema, schema_props, '.')
    for path in jen_order:
      if not path in schema_props:
        print('*** schema props:')
        print(schema_props)
        raise RuntimeError(f'Json path {path} not in schema props')





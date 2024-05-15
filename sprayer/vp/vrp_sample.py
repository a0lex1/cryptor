import os, random
from typing import List
from collections import deque #CircularBuffer #RingBuffer

from c2.sprayer.vp.vrpicker_factory import create_vrpicker_factory
from c2.sprayer.vp.vrpicker import UsePurpose
from c2.sprayer.vp.vls_shape import vls_shape_from_vls
from c2.sprayer.vp.stock import STOCK_vls1_vls, STOCK_vls2_vls
from c2.sprayer.ccode.var import *
from c2.infra.tool_cli import ToolCLI
from c2.infra.unischema import unischema_load
from c2.infra.cli_seed import CLISeed, DEFAULT_SEED_SIZE, textualize_seed
from c2.infra.seed_get_or_generate import seed_get_or_generate

_sd = os.path.dirname(__file__)
_inclroot = _sd+'/../..'


class VRPSample(ToolCLI):
  def _initialize(self):
    self._progname = os.path.basename(__file__)
    self.__cmd_table = {
      'c': (self.__dispcmd_clear, 'clear the state'),
      'hi': (self.__dispcmd_hist, 'show cmd history'),
      'p': (self.__dispcmd_print, 'print the state'),
      'q': (self.__dispcmd_quit, 'quit program'),

      'r': (self.__dispcmd_read, 'read byte(s); syntax: r 15'), # byte-level
      'w': (self.__dispcmd_write, 'write byte(s); syntax: w 5'),
      'rw': (self.__dispcmd_readwrite, 'readwrite byte(s); syntax: readwrite 15'),

      'rr': (self.__dispcmd_read_items, 'read items: syntax: read 2'), # item-level
      'ww': (self.__dispcmd_write_items, 'write items; syntax: write 2'),
      'rwrw': (self.__dispcmd_readwrite_items, 'readwrite items; syntax: readwrite 2'),

      #aux cmds
      'rep': (self.__dispcmd_rep, 'repeat (all|recent B) cmds A times; syntax: readwrite <A> [B]'),
    }
    self.__cmd_history = deque(maxlen=1024) # [, 'cmdY', 'cmdZ', 'most_recent_cmd']

  def _notes(self) -> List[str]:
    return self.__make_cmd_descr_help_list()
  def __make_cmd_descr_help_list(self):
    help_list = []
    for cmd_name in self.__cmd_table.keys():
      help_list.append(f'{cmd_name} - {self.__cmd_table[cmd_name][1]}')
    return help_list

  def _setup_args(self):
    self.__cli_seed = CLISeed(os.getcwd(), DEFAULT_SEED_SIZE)
    self._add_arg_processor(self.__cli_seed)
    # add configs for all types of vrpicker that factory supports
    self._agr.add_config('seqbased', unischema_load(_sd+f'/seqbased_opts.UNISCHEMA', _inclroot))
    self._agr.add_config('insular', unischema_load(_sd+f'/insular_opts.UNISCHEMA', _inclroot))
    parser = self._parser
    parser.add_argument('-p', '--picker', choices=['seqbased', 'insular'], required='true')
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument('-c', '--cmds', type=str, help='cmds delimited by ;')
    g.add_argument('-i', '--stdin', action='store_true', help='cmds from stdin')
    parser.add_argument('--vls', default='2', choices=['1', '2'])

  def _do_work(self):
    args = self._args
    if args.cmds:
      cmd_list = [c.strip() for c in args.cmds.split(';')]
    else:
      assert (args.stdin == True)
      cmd_list = None
    self.__create_rng()
    self.__recreate_objects()
    if args.stdin:
      print('reading commands from stdin')
    while not self.__quit:
      if cmd_list != None:
        if len(cmd_list) == 0:
          print('all --cmds executed, exiting')
          break
        input_line = cmd_list.pop(0)
      else:
        assert (args.stdin == True)
        input_line = sys.stdin.readline()
      input_line = input_line.rstrip()
      cmds = input_line.split(';')
      for cmd in cmds:
        if cmd == '':
          print('(empty command)')
          continue
        cmdparts = cmd.split(' ')
        cmdname = cmdparts[0]
        if not cmdname in self.__cmd_table:
          raise RuntimeError(f'{cmdname=} not in cmd_table')
        print('*** executing cmd:', cmdname, ' '.join(cmdparts[1:]))
        self.__exec_cmd(cmdname, cmdparts[1:])
        pass
    if len(cmd_list) != 0:
      print('quit, but some command(s) left')
    return

  #-----------------------------------------------------------------------------------
  def __create_rng(self):
    seed = seed_get_or_generate(self.__cli_seed, DEFAULT_SEED_SIZE)
    print(f'VRPSample: using seed: {textualize_seed(seed)}')
    self.__rng = random.Random(seed)

  def __recreate_objects(self):
    args = self._args
    fac = create_vrpicker_factory(args.picker)

    if args.vls == '1':
      self.__vls = STOCK_vls1_vls
    elif args.vls == '2':
      self.__vls = STOCK_vls2_vls
    else: raise
    vls_shape = vls_shape_from_vls(self.__vls)

    self.__state = fac.create_vrpicker_state(vls_shape)
    self.__state_printer = fac.create_vrpicker_state_printer()
    self.__vrpicker = fac.create_vrpicker(self.__vls,
                                          self.__state,
                                          self._agr.config(args.picker),
                                          self.__rng)
    self.__vrpicker.set_logfn(lambda msg: print('(log) '+msg))
    #self.__vrpicker.set_fn_isgood()
    self.__quit = False

  def __exec_cmd(self, cmdname, cmdargs, dont_add_to_history=False):
    dispfn, _help_text = self.__cmd_table[cmdname]
    dont_add2 = dispfn(cmdargs)
    if not dont_add2 and not dont_add_to_history:
      self.__cmd_history.append((cmdname, cmdargs))

  #-----------------------------------------------------------------------------------
  def __dispcmd_quit(self, argv):
    print('setting quit=True')
    self.__quit = True

  def __dispcmd_clear(self, argv):
    self.__recreate_objects()

  def __dispcmd_hist(self, argv):
    print(self.__cmd_history)

  def __dispcmd_print(self, argv):
    self.__state_printer.set_enable_debug_layers('-d' in argv)
    self.__state_printer.print(self.__state, sys.stdout, self.__vls)
    sys.stdout.write('='*180+'\n\n')
    sys.stdout.flush()

  #---------- byte-level -------------------------------

  # worker
  def __generic_readwrite(self, use_purpose, byte_count, item_count, dont_commit:bool=False,
                          new_marker_value=None):
    assert((byte_count == None and type(item_count) == int) or (type(byte_count) == int and item_count == None))
    rl = self.__vrpicker.pick_value_range(use_purpose, byte_count, item_count)
    print(f'picked {rl.byte_count()} bytes ({rl.value_count()} items) of type {rl.value_type().name}'
          f' for {use_purpose.name}: [{rl.idx_vl}][{rl.idx_var}][{rl.idx_val}..{rl.last_value_index()}]')
    if new_marker_value:
      vls[rl.idx_vl][rl.idx_var].values[rl.idx_val:rl.last_value_index() + 1] = new_marker_value
    if not dont_commit:
      self.__vrpicker.commit_picked_value_range(use_purpose, rl)

  def __dispcmd_read(self, argv):
    assert(len(argv) == 1)
    byte_count = int(argv[0])
    self.__generic_readwrite(UsePurpose.READ, byte_count, None)

  def __dispcmd_write(self, argv):
    assert(len(argv) == 1)
    byte_count = int(argv[0])
    self.__generic_readwrite(UsePurpose.WRITE, byte_count, None)

  def __dispcmd_readwrite(self, argv):
    raise RuntimeError('TODO: what does inout/readwrite things do?')

  #---------- item-level -------------------------------
  def __dispcmd_read_items(self, argv):
    assert(len(argv) == 1)
    item_count = int(argv[0])
    self.__generic_readwrite(UsePurpose.READ, None, item_count)

  def __dispcmd_write_items(self, argv):
    assert(len(argv) == 1)
    item_count = int(argv[0])
    self.__generic_readwrite(UsePurpose.WRITE, item_count, None)

  def __dispcmd_readwrite_items(self, argv):
    raise RuntimeError('TODO: what does inout/readwrite things do?')

  #---------- aux cmds -------------------------------
  def __dispcmd_rep(self, argv):
    # rep <REP_COUNT> [CMD_COUNT]
    assert(len(argv) == 1 or len(argv) == 2)
    if len(argv) == 1:
      times = int(argv[0])
      cmd_count = len(self.__cmd_history)
    elif len(argv) == 2:
      times = int(argv[0])
      cmd_count = int(argv[1])
      if cmd_count > len(self.__cmd_history):
        cmd_count = len(self.__cmd_history)
    else:
      raise RuntimeError('need 1 or 2 args')
    print(f'******executing most RECENT {cmd_count} cmds {times} times:', self.__cmd_history)
    for ntime in range(times):
      for ncmd in range(cmd_count):
        cmdname, cmdargs = self.__cmd_history[ncmd]
        self.__exec_cmd(cmdname, cmdargs, dont_add_to_history=True)
    print(f'******rep: DONE; all {cmd_count} commands executed {times} times')
    return True # don't add to history

  #-----------------------------------------------------------------------------------


if __name__ == '__main__':
  VRPSample(sys.argv[1:]).execute()


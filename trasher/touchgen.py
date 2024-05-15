import argparse, random, re, fnmatch, os, sys
from typing import List
from pprint import pprint

from sortedcollections import OrderedSet

from c2.trasher.touch_collector import TouchCollector
from c2.sprayer.ctools.macro_follower import MacroFollower
from c2._internal_config import get_touchprj_dir
from c2.infra.cli_seed import CLISeed, DEFAULT_SEED_SIZE, textualize_seed
from c2.infra.seed_get_or_generate import seed_get_or_generate
from c2.common.sx import Sx

_sd = os.path.dirname(__file__)


class TouchgenPicker:
  #UPD: Probably, no. A class that generates rubishes (probably class ProtographGen) will
  #     aggregate TouchgenPicker, keeping repository picking opts private.
  # Introduce touchrep:
  #def __init__(self, num_mods_sx, num_funcs_sx,
  #             touchrep:TouchProjectRepository, touchprjs_masks):
  #  self._touchrep = touchrep
  #  self._touchprj_masks = touchprjs_masks

  # num_mods_sx, num_funcs_sx can  accepts None, in this case, all mods/funcs are used
  def __init__(self, num_mods_sx:str, num_funcs_sx:str, rng, touchprj_dir=None, control_chars='#!'):
    self.num_mods_sx = num_mods_sx
    self.num_funcs_sx = num_funcs_sx
    self._rng = rng
    self._touchprj_dir = touchprj_dir if touchprj_dir else get_touchprj_dir()
    self._control_chars = control_chars

    self.piece = None # output, { 'headers': [], 'libs': {'a','b', }, 'lines': {'a','b', } }

  # static
  def enumerate_modules(touchprj_dir=None):
    tprjdir = touchprj_dir if touchprj_dir else get_touchprj_dir()
    src_dir = f'{tprjdir}/src'
    files = os.listdir(src_dir)
    ret_files = []
    for file in files:
      m = re.match('^mod_(.+?)\.cpp$', file)
      if m:
        ret_files.append(m[0])
    return ret_files

  # the result is in self.piece
  def pick(self):
    # TODO: delete duplicated headers and libs (convert to uppercase)
    self.piece = {}
    self.piece['lines'] = []
    self.piece['headers'] = OrderedSet()
    self.piece['libs'] = OrderedSet()

    src_dir = f'{self._touchprj_dir}/src'
    files = os.listdir(src_dir)
    files2 = [file for file in files if fnmatch.fnmatch(file, 'mod_*.cpp')]
    if self.num_mods_sx != None:
      num_mods = Sx(self.num_mods_sx, self._rng).make_number()
    else:
      num_mods = len(files2)
    if num_mods == 0:
      # don't feed k=0 to _rng.choices(), this would produce an error
      return

    # Don't do this, it returns duplicates:
    #picked_files = self._rng.choices(files2, k=min(num_mods, len(files2)))

    picked_files = [file for file in files2] # copy for shuffling
    self._rng.shuffle(picked_files) # shuffle
    picked_files = picked_files[:num_mods] # and then get only first |num_mods| elements
    print(f'TouchgenPicker: {picked_files=} ({files2=})  {num_mods=}')
    for file in picked_files:
      with open(f'{src_dir}/{file}') as f:

        collector = TouchCollector(MacroFollower(), self._control_chars)
        collector.initialize()

        for line in f.readlines():
          collector.input_line(line)

        # get only some random lines from touchlist
        if self.num_funcs_sx != None:
          num_funcs = Sx(self.num_funcs_sx, self._rng).make_number()
        else:
          num_funcs = len(collector.cur_touchlist)
        # Note: modifying collector's cur_touchlist
        self._rng.shuffle(collector.cur_touchlist)
        self.piece['lines'] += collector.cur_touchlist[:num_funcs]

        self.piece['headers'] |= collector.cur_extra_headers
        self.piece['libs'] |= collector.cur_extra_libs

        print(f'TouchgenPicker: added  {len(collector.cur_touchlist)} touches, {len(collector.cur_extra_headers)} hdrs, {len(collector.cur_extra_libs)} libs')


def touchgen_main(argv):
  parser = argparse.ArgumentParser(os.path.basename(__file__))
  parser.add_argument('-m', '--num_mods_sx', required=True)
  parser.add_argument('-f', '--num_funcs_sx', required=True)
  cli_seed = CLISeed(os.getcwd(), DEFAULT_SEED_SIZE)
  cli_seed.add_to_argparser(parser)
  args = parser.parse_args(argv)
  cli_seed.set_parsed_args(args)
  seed = seed_get_or_generate(cli_seed, DEFAULT_SEED_SIZE)
  print(f'touchgen_main() using seed {textualize_seed(seed)}')
  rng = random.Random(seed)
  picker = TouchgenPicker(args.num_mods_sx, args.num_funcs_sx, rng)
  picker.pick()
  pprint(picker.piece)


if __name__ == '__main__':
  touchgen_main(sys.argv[1:])



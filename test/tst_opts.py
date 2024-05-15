import os, argparse, sys
from dataclasses import dataclass
from typing import List

from c2._internal_config import get_tmp_dir
from c2.infra.cli_config_aggregator import CLIConfigAggregator
from c2.infra.unischema import unischema_load
from c2.infra.parse_worker import parse_worker

_sd = os.path.dirname(__file__)
_inclroot = f'{_sd}/..'
_u_tst_opts = unischema_load(f'{_sd}/tst_opts.UNISCHEMA', _inclroot)


@dataclass
class TstOpts:
  # raw dict
  tst_opts: dict = None
  # parsed values for some fields
  worker_index = None
  worker_count = None

  def from_argv(self, argv:List[str], allow_unknown=True, conf_id='tst'):
    agr = CLIConfigAggregator()
    agr.add_config(conf_id, _u_tst_opts)

    # allow_abbrev - don't consume, read python docs, IDK
    parser = argparse.ArgumentParser('tst_opts.py', allow_abbrev=False, add_help=False)
    agr.add_to_argparser(parser)

    if allow_unknown:
      args = parser.parse_known_args(argv)[0] # the [1] of the tuple is the rest (unknown)
    else:
      args = parser.parse_args(argv)

    agr.set_parsed_args(args)
    self.tst_opts = agr.config(conf_id)
    if self.tst_opts['worker'] != '':
      self.worker_index, self.worker_count = parse_worker(self.tst_opts['worker'])
    return self


def tmp_dir_from_tst_argv(tst_argv:List[str], allow_unknown=True, conf_id='tst'):
  tstopts = TstOpts().from_argv(tst_argv, allow_unknown, conf_id)
  _s = ''
  if tstopts.worker_index != None:
    _s = str(tstopts.worker_index)
  tmpdir = f'{get_tmp_dir()}{_s}'
  return tmpdir



def _test():
  tstopts = TstOpts().from_argv(['--tst_limit', '5', '--tst_worker', '2/7'])
  tstopts = TstOpts().from_argv(['--tst_limit', '5', '--UNKNOWN_FUCKING_OPTION']) # should be ok, cuz allow_unknown=True


def test_tst_opts(argv):
  _test()

if __name__ == '__main__':
  test_tst_opts(sys.argv[1:])


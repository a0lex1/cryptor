# This is a test for CLIConfigAggregator in JEN mode
import sys
from c2.infra.test_cli_config_aggregator import CliConfigAggregatorTestBase
from c2.infra.unischema import Unischema
from c2.infra.dyn_jen import DynJen

# --bills_personalities_spiderman SomeName
_UNI_bills = {
  'type': 'object',
  'properties': {
    'firstname': {'type':'string', 'default': 'aaa', '$jStupidTest': ['$jcs', 'max', 'dan', 'nico']},
    'personalities': {
      'type': 'object',
      'properties': {
        'code': {'type':'number', 'default': 25, '$jStupidTest': ['$jcn', '100', '500', '750']},
      }
    }
  }
}
# -- 123456
_UNI_checks = {
  'type': 'object',
  'properties': {
    'infoline': {'type':'string', 'default': 'myinfo', '$jStupidTest': ['$jcs', 'my1info', 'my2info']},
    'extrashit': {
      'type': 'object',
      'properties': {
        'extra1': {'type':'string', 'default':'goodguy','$jStupidTest': ['$jcs', 'e1', 'e2']},
      }
    }
  }
}

# Jerome is a guy that works with JEN
class _JeromeTest(CliConfigAggregatorTestBase):
  def execute(self, argv):
    self.aggregator.add_config('bills', Unischema(_UNI_bills), jen_tag='$jStupidTest')
    self.aggregator.add_config('checks', Unischema(_UNI_checks), jen_tag='$jStupidTest')
    self.parser.add_argument('--another_super_argument', type=int)
    self.aggregator.add_to_argparser(self.parser)
    args = self.parser.parse_args(argv)
    self.aggregator.set_parsed_args(args)


def _test_with_jen():
  # not testing overriding opts from file
  test = _JeromeTest()
  test.execute(['--bills_jen_order', 'personalities.code', 'firstname']) # use order for fun and profit
  test.print_fields()
  print(test.as_checkbook())
  #assert(not 'no. must be specific JEN things here.')
  dj = DynJen(test.aggregator.config('bills'), test.aggregator.get_jen_order('bills'))
  insts = []
  for inst in dj:
    print(inst)
    insts.append(inst)
  assert(insts == [{'firstname': 'max', 'personalities': {'code': 100}}, {'firstname': 'max', 'personalities': {'code': 500}}, {'firstname': 'max', 'personalities': {'code': 750}}, {'firstname': 'dan', 'personalities': {'code': 100}}, {'firstname': 'dan', 'personalities': {'code': 500}}, {'firstname': 'dan', 'personalities': {'code': 750}}, {'firstname': 'nico', 'personalities': {'code': 100}}, {'firstname': 'nico', 'personalities': {'code': 500}}, {'firstname': 'nico', 'personalities': {'code': 750}}])

def _test_with_jen_single():
  # not testing overriding opts from file
  test = _JeromeTest()
  test.execute(['--bills_jen_order', 'personalities.code', 'firstname',  # use order for fun and profit
            '--checks_single'])
  test.print_fields()
  print(test.as_checkbook())
  #######1 - this should be without any changes
  DJ_bills = DynJen(test.aggregator.config('bills'), test.aggregator.get_jen_order('bills'))
  insts_bills = [inst for inst in DJ_bills]
  assert(insts_bills == [{'firstname': 'max', 'personalities': {'code': 100}}, {'firstname': 'max', 'personalities': {'code': 500}}, {'firstname': 'max', 'personalities': {'code': 750}}, {'firstname': 'dan', 'personalities': {'code': 100}}, {'firstname': 'dan', 'personalities': {'code': 500}}, {'firstname': 'dan', 'personalities': {'code': 750}}, {'firstname': 'nico', 'personalities': {'code': 100}}, {'firstname': 'nico', 'personalities': {'code': 500}}, {'firstname': 'nico', 'personalities': {'code': 750}}])
  #######2 - this should be affected by --checks_single
  DJ_checks = DynJen(test.aggregator.config('checks'), test.aggregator.get_jen_order('checks'))
  insts_checks = [inst for inst in DJ_checks]
  assert(insts_checks == [{'infoline': 'myinfo', 'extrashit': {'extra1': 'goodguy'}}])



def test_cli_config_aggregator_with_jen(argv):
  _test_with_jen()
  _test_with_jen_single()

if __name__ == '__main__':
  test_cli_config_aggregator_with_jen(sys.argv[1:])



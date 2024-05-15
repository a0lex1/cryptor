import sys
from typing import List

from c2.infra.parse_worker import parse_worker
from c2.infra.unischema import Unischema

# TestloopRunner is the default implementation of handling tst_opts; some modules have their own implementations, like CasetestCLI (its tst_opts['limit'] controls global (case|jen) counter instead of JEN iters)
# tst_opts['limit'] is "global" to tst_opts['worker'], e.g. its number expresses the limit for all workers, not the "local" limit of executed iterations for a specific worker
class TestloopRunner:
  def __init__(self, tst_opts, generator, fn_dispatch_inst):
    self._tst_opts = tst_opts
    self._generator = generator
    self._fn_dispatch_inst = fn_dispatch_inst
    self._worker_index, self._worker_count = None, None
    if tst_opts['worker'] != '':
      self._worker_index, self._worker_count = parse_worker(tst_opts['worker'])


  def run(self):
    ninst = 0
    processed, skipped = 0, 0
    for inst in self._generator:
      if self._tst_opts['limit'] != -1:
        if ninst == self._tst_opts['limit']:
          break
        assert (ninst < self._tst_opts['limit'])

      skip = False
      if self._worker_index != None:
        # Worker enabled -> means parallel mode, skip items except our part (where ninst % == our id)
        assert(self._worker_count != None)
        if ninst % self._worker_count != (self._worker_index-1): #-1 cuz first worker's index is 1, not 0
          skip = True

      if not skip:
        # Form and print message
        _msg = f'TestloopRunner (inst#{ninst})'
        if self._worker_index != None:
          _msg += f' [worker {self._worker_index}/{self._worker_count}]'
        if self._tst_opts['dry']:
          _msg += '  (DRY MODE)'
        #print('*'*30)
        print(_msg)
        print('-'*5)
        print('  Inst ->', inst)
        #print('*'*30)

        if not self._tst_opts['dry']:
          # Call the dispatcher passing him |inst|
          self._fn_dispatch_inst(inst)

        processed += 1
      else:
        skipped += 1

      ninst += 1

    print(f'Testloop run done, processed {processed} (skipped {skipped}) insts (total {processed+skipped})')



_unischema = {
  "type": "object",
  "properties": {
    "a": {"type": "number", "$jdefault": ["$jcs", "A1", "A2", "A3"]},
    "b": {"type": "number", "$jdefault": ["$jcs", "B1", "B2", "B3"]}
  }
}

from c2.infra.dyn_jen import DynJen

def _test_expect(tst_opts, dj:DynJen, expected_insts:List[dict]):
  insts = []
  def fndisp(inst:dict):
    #print(inst)
    insts.append(inst)
  jlr = TestloopRunner(tst_opts, dj, fndisp)
  jlr.run()
  if insts != expected_insts:
    print('Expected insts:')
    print(expected_insts)
    print('Got insts:')
    print(insts)
    raise RuntimeError('unexpected insts')


def test_testloop_runner(argv):
  u = Unischema(_unischema)
  djdoc = u.make_dynjen_doc()


  _test_expect({'limit': -1, 'dry': False, 'worker': '' }, DynJen(djdoc, []),
    [{'a': 'A1', 'b': 'B1'}, {'a': 'A2', 'b': 'B1'}, {'a': 'A3', 'b': 'B1'}, {'a': 'A1', 'b': 'B2'},
    {'a': 'A2', 'b': 'B2'}, {'a': 'A3', 'b': 'B2'}, {'a': 'A1', 'b': 'B3'}, {'a': 'A2', 'b': 'B3'},
    {'a': 'A3', 'b': 'B3'}])
  _test_expect({'limit': -1, 'dry': True, 'worker': '' }, DynJen(djdoc, []), [])

  _test_expect({'limit': 3, 'dry': False, 'worker': '' }, DynJen(djdoc, []), [{'a': 'A1', 'b': 'B1'}, {'a': 'A2', 'b': 'B1'}, {'a': 'A3', 'b': 'B1'}])
  _test_expect({'limit': 3, 'dry': True, 'worker': '' }, DynJen(djdoc, []), [])


  _test_expect({'limit': -1, 'dry': False, 'worker': '2/3'}, DynJen(djdoc, []), [{'a': 'A2', 'b': 'B1'}, {'a': 'A2', 'b': 'B2'},  {'a': 'A2', 'b': 'B3'}])
  _test_expect({'limit': -1, 'dry': True, 'worker': '2/3'}, DynJen(djdoc, []), [])

  # increase limit for this test
  _test_expect({'limit': 5, 'dry': False, 'worker': '2/3'}, DynJen(djdoc, []), [{'a': 'A2', 'b': 'B1'}, {'a': 'A2', 'b': 'B2'}])
  _test_expect({'limit': 3, 'dry': True, 'worker': '2/3'}, DynJen(djdoc, []), [])
  # extra tests for N/N (the last piece)
  _test_expect({'limit': 9, 'dry': False, 'worker': '3/3'}, DynJen(djdoc, []), [{'a': 'A3', 'b': 'B1'}, {'a': 'A3', 'b': 'B2'}, {'a': 'A3', 'b': 'B3'}])
  _test_expect({'limit': 3, 'dry': True, 'worker': '3/3'}, DynJen(djdoc, []), [])



if __name__ == '__main__':
  test_testloop_runner(sys.argv[1:])









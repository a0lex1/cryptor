import json, random, os, sys
import networkx as nx

from c2._internal_config import get_tmp_dir
from c2.sprayer.rg.rolegen_old import RoleGenOld
from c2.infra.unischema import unischema_load
from c2.common.graph import save_graph

_sd = os.path.dirname(__file__)
_my_tmpdir = get_tmp_dir()+'/example_rolegen_old'
_inclroot = f'{_sd}/../..'


# Really neat and nice example, try it!
def example_rolegen_old(argv):
  #G = nx.DiGraph(nx.drawing.nx_pydot.read_dot(f'{_sd}/../test/td/test_rolegen_old/cmstp.dot')) #nx avail without import networkx as nx? I don't know python?
  spraytab = json.load(open(f'{_sd}/../test/td/test_rolegen_old/spraytab.json'))
  rgold_opts = unischema_load(f'{_sd}/../rgold_opts.UNISCHEMA', _inclroot).make_default_config()
  rgpxlx_inline = False
  rng = random.Random()
  rgold = RoleGenOld(spraytab, rgpxlx_inline, rgold_opts, rng)
  while rgold.stages_left():
    print(f'doing stage  {rgold.stage_name()}')
    rgold.stage()
    if len(rgold.get_changed_flags()):
      print('changed flags: ', rgold.get_changed_flags())
      if 'graph_changed' in rgold.get_changed_flags():
        save_graph(rgold._G, _my_tmpdir, show=True, create_dir=True)
    else:
      print('no changed flags')
    print()


if __name__ == '__main__':
  example_rolegen_old(sys.argv[1:])


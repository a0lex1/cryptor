import networkx as nx
from c2.pg.program_model import ProgramModel

# TODO: rename to make_alpha_test_pm()
def make_test_pm():
  pm = ProgramModel(cached_number_of_userprocs=3)
  pm.G = nx.DiGraph()
  pm.G.add_edge(0, 1)
  pm.G.add_edge(1, 2)
  pm.G.add_edge(1, 3)
  pm.G.add_edge(0, 4)
  pm.G.add_edge(0, 5)
  pm.G.add_edge(5, 6)
  pm.G.add_edge(5, 7)
  pm.gdata = { nid: {} for nid in pm.G.nodes }
  pm.gdata[0]['t'] = 0
  pm.gdata[0]['e'] = 0
  pm.gdata[0]['tt'] = 'R'
  pm.gdata[0]['waker_name'] = 'wfo'
  pm.gdata[0]['waker'] = 2
  pm.gdata[0]['waker_nobjs'] = 1
  pm.gdata[0]['acts'] = [('always', None, '!hlt', None)]
  #pm.gdata[0]['timeofs'] = 0 #trivial

  pm.gdata[1]['t'] = 1
  pm.gdata[1]['e'] = 1
  pm.gdata[1]['tt'] = 'R'
  pm.gdata[1]['waker_name'] = 'iocp'
  pm.gdata[1]['waker'] = 1
  pm.gdata[1]['acts'] = [('one-shot', 1000, 'cocrel', None), ]
  pm.gdata[1]['waker_nobjs'] = 3
  pm.gdata[1]['timeofs'] = 900

  pm.gdata[2]['t'] = 2
  pm.gdata[2]['e'] = 2
  pm.gdata[2]['tt'] = 'R'
  pm.gdata[2]['acts'] = [('trigger', 1500, '!wake', 2), ('upidx_eq', 2000, '!call_userproc', 2)]
  pm.gdata[2]['timeofs'] = 1300

  pm.gdata[3]['t'] = 3
  pm.gdata[3]['e'] = 3
  pm.gdata[3]['tt'] = 'R'
  pm.gdata[3]['acts'] = [('always', None, '!hlt', None)]
  pm.gdata[3]['timeofs'] = 2400

  #####################
  pm.gdata[4]['t'] = 4
  pm.gdata[4]['e'] = 4
  pm.gdata[4]['tt'] = 'G'
  pm.gdata[4]['timeofs'] = 1200
  pm.gdata[4]['acts'] = [('trigger', 3000, '!wake', 1), ('trigger', 3100, '!wake', 1), ('trigger', 3200, '!wake', 1),
                          ('upidx_eq', 4000, '!call_userproc', 1)]

  pm.gdata[5]['t'] = 5
  pm.gdata[5]['e'] = 5
  pm.gdata[5]['tt'] = 'R'
  pm.gdata[5]['acts'] = [('always', -1, 'cocrel', None), ('always', -1, 'loadlib', None), ]
  pm.gdata[5]['timeofs'] = 1400

  #####################
  pm.gdata[6]['t'] = 6
  pm.gdata[6]['e'] = 1
  pm.gdata[6]['tt'] = 'G'
  pm.gdata[6]['acts'] = [('always', None, '!hlt', None)]
  pm.gdata[6]['timeofs'] = 1800

  pm.gdata[7]['t'] = 7
  pm.gdata[7]['e'] = 2
  pm.gdata[7]['tt'] = 'R'
  pm.gdata[7]['acts'] = [('upidx_eq', 4530, '!call_userproc', 3), ('trigger', 3000, '!wake', 2)]
  pm.gdata[7]['timeofs'] = 1900


  return pm


def _render_and_show_graph():
  from c2.common.graph import save_graph
  pm = make_test_pm()
  pm.render_gdata_on_graph()
  save_graph(pm.G, '.', 'pms_for_test001')


if __name__ == '__main__':
  _render_and_show_graph()




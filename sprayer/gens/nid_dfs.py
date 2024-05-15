import networkx as nx

from c2.common.graph import save_graph


class NIDDfsOrderChecker:
  def __init__(self, G:nx.DiGraph):
    self.G = G
    self.result = None
    self.stop_nid = None
    
  def do_check(self):
    self.result = True # by default
    self.__cur_nid = 0
    self.__vis(self.G, 0)
    
  def __vis(self, G, nid):
    RECURSE = self.__vis
    chnids = G.successors(nid)
    self.__cur_nid += 1
    for chnid in chnids:
      if self.__cur_nid != chnid:
        self.stop_nid = chnid
        self.result = False
        break
      RECURSE(G, chnid)
      if self.stop_nid != None:
        break

# expected_result and expected_stop_nid can be 0
def _test_expect(G, expected_result:bool, expected_stop_nid:int):
  checker = NIDDfsOrderChecker(G)
  checker.do_check()
  if expected_result != checker.result:
    raise RuntimeError(f'{expected_result=} != {checker.result=}')
  if expected_stop_nid != checker.stop_nid:
    raise RuntimeError(f'{expected_stop_nid=} != {checker.stop_nid=}')

def _get_test_G3():
  G3 = nx.DiGraph()
  G3.add_edge(0, 1)
  G3.add_edge(1, 2)
  G3.add_edge(2, 3)
  G3.add_edge(3, 4)
  G3.add_edge(3, 5)
  G3.add_edge(5, 6)
  G3.add_edge(5, 7)
  G3.add_edge(3, 8)
  G3.add_edge(2, 9)
  G3.add_edge(1, 10)
  G3.add_edge(0, 11)
  #G3.add_edge()
  return G3

def _get_test_G3BAD1():
  G3BAD1 = nx.DiGraph()
  G3BAD1.add_edge(0, 1)
  G3BAD1.add_edge(1, 2)
  G3BAD1.add_edge(2, 3)
  G3BAD1.add_edge(3, 4)
  G3BAD1.add_edge(3, 5)
  G3BAD1.add_edge(5, 6)
  G3BAD1.add_edge(5, 7)
  G3BAD1.add_edge(3, 8)
  G3BAD1.add_edge(2, 10) # swap
  G3BAD1.add_edge(1, 9)  # swap
  G3BAD1.add_edge(0, 11)
  #G3.add_edge()
  return G3BAD1

def test_nid_dfs_order_checker():
  #save_graph(_get_test_G3(), '.', 'G3')
  _test_expect(_get_test_G3(), True, None)
  _test_expect(_get_test_G3BAD1(), False, 10)

if __name__ == '__main__':
  test_nid_dfs_order_checker()



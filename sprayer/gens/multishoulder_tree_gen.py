import networkx as nx
import random
from typing import List

from c2.sprayer.gens.distribute_randomly import distribute_randomly
from c2.sprayer.gens.nid_dfs import NIDDfsOrderChecker
from c2.common.graph import save_graph


# Output .G is nid-dfs ordered, no need to reassign nids
# Limitations: set_number_of_shoulders(0) leads to empty G, set_number_of_nodes_to_distribute() should be 0 too (otherwise, exception)
# Can generate empty graph for some zero int params (set_*)
# paper#60
class MultishoulderTreeGen:
  def __init__(self, rng):
    self.G = None  # output
    self.__rng = rng

    self.__num_shoulders = None
    self.__total_nodes = None
    self.__scatter_percent = None

  def set_number_of_shoulders(self, num_shoulders):
    self.__num_shoulders = num_shoulders

  def get_number_of_shoulders(self) -> int:
    return self.__num_shoulders

  # The graph will consist of
  #   1) root node
  #   2) shoulder nodes (children of root)
  #   3) |total_nodes| nodes distributed to shoulders
  def set_number_of_nodes_to_distribute(self, total_nodes):
    self.__total_nodes = total_nodes

  def set_scatter_percent(self, scatter_percent:int):
    self.__scatter_percent = scatter_percent

  def do_gen(self):
    assert(self.__num_shoulders != None and self.__total_nodes != None and self.__scatter_percent != None)
    self.G = nx.DiGraph()
    self.G.add_node(0)  # add root node
    # glue several tree graphs into a big one as multiple shoulders
    shoulders = distribute_randomly(self.__total_nodes, self.__num_shoulders, self.__scatter_percent, self.__rng)
    assert(len(shoulders) == self.__num_shoulders)
    start_nid = 1
    for nshoulder in range(self.__num_shoulders):
      # gen graph
      num_leafs_in_shoulder = shoulders[nshoulder]
      # __make_tree will append new branch (where the shoulder is the root node of this branch) to G
      new_nid = self.__make_tree(self.__gen_seq(num_leafs_in_shoulder), self.G, 0, start_nid)
      start_nid = new_nid


  def __gen_seq(self, num_leafs) -> List[str]:
    # ['l', 'l', 'l', 'e', 'e', 'e', 'e', 'e', 'l', 'e', 'e', 'e', 'l', 'l', 'e', 'l', 'l', 'l', 'e', 'l', ]
    seq = ['e' for i in range(num_leafs)] + ['l' for j in range(num_leafs)]
    self.__rng.shuffle(seq)
    return seq

  # start_nid should be free (not on graph) nid
  def __make_tree(self, seq: List[str], G, root_nid, start_nid) -> int:
    # e=enter, l=leave
    stack = [start_nid]
    G.add_node(start_nid)
    G.add_edge(root_nid, start_nid)
    nid = start_nid+1
    for i in range(0, len(seq)):
      assert (len(stack) >= 1)
      if seq[i] == 'e':
        # print(f'adding node {nid} (prev {stack[-1]})')
        G.add_node(nid)
        # if len(stack):
        G.add_edge(stack[-1], nid)  # add edge to prev node
        stack.append(nid)
        nid += 1
      elif seq[i] == 'l':
        if len(stack) > 1:
          stack.pop()
    # stack can still have elements, we don't care
    return nid


############# TEST CODE ###################

# Customizable MultishoulerTreeGen test
class _MultishoulderTGTestBase:
  def __init__(self, rng=None):
    self.show_graph_on_error = False
    self.show_graph_on_success = False
    if rng == None:
      rng = random.Random()
    self.__rng = rng

  def execute_test(self):
    print('[ ] execute_test enter, params:')
    self._display_params()
    print('[ ] create MultishoulderTreeGen...')
    self._create_tg()
    print('[ ] configure MultishoulderTreeGen...')
    self._configure_tg()
    print('[ ] do gen...')
    self._do_gen()
    print('[ ] checking result...')
    self.__check_result()
    print('[+] execute_test done')
    print()

  def _create_tg(self):
    self._tg = MultishoulderTreeGen(self.__rng)

  def _configure_tg(self):
    # REQUIRED TO HOOK. Custom configuration process
    # tg.set_*()
    raise NotImplementedError()

  def _do_gen(self):
    self._tg.do_gen()

  def __internal_checks(self):
    if self._tg.G.number_of_nodes() == 0:
      # ok, nothing to check in empty graph
      return
    if not nx.is_tree(self._tg.G):
      raise RuntimeError('should be a tree')

  def __check_result(self):
    try:
      self.__internal_checks()
      self._extra_checks() # in derived
      if self.show_graph_on_success:
        print('`show graph on success` is enabled, showing graph...')
        save_graph(self._tg.G, '.', 'MultishoulderTGTestBase_SUCCESS', show=True)
    except Exception as e:
      print('_extra_checks() raised an exception:')
      print(e)
      if self.show_graph_on_error:
        print('`show graph on error` is enabled, showing graph...')
        save_graph(self._tg.G, '.', 'MultishoulderTGTestBase_ERROR', show=True)
      print('Reraising...')
      raise

  def _extra_checks(self):
    # OPTIONAL TO HOOK. Custom extra checks that goes well with logic done by _configure_tg()
    pass

  def _display_params(self):
    # OPTIONAL TO HOOK
    pass


class _MultishoulderTGTest(_MultishoulderTGTestBase):
  def __init__(self, num_shoulders, num_nodes_to_distrib, scatter_percent, rng=None):
    super().__init__(rng)
    self.__num_shoulders = num_shoulders
    self.__num_nodes_to_distrib = num_nodes_to_distrib
    self.__scatter_percent = scatter_percent

  def _configure_tg(self):
    self._tg.set_number_of_shoulders(self.__num_shoulders)
    self._tg.set_number_of_nodes_to_distribute(self.__num_nodes_to_distrib)
    self._tg.set_scatter_percent(self.__scatter_percent)

  def _display_params(self):
    print(f'{self.__num_shoulders=} {self.__num_nodes_to_distrib=} {self.__scatter_percent=}')

  def _extra_checks(self):
    ### check shoulders form, root node's children are shoulders (root nid = 0 by design)
    actual_shoulder_nids = list(self._tg.G.successors(0))
    if len(actual_shoulder_nids) != self.__num_shoulders:
      raise RuntimeError(f'{len(actual_shoulder_nids)=} != {self.__num_shoulders=}')
    ### the FORMULA to check the total num nodes
    expected_num_nodes = 1 + self.__num_shoulders + self.__num_nodes_to_distrib
    if self._tg.G.number_of_nodes() != expected_num_nodes:
      raise RuntimeError(f'unexpected number of nodes {tg.G.number_of_nodes()}, expected {expected_num_nodes}')
    ### check dfs-nid counting (being dfs-nid is MultishoulderTreeGen public guarantee)
    ordchecker = NIDDfsOrderChecker(self._tg.G)
    ordchecker.do_check()
    if ordchecker.result != True:
      assert(ordchecker.result == False)
      raise RuntimeError(f'the graph is not dfs-nid, check stopped at nid {ordchecker.stop_nid}')


def _test_multishoulder_tree_generator_EdgeCases(rng):
  test = _MultishoulderTGTest(0, 0, 50, rng)
  test.execute_test()

  #test = MultishoulderTGTest(0, 1) # breaks public limitations of MultishoulderTreeGen

  test = _MultishoulderTGTest(1, 0, 50, rng)
  test.execute_test()

  test = _MultishoulderTGTest(2, 0, 50, rng)
  test.execute_test()

  ###
  test = _MultishoulderTGTest(1, 1, 50, rng)
  test.execute_test()


def _test_multishoulder_tree_generator_OtherCases(rng):
  test = _MultishoulderTGTest(2, 2, 50, rng)
  test.execute_test()

  test = _MultishoulderTGTest(5, 5, 50, rng)
  test.execute_test()

  test = _MultishoulderTGTest(6, 42, 50, rng)
  test.execute_test()

  test = _MultishoulderTGTest(6, 542, 50, rng)
  #test.show_graph_on_success, test.show_graph_on_error = True, True # <---<<human:open your eyes>>--->
  test.execute_test()

  pass

def test_multishoulder_tree_generator():
  rng = random.Random()
  _test_multishoulder_tree_generator_EdgeCases(rng)
  _test_multishoulder_tree_generator_OtherCases(rng)
  pass

if __name__ == '__main__':
  test_multishoulder_tree_generator()










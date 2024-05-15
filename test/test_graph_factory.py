import os, sys
from c2.graph_factory import GraphFactory


# use lightest samples to save time
def test_graph_factory(argv):
  graphfac = GraphFactory('barabasi://default?n_sx=10..20&m_sx=2')
  graphfac.create_graph()
  print('Mr. Barabasi generated')

  # deprecated pg_graphs0\
  graphfac = GraphFactory('testgstock://i0_r0_sl0.dot')
  graphfac.create_graph()
  print('testgstock generated')

  # deprecated otherapp_graphs0\
  graphfac = GraphFactory('testlegal://notepad.dot')
  graphfac.create_graph()
  print('testlegal generated')


if __name__ == '__main__':
  test_graph_factory(sys.argv[1:])



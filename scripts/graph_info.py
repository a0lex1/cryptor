import sys
import networkx as nx
#import matplotlib.pyplot as plt


G = nx.drawing.nx_pydot.read_dot(sys.argv[1])

print(G.number_of_edges(), 'edges')



import os, networkx as nx
import io
from pprint import pprint

def labelnodes(G, dat:dict, skips=None, width=30):
  if skips == None:
    skips = []
  for key in dat.keys():
    ddict = dat[key]
    ddict = {k: ddict[k] for k in ddict.keys() if not k in skips}
    #G.nodes[key]['label'] = '"'+str(ddict)[1:-1]+'"'
    s = io.StringIO()
    pprint(ddict, width=width, stream=s)
    G.nodes[key]['label'] = '"'+s.getvalue()+'"'


# WARNING file_title INSECURE CHARS
def save_graph(G, root_dir, file_title='_deftitle_', png_too=False, show=True, create_dir=False):
  if create_dir:
    os.makedirs(root_dir, exist_ok=True)
  dot = nx.drawing.nx_pydot.to_pydot(G)
  dotname = os.path.join(os.path.realpath(root_dir), f'{file_title}.dot')
  dot.write_dot(dotname)
  if png_too:
    pngname = os.path.join(os.path.realpath(root_dir), f'{file_title}.png')
    dot.write_png(pngname)
  if show:
    cmd = '"'+dotname+'"'+' > NUL'
    print(f'executing {cmd}')
    os.system(cmd)


def node_color(node, fillcolor):
  node['style'] = 'filled'
  node['fillcolor'] = fillcolor


def hex_to_rgb(hexa):
  return tuple(int(hexa[i:i + 2], 16) for i in (0, 2, 4))


def rgb_to_hex(rgb_tup):
  return '%02x%02x%02x' % rgb_tup


def parse_html_color(color):
  assert (type(color) == str)
  assert (len(color) == 7)
  assert (color[0] == '#')
  return hex_to_rgb(color[1:])


def make_html_color(rgb_tup):
  return '#' + rgb_to_hex(rgb_tup)


def node_color_c(node, R=None, G=None, B=None):
  hc = list(parse_html_color(node['fillcolor']))
  if R != None:
    hc[0] = R
  if G != None:
    hc[1] = G
  if B != None:
    hc[2] = B
  node_color(node, make_html_color(tuple(hc)))



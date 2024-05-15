#needs to be reloaded every time before calling, IDK why !
#simplegraph(["FUNCNAME"], 7, True, "Z:\\v\\1.dot")

#pip install matplotlib
#pip install networkx
#pip install scipy
#(Install graphviz release bin)
#python -m pip install --global-option=build_ext --global-option="-IC:\Program Files\Graphviz\include" --global-option="-LC:\Program Files\Graphviz\lib" pygraphviz
#pip install pydot

import random, pprint
import csv
import json
import io
import base64
import networkx as nx
import matplotlib.pyplot as plt
import ctypes
import ida_xref
import idautils
import ida_funcs
import idc
import ida_name

def gh_demangle(name):
  BUFSIZE = 4096
  szBuf = ctypes.create_unicode_buffer(BUFSIZE)
  UNDNAME_NAME_ONLY = 0x1000
  dwFlags = UNDNAME_NAME_ONLY
  dwRet = ctypes.windll.dbghelp.UnDecorateSymbolNameW(name, szBuf, BUFSIZE, dwFlags)
  return str(szBuf.value)

def gh_get_func_pretty_name(ea):
  fxname = ida_funcs.get_func_name(ea)
  if not fxname:
    pretty = str(ea)
  else:
    demangled = gh_demangle(fxname)
    if demangled:
      pretty = demangled
    else:
      pretty = str(ea)
  return pretty


def _gh_normalize_ida_name(name):
  #OTOD: demangle
  name = name.replace('::','__')
  name = name[0:30]
  return name

def _gh_copy_node_attrs(G, node, node_attrs):
  for na in node_attrs.keys():
    G.nodes[node][na] = node_attrs[na]

def _gh_finalize_attributes(G, func_color='#ffffff', get_func_label_cb=None):
  MAGIC_INTERNAL_MAX_LEN = 20 # IDK WTF
  def shorten(strval, maxlen):
    if len(strval) > maxlen:
      return strval[0:maxlen-3] + '...'
    else:
      return strval
  def func2label(func):
    return '"'+''+'"'
  
  if get_func_label_cb == None:
    get_func_label_cb = func2label

  for node in G.nodes:
    #G.nodes[node]['label'] = get_func_label_cb(G.nodes[node]['func'])
    G.nodes[node]['style'] = 'filled'
    G.nodes[node]['fillcolor'] = func_color
    G.nodes[node]['func'] = '"' + G.nodes[node]['func'] + '"'


def _gh_get_func_sizes():
  func_sizes = {}
  for segea in Segments():
    for funcea in Functions(segea, idc.get_segm_end(segea)):
      #functionName = GetFunctionName(funcea)
      for (startea, endea) in Chunks(funcea):
        for head in Heads(startea, endea):
          #print functionName, ":", "0x%08x"%(head), ":", GetDisasm(head)
          head_len = endea - startea
          if funcea in func_sizes:
            func_sizes[funcea] += head_len
          else:
            func_sizes[funcea] = head_len
  return func_sizes


################# mutable default args!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
def _gh_get_brief_graph(ea_from_list, depth, with_sizes, G=None, RefStrings={}, visited_eas=[]):  
  # TODO: max recursion test. ELIMINATE RECURSIVE PATHS
  # only named (not sub_)
  assert not depth < 0
  if depth == 0:
    return
  func_sizes = _gh_get_func_sizes()
  all_funcs_len = sum(func_sizes.values())
  num_funcs = len(func_sizes)
  print(f'###!!!@@@!!!###  all funcs len: {all_funcs_len}, num_funcs: {num_funcs}')
  def add_func_node(funcea, funcname):
    avg_func_size = all_funcs_len // num_funcs
    func_size_mul = ida_funcs.calc_func_size(ida_funcs.get_func(funcea)) / avg_func_size
    if with_sizes:
      G.add_node(funcea, height=str(func_size_mul*100), width=str(func_size_mul*100))
    else:
      G.add_node(funcea)
    _gh_copy_node_attrs(G, funcea, {
      'type': 'func',
      'func': funcname,
      'label': funcname#f'0x{funcea:x}'
      })
    pass

  
  to_funcs = []
  for fe in ea_from_list:
    from_func = ida_funcs.get_func(fe)
    if not from_func:
      print(f"*** Bad func found*** - EA {from_func}")
      continue
    if from_func.start_ea in visited_eas:
      continue
    visited_eas.append(from_func.start_ea)
    from_name = gh_get_func_pretty_name(from_func.start_ea)
    norm_from_name = _gh_normalize_ida_name(from_name)
    
    #cur_func_ecalls = ['FUUUUUUUUUUUUUUUUUUUUU', 'aaa']
    #cur_func_ecalls = []
    cur_func_ecalls = set()
    
    is_data = lambda xt: xt == ida_xref.fl_U or xt == ida_xref.dr_T or xt == ida_xref.dr_I or \
                         xt == ida_xref.dr_O or xt == ida_xref.dr_W or xt == ida_xref.dr_R

    func_items = idautils.FuncItems(fe)
    zz = [x for x in func_items]
    for func_item in zz:
      # collect dests of all entry funcs (ea_from_list)
      for xref in idautils.XrefsFrom(func_item, 0):
      
        eaname = ida_name.get_ea_name(xref.to) # not used
        if is_data(xref.type):
          strt = idc.get_str_type(xref.to)
          if strt == None: # e.g. if not string
            if eaname.startswith(ida_name.FUNC_IMPORT_PREFIX): # e.g. starts with __imp_
              importedname = eaname[len(ida_name.FUNC_IMPORT_PREFIX):]
              cur_func_ecalls.add(importedname)
              continue
        if xref.type != ida_xref.fl_CF and xref.type != ida_xref.fl_CN:
          continue
        # if we are here, it's code ref
        to_func = ida_funcs.get_func(xref.to)
        if not to_func:
          continue
        shitkey = f'{from_func.start_ea:x}->{to_func.start_ea:x}'
        if not to_func in to_funcs:
          to_funcs += [to_func]
        if shitkey in RefStrings:
          RefStrings[shitkey] += 1
        else:
          RefStrings[shitkey] = 1
        #if to_func in to_funcs:
        #  continue
        to_name = gh_get_func_pretty_name(to_func.start_ea)
        if G != None:
          norm_to_name = _gh_normalize_ida_name(to_name)
          
          if not from_func.start_ea in G.nodes:
            add_func_node(from_func.start_ea, norm_from_name)

          if not to_func.start_ea in G.nodes:
            add_func_node(to_func.start_ea, norm_to_name)

          if not G.has_edge(from_func.start_ea, to_func.start_ea):
            G.add_edge(from_func.start_ea, to_func.start_ea)
            G.edges[from_func.start_ea, to_func.start_ea]['label'] = 0

          G.edges[from_func.start_ea, to_func.start_ea]['label'] += 1
          
        pass # xref done
      pass # func[item] done
    # all func items enumerated.
    if from_func.start_ea in G.nodes:
      # if func was added, set its ecalls as label
      fp = io.StringIO()
      pprint.pprint(cur_func_ecalls, width=80, stream=fp)
      #G.nodes[from_func.start_ea]['label'] = '!'+fp.getvalue()
    else:
      pass

    # loop to next func
    print(f'func {from_name} done')
    pass


  # recursively analyze collected funcs
  to_eas = [t.start_ea for t in to_funcs]
  _gh_get_brief_graph(to_eas, depth-1, with_sizes, G, RefStrings, visited_eas)



def simplegraph(name_from_list, depth, with_sizes, dot_out_path="Y.dot"):
  G = nx.DiGraph()
  ea_from_list = [idc.get_name_ea_simple(x) for x in name_from_list]

  RefStrings = {}
  _gh_get_brief_graph(ea_from_list, depth, with_sizes, G, RefStrings)
  _gh_finalize_attributes(G)

  print('**************** not sorted RefStrings:')
  pprint.pprint(RefStrings)

  RefStrings = sorted(RefStrings.items(), key=lambda x: x[1])

  print('**************** SORTED RefStrings:')
  pprint.pprint(RefStrings)

  print(f"brief: saving {dot_out_path}...")
  nx.drawing.nx_pydot.write_dot(G, dot_out_path)
  cmd = f"z:\\d\\s\\viewdot-svg.bat {dot_out_path}"
  print('running cmd '+cmd)
  r = os.system(cmd)
  print('cmd done, ret:', r)

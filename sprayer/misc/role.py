import random
from typing import OrderedDict

from c2.sprayer.ccode.node import Node

#                  ______________ the switchdict
#                /
#             vvvvvvvvvvvvvvvvvvvvvvvvvv
#       expr, {swval: [act, act, ...],
#              swval: [act, ],
#              ... }

# switchdict should be ordered! For simplicity we assume the default {'a':1,} dict is ordered in python >3.x
class Role:
  def __init__(self, expr=None, switchdict:dict=None):
    self.expr = expr
    if switchdict == None:
      switchdict = {}
    self.switchdict = switchdict

  def __repr__(self):
    return 'expr: '+str(self.expr) + ', switchdict: '+str(self.switchdict)

  '''
  # commented out, never called
  def validate(self):
    if self.expr == None:
      assert (len(self.switchdict) == 1)
    #for i in range(len(self.switchdict)):
    for swkey in self.switchdict.keys():
      acts = self.switchdict[swkey]
      assert(type(acts) == list)
      for acts in acts:
        if acts != None:
          assert(issubclass(type(acts), Node))
  '''

  '''def __repr__(self):
    self.validate()
    texer = Textualizer(lambda v: None) # wtf, why None? It crashes.
    if self.expr != None:
      exprtext = texer.visit(self.expr)
    else:
      exprtext = '<no-expr>'
    tupstexts = []
    for swkey in self.switchdict.keys():
      acts = self.switchdict[swkey]
      if swkey != None:
        #valtext = texer.visit(swkey)
        assert(type(swkey) == int)
        valtext = str(swkey)
      else:
        valtext = '<no-condvar>'
      actstext = f'({len(acts)} acts)'
      tupstexts.append((valtext, actstext))

    return f'Role({exprtext}, { {t[0]: t[1] for t in tupstexts} })'
  '''



import random

from c2.sprayer._wave import RandomSinWaveCoeff, adjust_sinwaves
from c2.sprayer.gens.bin_tree_from_n import BinTreeFromN
from c2.sprayer.gens._expr_filler import ExpressionFiller
from c2.sprayer.ccode.node import Node
from c2.sprayer.ccode.var import Var, VT
from c2.sprayer.misc.vargen import VarPicker, PICK_FLAG_ALL


def _demo_exprfiller_waves(rng, treegen: BinTreeFromN, term_grav_right, op_grav_right):
  class ShitGen: # subgen for test
    def gen_expr(self):
      return node_const(9)

  # Important test, to debug by eyes
  print('max_n:', treegen.max_n)
  cw = adjust_sinwaves(RandomSinWaveCoeff(5), 100, treegen.max_n, positive=True, amplify_to_height=True, round_to=None)

  # 2fff cuts some naked exprs (var/const only)
  for c in range(0x2fff, treegen.max_n):
  #for c in cw:
    print(f'c={c}/{treegen.max_n}')
    tree = treegen.tree(c)

    vl = [Var(VT.i8, [0x33123])]
    varpicker = VarPicker([vl], PICK_FLAG_ALL, rng)
    filler = ExpressionFiller(treegen.bitcount, varpicker, tree)
    filler.set_gravitation(term_grav_right, op_grav_right)
    filler.set_subgen(ShitGen(), 25, rng)
    filler.set_prerotate(random.randint(0, 31), random.randint(0, 31))
    filler.fill(c)

    #print(filler._next_term()+'  '+filler._next_term()+'  '+filler._next_term())
    #print_simple_tree(tree, filler.leafdata)
    code = Textualizer(lambda v: 'var').visit(tree)
    print(code)
    #print('--------------------')
    #sys.stdin.read(1)


def _demo():
  # Adapt ccode.Node to use as tree
  def fn_makeleaf(children:list):
    return Node(children=children)
  def fn_setchildren(node:Node, children:list):
    node.children = children
  #treegen = BinTreeFromN(3)
  treegen = BinTreeFromN(3, fn_makeleaf=fn_makeleaf, fn_setchildren=fn_setchildren)
  rng = random.Random()
  _demo_exprfiller_waves(rng, treegen, False, False)


if __name__ == '__main__':
  _demo()


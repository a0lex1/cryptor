class BinTreeFromN:
  # fn_makeleaf = lambda: Leaf()
  # fn_setchildren -> lambda leaf, children
  def __init__(self, maxlev, fn_makeleaf, fn_setchildren):
    # maxpower: 0->1 bits, 1->3 bits, 2->7 bits, 3->15 bits, 4->31 bits, ...
    self.maxlev = maxlev
    self.fn_makeleaf = fn_makeleaf
    self.fn_setchildren = fn_setchildren
    self.bitcount = sum([2**i for i in range(maxlev+1)])
    self.max_n = 2**self.bitcount-1
    self.max_g = self.max_n*2

  def symm_tree(self, g):
    # g is [0 .. n*2]
    assert(g <= self.max_g*2)
    x = g if g < self.max_n else self.max_n - g
    return self.tree(x)

  def tree(self, n):
    leafs = [None for _ in range(self.bitcount)]
    fn_makeleaf = self.fn_makeleaf
    leafs[0] = fn_makeleaf([])
    for iter in range((self.bitcount)//2):
      # parent must exist
      if leafs[iter] == None:
        continue
      # check bit
      shiftleft = self.bitcount - iter - 1
      if 0 == (n & (1 << shiftleft)):
        continue # bit not set
      # bit is set
      a = iter*2+1
      b = a+1
      # expand current leaf
      if leafs[a] == None:
        leafs[a] = fn_makeleaf([])
      if leafs[b] == None:
        leafs[b] = fn_makeleaf([])
      self.fn_setchildren(leafs[iter], [leafs[a], leafs[b]])
    root_leaf = leafs[0]
    del leafs
    return root_leaf


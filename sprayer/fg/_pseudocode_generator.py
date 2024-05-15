from c2.sprayer.ccode.node import *


# Creates AST, class name is legacy; name should be SkelToASTTranslator
class PseudocodeGenerator:
  def __init__(self, stmtlist, skel, skeldata):
    assert (0 == len(stmtlist.children))
    self.stmtlist = stmtlist
    self.skel = skel
    self.skeldata = skeldata

    # outputs
    self.num_blocks = None
    self.max_level = None  # output, pass to PseudocodeExpander
    # useful to count, somebody may need this
    self.num_roleifs = None
    self.num_if_trues = None
    self.num_if_falses = None

  def skelgraph2ast(self):
    self.num_blocks = 0
    self.num_roleifs = 0
    self.num_if_trues = 0
    self.num_if_falses = 0

    self._vis_graph2nod(self.skel.root_nid, self.stmtlist.children)
    # self.num_blocks now contains total number of blocks inserted

  # only user of skeldata
  def _vis_graph2nod(self, nid, stmtlist: list, lev=0):
    skel = self.skel
    RECURSE = self._vis_graph2nod
    if self.max_level == None or lev > self.max_level:
      self.max_level = lev
    succ_nids = list(skel.G.successors(nid))

    stmtlist.append(node_line(f'@block_bef@', f'// [bb {self.num_blocks}]'))  # PUT BLOCK 1/2

    self.num_blocks += 1
    prev_if = None
    skeldata = self.skeldata
    for succ_nid in succ_nids:
      insert_block_after = True
      # if_true  if_false  role_if  _else  for  while  role_impl
      succnid = skeldata[succ_nid]['']
      t = skeldata[succ_nid]['t']
      if t == 'if_true':
        self.num_if_trues += 1
        prev_if = node_if(node_line(f'@true@'))
        # prev_if.comment = f'// '
        stmtlist.append(prev_if)
        RECURSE(succ_nid, prev_if.children[1].children, lev + 1)  # recursion # true_stmtlist

      elif t == 'if_false':
        self.num_if_falses += 1
        prev_if = node_if(node_line(f'@false@'))
        # prev_if.comment = f'// '
        stmtlist.append(prev_if)
        # prev_if.children[1] is true_stmtlist
        RECURSE(succ_nid, prev_if.children[1].children, lev + 1)  # recursion # true_stmtlist

      elif t == 'role_if':
        nrol, swkey = skeldata[succ_nid]['role']
        assert (type(swkey) == int or swkey == None)  #
        self.num_roleifs += 1
        if swkey == None:
          # unconditional role
          #prev_if = node_if(node_line(f'@true@')) #this way it would break into if_true case's responsibility
          prev_if = node_if(node_const(1), comment='// uncond role')
        else:
          # conditional role
          prev_if = node_if(node_line(f'@rolecond@{nrol}@{swkey}@'))
        # prev_if.comment = f'// '
        stmtlist.append(prev_if)
        RECURSE(succ_nid, prev_if.children[1].children, lev + 1)  # recursion # true_stmtlist

      elif t == '_else':
        # merge to prev IF
        assert (prev_if.typ == NT.If)
        assert (prev_if.children[2] == None)  # else_stmtlist
        prev_if.children[2] = node_stmtlist()  # else_stmtlist
        RECURSE(succ_nid, prev_if.children[2].children, lev + 1)  # recursion
        insert_block_after = False  # we don't need block after else

      elif t == 'for':
        fornode = node_for(node_line('anyvar'), node_const(0), node_relop('<', node_const(1), node_const(2)),
                           node_line('x++'),
                           node_stmtlist())
        # fornode.comment = f'// for {succnid}'
        stmtlist.append(fornode)
        RECURSE(succ_nid, fornode.children[4].children, lev + 1)  # stmtlist

      elif t == 'while':
        whilenode = node_while(node_line('somecond'), node_stmtlist())
        # whilenode.comment = f'// while {succnid}'
        stmtlist.append(whilenode)
        RECURSE(succ_nid, whilenode.children[1].children, lev + 1)  # stmtlist

      elif t == 'role_impl':
        # role act
        nrole, swkey, nact = skeldata[succ_nid]['roletup']
        assert (type(swkey) == int or swkey == None)  #
        sswkey = swkey
        if sswkey == None:
          sswkey = ''
        stmtlist.append(node_line(f'@roleact@{nrole}@{sswkey}@{nact}@'))
        pass
      else:
        raise RuntimeError('bad t')

      if insert_block_after:
        stmtlist.append(node_line(f'@block_aft@', f'// [ba {self.num_blocks}]'))  # PUT BLOCK 2/2
        self.num_blocks += 1




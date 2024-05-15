from c2.sprayer.ccode.node import NodeVisitor, NT


# It supports only replacing children in node_stmtlist so it's not a generic replacing visitor.
# The generic visitor (with replacing on visit()-level, not on fn_-level) would require
# the change to NodeVisitor and more thinking. Now we just leave this class in '_'-named file.
class ReplacingVisitor(NodeVisitor):
  def __init__(self):
    super().__init__()

  def fn_stmt_list(self, node):
    # Override base's behavior of visiting statement list. Add replacement feature.
    # Recurse to Statement List, support replacing child#N to list L
    # (N, L) collected, executed after visiting tree
    all_repls = []  # [ (nchild, repl_list), ... ]
    for nchild in range(len(node.children)):

      # we hooked Visitor.fn_stmt_list so we need to do this
      self.cur_block_level += 1
      repl_list = self.visit(node.children[nchild])  # recursion
      self.cur_block_level -= 1

      if type(repl_list) == list:  # returned from fn_line
        assert (node.children[nchild].typ == NT.Line) # limiting types
        # collect replacement
        all_repls.append((nchild, repl_list))

    # execute replacements: this will replace node_line s with NT.Assig s
    _extra = 0
    for nchild, repl_list in all_repls:
      nchild += _extra
      # allow empty repl_list, place 0 blocks if so
      node.children = node.children[0:nchild] + repl_list + node.children[nchild + 1:]
      _extra += len(repl_list) - 1  # shift, made by replacing 1 nodes by 1+ nodes on prev iterations

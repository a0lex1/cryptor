from c2.sprayer.ccode.node import *
from copy import copy


class DbgBreakElseAdder(NodeVisitor):
  def fn_if(self, if_node):
    # inserting a copy() because of intuitive thought that those nodes should be different objects
    cond_node, true_block_node, else_block_node = if_node.children
    dbgbreak_stmt = '@not_reached@'
    dbgbreak_node = node_line(dbgbreak_stmt, 'by DbgBreakElseAdder')
    if cond_node.typ == NT.Line:
      if cond_node.props['line'] == '@true@':
        if else_block_node != None:
          # insert stmt at the beginning to existing else block
          else_block_node.children.insert(0, copy(dbgbreak_node))
        else:
          # add else branch with just one statement
          if_node.children[2] = node_stmtlist([dbgbreak_node, ])
      elif cond_node.props['line'] == '@false@':
        true_block_node.children.insert(0, copy(dbgbreak_node))
    super().fn_if(if_node)
    
    


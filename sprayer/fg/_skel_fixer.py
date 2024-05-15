from c2.sprayer.gens.nx_tree_graph import NXTreeGraphRecombiner


class SkelFixer:
  def __init__(self, skel, max_depth, roles_shape):
    self.skel = skel
    self.max_depth = max_depth
    self.roles_shape = roles_shape

  def recombine_limit_depth(self):
    # limit depth by recombining too long paths to root
    skel = self.skel
    recomber = NXTreeGraphRecombiner(skel.G, skel.root_nid)
    recomber.recomb(self.max_depth)
    skel.G = recomber.new_G
    skel.root_nid = recomber.new_root_nid

  def fixup_for_roles(self):
    # add minimum unrelated ifs
    skel = self.skel
    root_children = list(skel.G.successors(skel.root_nid))
    needed = max(self.roles_shape.total_switchkeys() - len(root_children), 0)
    for i in range(needed):
      skel.G.add_node(skel.next_nid)
      skel.G.add_edge(skel.root_nid, skel.next_nid)
      skel.next_nid += 1


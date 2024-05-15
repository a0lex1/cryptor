from c2.sprayer.rg.rolegen import RoleGen
from c2.sprayer.ccode.var import Var, VT, NullPtr


# Base for RoleGenDumb and RoleGenSpray
class RoleGenBasic(RoleGen):
  def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)

  # ARGS USED TO _CALL() FROM CPP, other args are random (except routearg)
  def _generate_arglistarr(self, num_procs, min_args, max_args):
    self.arglistarr = []
    self.fixed_var_names = {}
    for nproc in range(num_procs):
      procname = self.spraytab['procs'][nproc]
      if procname in self.spraytab['proc_opts'] and self.spraytab['proc_opts'][procname]['is_from_decl']:
        # proc from decls CAN'T have args
        self.arglistarr.append([])
        continue
      vl_a = self._mk_one_arglist(min_args, max_args)
      self.arglistarr.append(vl_a)

  def _mk_one_arglist(self, min_args, max_args):
    vlgenfuncs = VLVarsGenFuncs()
    vlgenfuncs.only_unknowns()
    # DISABLE arrays in func arguments; alternative is to develop array callargs support (buffer with at least X size)
    vlgenfuncs.fixed_count(1)
    # generate arguments
    vlgen = VarListGenerator(vlgenfuncs, self._rng)
    vl_a = vlgen.gen_var_list(min_args, max_args)
    return vl_a

  def _generate_arglistarr2(self, num_procs):
    self.arglistarr = []
    self.fixed_var_names = {}
    for nproc in range(num_procs):
      procname = self.spraytab['procs'][nproc]
      if procname in self.spraytab['proc_opts'] and self.spraytab['proc_opts'][procname]['is_from_decl']:
        # proc from decls CAN'T have args
        self.arglistarr.append([])
        continue
      vl_a = [Var(VT.pvoid, [NullPtr() for _ in range(10)]),  # our _XARG
              Var(VT.floa, [3.14])]  # junk for testing

      self.arglistarr.append(vl_a)

      self.fixed_var_names[vl_a[0]] = '_xarg'

    return

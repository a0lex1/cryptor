import threading, json, random, functools, os, sys
from pprint import pprint

from c2.sprayer.validate_opts import validate_spraygen_opts, validate_spgaux_opts
from c2.sprayer._sourcegen import SourceGen, SourceCode
from c2.sprayer._struct_reorderer import StructReorderer
from c2.sprayer.rg.rolegen_dumb import RoleGenDumb
from c2.sprayer.rg.rolegen_old import RoleGenOld
from c2.sprayer.rg.rolegen_spray import RoleGenSpray
from c2.sprayer.fg.funcgen_min import FuncGenMin
from c2.sprayer.fg.funcgen_new import FuncGenNew
from c2.sprayer.fg.func_ast import FuncAST
from c2.sprayer.fg.var_storage import *
from c2.sprayer.misc.spraytab_utils import spraytab_from_sig
from c2.sprayer.gens.var_list_generator import VarListGenerator, VLVarsGenFuncs
from c2.sprayer.ccode.var import VT, Var, ValueUnknown
from c2.sprayer.ccode.node import Node, NodeVisitor, node_stmtlist, node_line
from c2.infra.tool_cli import ToolCLI
from c2.infra.unischema import unischema_load
from c2.infra.cli_seed import CLISeed, DEFAULT_SEED_SIZE
from c2.infra.seed_get_or_generate import seed_get_or_generate
from c2.base.stage_runner import StageRunner
from c2.common.sx import Sx
from c2.common.graph import save_graph

_sd = os.path.dirname(__file__)


class SpraygenCLI(ToolCLI):
  def _initialize(self):
    self._progname = os.path.basename(__file__)

  def _setup_args(self):
    # [was -t management here, removed to simplity]
    agr = self._agr

    agr.add_config('opts', unischema_load(f'{_sd}/spraygen_opts.UNISCHEMA', f'{_sd}/../'))
    agr.add_config('aux', unischema_load(f'{_sd}/spgaux_opts.UNISCHEMA', f'{_sd}/../'))

    self.__cli_seed = CLISeed(None, DEFAULT_SEED_SIZE)
    self._add_arg_processor(self.__cli_seed)

    parser = self._parser
    parser.add_argument('-o', '--outdir', required=True)
    exclgrp = parser.add_mutually_exclusive_group(required=True)
    exclgrp.add_argument('-s', '--signature', help='generate blank spraytab from signature')
    exclgrp.add_argument('-j', '--spraytab_json')


  def _do_work(self):
    args = self._args
    agr = self._agr
    cli_seed = self.__cli_seed

    seed = seed_get_or_generate(cli_seed, DEFAULT_SEED_SIZE)
    rng = random.Random(seed)
    print(f'<spraygen.py rng probe: {rng.randint(0, sys.maxsize)}>')

    if args.signature:
      spraytab = spraytab_from_sig(args.signature)
      print(f'[+] dummy spraytab was made for signature {args.signature}')
      print(json.dumps(spraytab, indent=2))
    else:
      spraytab = json.load(open(args.spraytab_json, 'r'))

    spraygen = Spraygen(spraytab,
                        agr.config('opts'),
                        agr.config('aux'),
                        args.outdir,
                        rng)

    nstage = 0
    while spraygen.stages_left():
      print(f'[STAGE]  {nstage}  {spraygen.stage_name()}')
      spraygen.stage()
      nstage += 1



class Spraygen(StageRunner):
  def __init__(self, spraytab:dict, opts:dict, spgaux_opts:dict, outdir, rng):
    super().__init__()

    validate_spraygen_opts(opts)
    validate_spgaux_opts(spgaux_opts)

    if spgaux_opts['show_graph'] and not spgaux_opts['save_graph']:
      raise RuntimeError('--aux_show_graph requires --aux_save_graph')

    self.spraytab = spraytab
    self.opts = opts
    self.spgaux_opts = spgaux_opts
    self.outdir = outdir
    self._rng = rng

    self._rg = None
    self._sourcegen = None

    self._call_graph = None
    self._proceed_to_next_stage(self.__st_init, 'initialize and load') # may load graph

  # sets self._rg
  def __st_init(self):
    opts = self.opts
    spraytab = self.spraytab
    rng = self._rng
    if opts['rg'] == 'dumb':

      # We are ignorring profile (spray, funcgen opts, etc.)
      rg = RoleGenDumb(spraytab, self.__fn_create_pxlx_line_node, opts['rgdumb'], rng)

      assert(self._call_graph == None)

    elif opts['rg'] == 'old':

      rg = RoleGenOld(spraytab, self.__fn_create_pxlx_line_node, opts['rgold'], rng)

    elif opts['rg'] == 'spray':
      # # # # # # # # this code is all wrong, need rewrite: opts -> RoleGenSpray.__init__, argument on bad positions, etc.
      self._call_graph = Spraygen._make_call_graph(opts['rgspray']['graph'])
      rg_opts = opts['rg_opts']
      # optimize opt is now present as options root_order, proc_order
      # # # # bad code # # # # #
      _rorder = {'random': RootOrder.RANDOM, 'hugest_first': RootOrder.HUGEST_FIRST}[rg_opts['root_order']]
      _porder = {'random': ProcOrder.RANDOM, 'hugest_first': ProcOrder.HUGEST_FIRST, 'default': ProcOrder.DEFAULT}[rg_opts['proc_order']]
      # # # # bad code # # # # #
      rg = RoleGenSpray(spraytab,
                        self.__fn_create_pxlx_line_node,
                        # # # # bad code # # # # #
                        rng,
                        self._call_graph,
                        rg_opts['route_limit'],
                        # # # # bad code # # # # #
                        rg_opts['route_bits'],
                        #bool(args.eliminate_unrouted),
                        _rorder,
                        # # # # bad code # # # # #
                        _porder,
                        rg_opts['max_args'])
      # # # # bad code # # # # #
      rg.do_render = True
      # # # # bad code # # # # #
      rg._pathgen.do_render = True
      print(f' [ ] RoleGenSpray num_route_dwords -> {rg.num_route_dwords()}')
      # # # # bad code # # # # #
    else:
      raise RuntimeError(f'unknown rg - {opts["rg"]}')

    self._rg = rg
    self._proceed_to_next_stage(self.__st_generate_roles, 'generate roles')


  # RoleGen delegates creating PX_LX node_line(s) to the following func
  # The way of creating such nodes should be encapsulated outside RoleGen, its logic
  # is connected to postprocessing __st_reassign_changed_code_lines
  # Multithreading: no problem since funcs generated by different threads don't intersect; we just need a lock to prevent unsynchronized access to |spraytab| object
  def __fn_create_pxlx_line_node(self, nproc, nline):
    procname = self.spraytab['procs'][nproc]
    orig_line = self.spraytab['lines'][procname][nline]
    if self.opts['rgpxlx_inline']:
      line_node = node_line(orig_line)
    else:
      comment = '// ' + orig_line.replace('\n', '\n// ')
      line_node = node_line(f'P{nproc}_L{nline}', comment=comment)

    # ability to edit lines in spraytab is required at FG stage so provide the setter to every node_line
    def _setter(spraytab, _procname, _nproc, _nline, _new_line):
      # Can be called from different threads, but regarding different spraytab's funcs
      self.__mt_lock_acquire_if_exists()
      spraytab['lines'][_procname][_nline] = _new_line
      self.__mt_lock_release_if_exists()

    def _getter(spraytab, _procname, _nproc, _nline) -> str:
      return spraytab['lines'][_procname][_nline]

    # Public, can be used by FuncGen (and RoleGen)
    line_node.props['line_behind_getter'] = functools.partial(_getter, self.spraytab, procname, nproc, nline)
    line_node.props['line_behind_setter'] = functools.partial(_setter, self.spraytab, procname, nproc, nline)
    # Private, for us (spraygen.py)
    line_node.props['_nproc'] = nproc
    line_node.props['_nline'] = nline
    return line_node


  def __st_generate_roles(self):
    rg = self._rg
    opts = self.opts
    spgaux_opts = self.spgaux_opts
    spraytab = self.spraytab
    nstage = 0
    while rg.stages_left():
      stagename = rg.stage_name()
      print(f' [ ]  rg stage  {stagename} ...')

      rg.stage()
      print(f'    stage {stagename} -> changed flags: {rg.get_changed_flags()}')

      if self.spgaux_opts['save_graph']:
        do_show = ('graph_changed' in rg.get_changed_flags()) and (self.spgaux_opts['show_graph'])
        save_graph(self._rg._G, self.outdir, file_title=f'rg_{nstage}_{rg.stage_name()}', show=do_show)

      if type(rg) == RoleGenSpray:
        # # # # bad code # # # # #
        # # # # bad code # # # # #
        '''if rg.graph_updated():
          if args.show_rg_stages:
            print(' [+] rg graph updated, showing...')
            save_graph(rg.get_labeled_graph(), file_title='rg [' + stagename + ']')
          else:
            print(' [+] rg graph updated')
          if rg.log0_updated():
            print('---RG LOG UPDATED:---')
            print('\n'.join(rg.get_log0()))
            print('---END OF RG LOG---')
        '''
        # # # # bad code # # # # #
        # # # # bad code # # # # #
        raise RuntimeError('todo')
      nstage += 1

    print('----------- Roles have been generated ------------')
    if spgaux_opts['save_paths']:
      _text = self.__textualize_roles(rg.rolearr, rg.namearr)
      open(j(self.outdir, 'roles.txt'), 'w').write(_text)
    assert(len(rg.spraytab_procidxes) == len(spraytab['lines']))
    assert(len(rg.rolearr) == len(rg.arglistarr))
    if type(rg) == RoleGenSpray:
      assert(len(rg.rolearr) == call_graph.number_of_nodes())
    if spgaux_opts['verbose'] == True:
      self.__verbose_rolegen_output(rg)
    # OK. Roles generated. What's next?
    # Sort. Proc entry funcs will be added first. E.g. source code top position.
    sorted_rolearr = sorted(rg.rolearr, key=lambda x: x not in rg.spraytab_procidxes)
    rolearr = sorted_rolearr
    self._proceed_to_next_stage(self.__st_generate_funcs, f'generate functions (fg = {opts["fg"]})')

    # Create and configure SourceGen
    self._sourcegen = SourceGen(spraytab, None,
                                rg.spraytab_procidxes, opts['holders'], fr'{_sd}/include',
                                self._rng)
    sourcegen = self._sourcegen

    if 'zvars' in spraytab:
      sourcegen.set_zvar_lines(spraytab['zvars'])
    sourcegen.set_privdefs(spraytab['privdefs'])

    all_defs = {**self.__default_defs(opts, self._rng), **rg.defs} #opts['rgsleep1']
    sourcegen.set_defs(all_defs)

    # spraytab's output .h isn't included, its contents used
    if 'staticvars' in spraytab:
      sourcegen.set_spraytab_static_vars_linelist(spraytab['staticvars'])

    # Copy from spraytab['glob_defs'] to SourceGen
    sourcegen.defs['spraytab_glob_defs'] = spraytab['glob_defs'] if 'glob_defs' in spraytab else {}

    sourcegen.set_fixed_var_names(rg.fixed_var_names)

    # Manage structs.
    if 'structs' in spraytab and 'struct_fields' in spraytab:
      self.__ensure_no_mixed_structs()
      # Reorder structs. Do this action over a copy of structs, because we don't want
      # this to reflected anywhere except SourceGen.set_structs()
      new_structs = spraytab['structs'].copy()
      struct_fields = spraytab['struct_fields']
      print(f'[ ] Reordering {len(new_structs)} structs')
      sreord = StructReorderer(new_structs, struct_fields)
      sreord.do_reorder()
      sourcegen.set_structs(new_structs, struct_fields)
      # Leave spraytab's structs unchanged (unordered)

    sourcegen.set_specific_lines(rg.specific_lines)
    sourcegen.set_raw_lines(spraytab['raw_lines'])
    sourcegen.set_lib_lines(spraytab['libs'])

    vl_g = []
    if True: #was if args.globvars
      # TODO: VarListGenerator#
      vl_g += [Var(VT.i32, [0x1, 0x2, 0x3, ValueUnknown()])]
    sourcegen.vl_g = vl_g

  def __ensure_no_mixed_structs(self):
    for structname in self.spraytab['struct_opts'].keys():
      if 'is_mix' in self.spraytab['struct_opts'][structname]:
        raise RuntimeError('todo - we did not buy the mixer yet')

  def __st_generate_funcs(self):
    # Generate roles (TODO: // proc has no successors, keep it alive\n')
    rg = self._rg
    opts = self.opts
    num_procs = len(rg.rolearr)
    num_threads = self.spgaux_opts["fg_threads"]
    print(f'[ ] generating {num_procs} funcs (fg {opts["fg"]}, {num_threads} threads)')
    self._sourcegen.allocate_funcs(num_procs)
    if num_threads == 1:
      ### Single threaded variant
      self.__mt_lock = None
      for nproc in range(num_procs):
        self.__gen_func(nproc, self._rng, print_stages=True)
    else:
      ### Multithreaded variant
      self.__mt_lock = threading.Lock()
      threads = []
      for thread_idx in range(self.spgaux_opts['fg_threads']):
        # Every thread should have its own rng to support determinism in multithreaded mode.
        rng_for_thread = random.Random(self._rng.randint(0, sys.maxsize))
        t = threading.Thread(target=self.__fg_thread, args=(thread_idx,num_threads,num_procs,rng_for_thread))
        t.start()
        threads.append(t)
      # DON'T print() ANYTHING HERE. Otherwise, you'll get a race condition with one of the currently working threads.
      for t in threads:
        t.join()
      # HERE you can start print()ing again.
      print(f'[ ] all threads finished')
      del self.__mt_lock
    self._proceed_to_next_stage(self.__st_reassign_changed_code_lines, 'reassign changed code lines')
    return

  def __fg_thread(self, thread_idx, num_threads, num_procs, rng_for_thread):
    # Each thread begins from nproc number |thread_idx|, adding |num_threads| at every iteration until < num_procs-1
    nproc = thread_idx
    while nproc < num_procs:
      self.__gen_func(nproc, rng_for_thread, print_stages=False)
      nproc += num_threads

  # If called in multithreaded mode, don't print anything while these threads are working, otherwise you'll get #CatchingStdoutDecodeBug
  # This routine uses self.__mt_lock if it's not None; highlight 'self.' to see where it writes.
  def __gen_func(self, nproc, rng, print_stages=True):
    rg = self._rg
    opts = self.opts
    rolearr = rg.rolearr
    func_roles = rolearr[nproc]
    procname = rg.namearr[nproc]

    self.__mt_lock_acquire_if_exists() # for print()
    st_procidx = None
    if nproc in rg.spraytab_procidxes:
      st_procidx = rg.spraytab_procidxes.index(nproc)
      _oname = self.spraytab['procs'][st_procidx]  # TODO: Does it work? Do we see a good log?
      message = f' [ ] generating func {procname} (orig {_oname}) #{nproc}/{len(rolearr)} ({len(func_roles)} roles) with fg {opts["fg"]}'
    else:
      message = f' [ ] generating func {procname} #{nproc}/{len(rolearr)} ({len(func_roles)} roles) with fg {opts["fg"]}'
    #print(message)
    self.__mt_lock_release_if_exists() # for print()

    # dizzy vars are temp vars for trashing
    dizzy_vars = VarListGenerator(VLVarsGenFuncs(), rng).gen_var_list(5, 25)
    ###
    # |local_vars| is the main local var storage
    ###
    local_vars = [*dizzy_vars]
    varstor = make_var_storage(vl_g=self._sourcegen.vl_g, vl_a=rg.arglistarr[nproc],
                               # note: <no vl_l_ctl and vl_l_trash>, only _u
                               vl_l_ctl_u=local_vars,
                               vl_l_trash_u=rg.lvararr[nproc])

    func_ast = FuncAST()

    # FuncGen can work with line_node.props['line_behind_setter'](new_line) - e.g. lines can be CHANGED here
    if opts['fg'] == 'min':
      funcgen = FuncGenMin()
      funcgen.configure(func_ast, func_roles, varstor, opts['fgmin'], rng)

    elif opts['fg'] == 'new':
      funcgen = FuncGenNew()
      funcgen.configure(func_ast, func_roles, varstor, opts['fgnew'], rng)

    else:
      raise RuntimeError(f'unknown {opts["fg"]=}')

    # When uncommenting this print, we will need to add __mt_lock acquire/release so it doesn't crash in multithreaded mode
    #fn_prn = lambda msg: print('-[ ' + msg + ' ]-')
    fn_prn = lambda msg: None
    funcgen.all_stages(fn_prn)

    # add generated proc to SourceGen
    self.__mt_lock_acquire_if_exists()
    self._sourcegen.set_func(nproc,
                             rg.namearr[nproc],
                             sum(get_argvar_vls(varstor), []),
                             sum(get_locvar_vls(varstor), []),
                             func_ast.stmtlist)
    self.__mt_lock_release_if_exists()


  def __mt_lock_acquire_if_exists(self):
    if self.__mt_lock != None:
      self.__mt_lock.acquire()

  def __mt_lock_release_if_exists(self):
    if self.__mt_lock != None:
      self.__mt_lock.release()


  # #ShareableSpraytab
  # FG needs to change code lines from spraytab, which are already nodes, after RoleGen generated them
  # But rgpxlx_inline requires us to keep both methods of inserting PX_LX line impls
  # If true, we inject lines from spraytab; if false, we inject PX_LX and comment it with line from spraytab
  # So we need to keep versions of data for both mechanisms - with rgpxlx_inline and without it.
  # So we decided to do it this way. Both RoleGen and FuncGen can write to spraytab.
  # After FuncGen-ing, we call __st_reassign_changed_code_lines to update AST node (in rolearr)
  # so SourceGen will write it correctly. With this scheme, SourceGen writes spraytab.h table
  # (for rgpxlx_inline=False version) with modified (by FG, mainly, because of _f(s)) version of spraytab
  # So both node and spraytab are updated. Both rgpxlx_inline=True and False modes will work.
  # I was marking this reasonings with a tiny '#SetCommentsAfter thing' tag previously.
  # 21:07 25 Sep 2023

  # This func is not just about comments. It's necessary. It:
  #       1) copies spraytab's contents of lines to node.props['line'] and #ShareableSpraytab
  #       2) marks it with special tag if it was changed so the human can see
  def __st_reassign_changed_code_lines(self):
    # a helper class
    class LineReassignVisitor(NodeVisitor):
      def __init__(self, spraytab, opts):
        super().__init__()
        self.spraytab = spraytab
        self.opts = opts
      def fn_line(self, node:Node):
        if 'line_behind_setter' in node.props:
          nproc, nline = node.props['_nproc'], node.props['_nline']
          procname = self.spraytab['procs'][nproc]
          cur_line = self.spraytab['lines'][procname][nline]
          # depending on rgpxlx_inline,,,,
          if self.opts['rgpxlx_inline']:
            if node.props['line'] != cur_line:
              # update line itself
              node.props['line'] = '/*^*/'+cur_line.replace('\n', '<LF>')
          else:
            if node.comment != '// '+cur_line:
              # update comment, ^ character is used to highlight
              node.comment = '//^' + cur_line.replace('\n', '\\n')
        return
    sourcegen = self._sourcegen
    # use our helper class to visit and reassign
    for name, vl_a, vl_l, root_stmtlist in sourcegen.get_funcs():
      vis = LineReassignVisitor(self.spraytab, self.opts) # in this class
      vis.visit(root_stmtlist)
    self._proceed_to_next_stage(self.__st_write_code, 'write generated source code')


  def __st_write_code(self):
    sourcegen = self._sourcegen
    assert(sourcegen.num_funcs() == len(self._rg.rolearr))
    assert(sourcegen.num_funcs() == len(self._rg.arglistarr))
    #sg.defs += othermodule.get_defs()
    src = SourceCode('\t')
    sourcegen.gen_src(src)
    src.write_to_dir(self.outdir)
    print('[+] source code written')
    # generate spraytab.h at the end, we need it to be after lines are changed
    self.__generate_spraytab_h(self.outdir, self.spraytab)
    print('[+] spraytab.h generated')
    self.__generate_gened_headers_h(self.outdir, self.spraytab)
    print('[+] gened_headers.h generated')
    self._proceed_to_next_stage(None, None) # execute() done.
    print('[+] last stage done')

  def __generate_gened_headers_h(self, outdir, spraytab):
    with open(f'{outdir}/gened_headers.h', 'w') as f:
      f.write('#pragma once\n')
      f.write('\n')
      f.write(f'// autogenerated by spraygen.py {" ".join(sys.argv)} ;\n')
      f.write('\n')
      for header_name in spraytab['headers']:
        f.write(header_name + '\n')
      f.write('\n')

  def __textualize_roles(self, procroles, procnames):
    o = ''
    for i in range(len(procroles)):
      n = procnames[i]
      o += ''
    return o

  def __generate_spraytab_h(self, outdir, spraytab):
    # spraytab.h contains line table for C code
    # spraytab may be already edited by RoleGen and FuncGen so it differs from original spraytab
    print(f'[ ] Generating spraytab.h')
    # also write spraytab.h based on json spraytab
    path = f'{outdir}/spraytab.h'
    with open(path, 'w') as ftab:
      ftab.write('#pragma once\n\n')
      ftab.write(f'// this header is based on spraytab.json\n')
      ftab.write(f'// auto-generated with: {" ".join(sys.argv)} ;\n\n')
      i = 0
      for procname in spraytab['procs']:
        n = 50 - len(procname)
        spaces = ' ' * n
        ftab.write(f'#define  /* {i} */  {procname}_ENTRY{spaces}P{i}\n')
        i += 1
      ftab.write('\n')

      assert (len(spraytab['procs']) == len(spraytab['lines']))
      # #define P0_L0 someproc_L0
      # ...
      i = 0
      for procname in spraytab['procs']:
        l = 0
        for _ in range(len(spraytab['lines'][procname])):
          ftab.write(f'#define P{i}_L{l} {procname}_L{l}\n')
          l += 1
        i += 1
      ftab.write('\n')

      # #define someproc_L0   CAL(C(antiemu));
      # ...
      for procname in spraytab['procs']:
        iline = 0
        for proc_line in spraytab['lines'][procname]:
          # correctly handle multiline #defines
          proc_line2 = proc_line.replace('\n', ' \\\n\t')
          ftab.write(f'#define {procname}_L{iline} {proc_line2}\n')
          iline += 1
      ftab.write('\n')
    return

  def __default_defs(self, spraygen_opts, rng):  # seed
    s1 = Sx(spraygen_opts['sgsleep1_sx'], rng).make_number()
    s2 = Sx(spraygen_opts['sgsleep2_sx'], rng).make_number()
    return {
      'spraygen_default_defs':
        {'OBFUSCATION_DWORD': f'0x{self._rng.randint(0, 0xffffffff):x}',
         #'_CALL(F)': 'C(F)(DEFAULT_ARGS)', #now in spraygen/include/stk.h; UPD: now in RoleGen
         'SLEEPTIME0_MSEC': f'{s1}', # now used from EVPGen
         'SLEEPTIME1_MSEC': f'{s2}', # now used from EVPGen
         }
    }

  def __verbose_rolegen_output(self, rg):
    print('Roles:')
    for nfunc in range(len(rg.rolearr)):
      if nfunc in rg.spraytab_procidxes:
        norig = rg.spraytab_procidxes.index(nfunc)
        P = f'P{norig}'
      else:
        P = ''
      print(f'  Func #{nfunc} `{P}` {len(rg.rolearr[nfunc])} roles:')
      for nrole in range(len(rg.rolearr[nfunc])):
        print(f'    {nrole} -> {rg.rolearr[nfunc][nrole]}')
    print('Org indecies: ', rg.spraytab_procidxes)




if __name__ == '__main__':
  SpraygenCLI(sys.argv[1:]).execute()



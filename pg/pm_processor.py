import networkx as nx
from typing import List, Dict, Tuple
from dataclasses import dataclass, field

from c2.pg.intermed import ProgramIntermed, ProcIntermed
from c2.pg.program_model import ProgramModel

ACT_TYPES = ['always', 'trigger', 'one-shot', 'upidx_eq']
NORMAL_ACT_NAMES = ['cocrel', 'loadlib']
SPECIAL_ACT_NAMES = ['!crthread', '!hlt', '!wake', '!call_userproc']


class ThreadCreationActAdder:
  def __init__(self, pm:ProgramModel, pgopts:dict):
    self._pm = pm
    self._pgopts = pgopts
  def execute(self):
    G = self._pm.G
    gdata = self._pm.gdata
    for u, v in G.edges:
      gdata[u].setdefault('acts', []).append( ('one-shot', gdata[v]['timeofs'], '!crthread', v ))


# generates: ProgramModel -> ProgramIntermed
class PMProcessorBase:
  def __init__(self, pm: ProgramModel, pi: ProgramIntermed):
    self._pm = pm
    self._pi = pi

  def execute(self):
    raise NotImplementedError()


class PMProcessorEmpty(PMProcessorBase):
  def execute(self):
    # self._pm not used
    assert(not self._pi.conceptually_empty)
    self._pi.conceptually_empty = True
    self._pi.cached_depfiles = ['act_cocrel.h'] # include something here for testing



class PMHelperVisitor:
  def __init__(self, pm:ProgramModel):
    self.pm = pm
    '''
    Examples of outputs.
    
    e_for_t -> {'t0': 'e0',
                't1': 'e1',~
                't2': 'e2',
                ..., 
                't6': 'e1',
                't7': 'e2' }
                
    tlist_for_e -> { e   t*
                     1: [1, 6],
                     2: [2, 7],
                     3: [3], 
                     4: [4],
                     5: [5],
                     } 
                    
    '''
    self.e_for_t = {}
    self.tlist_for_e = {} # output

  def execute(self):
    G = self.pm.G
    root_nid = 0
    self._vis(self.pm.G, root_nid)
    assert(len(self.e_for_t) == G.number_of_nodes())

  def _vis(self, G:nx.DiGraph, nid):
    _RECURSE = self._vis
    e = self.pm.gdata[nid]['e']
    t = self.pm.gdata[nid]['t']
    assert(t == nid)
    # the job of this class is to cache these two parameters:
    self.tlist_for_e.setdefault(e, []).append(t)
    self.e_for_t[t] = e
    for chnid in G.successors(nid):
      _RECURSE(G, chnid)



# Produces spraytab from PM
class PMProcessor(PMProcessorBase):
  def __init__(self, pm, pi, enable_dbgprints:bool, retcode:int):
    super().__init__(pm, pi)
    self._enable_dbgprints = enable_dbgprints
    self._retcode = retcode

    self.out_spraytab = None
    # _proc_intermeds=> { 't0': ProcIntermed(),  }
    self._proc_intermeds = {}
    self._hlpvis = None
    self._act_counters = {} # { 't0': 5, 't1': 10, 't2': 15 }
    self._g_list = []

  def execute(self):
    _my_privdefs = {}
    # Initial spraytab to begin from
    self.out_spraytab = {
      'root_proc': 'ProgramEntry',
      'procs': [],
      'proc_opts': { 'ProgramEntry': {'is_from_decl': True} },
      'glob_defs': { 'ProgramEntry_PRE()': 'XARGSETUP()',
                     'ProgramEntry_POST()': f'XARGCLEANUP(); return {self._retcode}',
                     'ProgramEntry_DECL()': 'int main()'},
      'lines': {},
      'structs': [],
      'struct_fields': {},
      'struct_opts': {},
      'zvars': ["DWORD tick_start;", "BOOL need_exit;", "DWORD tid;", "int cur_userproc_idx;"],
      'headers': ['#include <windows.h>', '#include "dbgutils.h"'],
      'privdefs': {**_my_privdefs}
    }
    # t is nid, e.g. G.nodes[t] is thread t on graph
    self._hlpvis = PMHelperVisitor(self._pm)
    self._hlpvis.execute()

    self._gen_intermed_g_procs()
    assert(len(self._proc_intermeds) == self._pm.G.number_of_nodes())
    assert(len(self._proc_intermeds) == len(self._hlpvis.e_for_t))
    self._gen_intermed_acts()
    self._gen_intermed_thread_to_iter_calls()
    self._gen_intermed_init_globals()

    self._gen_lines()
    assert(len(self.out_spraytab['procs']) == len(self.out_spraytab['lines']))
    assert(self.out_spraytab['procs'].index('t0') == 0)
    self._gen_proc_opts()
    self._gen_privdefs()
    self._gen_act_defs()
    self._gen_zvars()
    self._gen_threaddata_structs()
    self._gen_userprocs()

    self.out_spraytab['procs'][0] = 'ProgramEntry'
    self.out_spraytab['lines']['ProgramEntry'] = ['__noop;'] + self.out_spraytab['lines']['t0']
    del self.out_spraytab['lines']['t0']
    del self.out_spraytab['proc_opts']['t0']

    return # from execute()

  def _gen_intermed_init_globals(self):
    self._proc_intermeds['t0'].s_init_globals = [
      'Z(cur_userproc_idx) = 1;',
      'Z(tick_start) = TICKMS;'
    ]

  def _gen_userprocs(self):
    spraytab = self.out_spraytab
    for nuproc in range(self._pm.cached_number_of_userprocs):
      upname = f'userproc{nuproc+1}'
      spraytab['procs'] += [upname]
      spraytab['lines'][upname] = [
        f'printf("%%%%%%%%%%%%%%%%%%% USERPROC {upname} CALLED %%%%%%%%%%%%%%%%%%%\\n"); Beep({250*(nuproc+1)}, 300);'
      ]

  def _gen_zvars(self):
    G = self._pm.G
    spraytab = self.out_spraytab
    for nthread in range(G.number_of_nodes()):
      spraytab['zvars'] += [f'HANDLE hThread{nthread};']
    for nthread in range(G.number_of_nodes()):
      spraytab['zvars'] += [f'T{nthread}_DATA t{nthread}data;']

  def _gen_threaddata_structs(self):
    G = self._pm.G
    gdata = self._pm.gdata
    spraytab = self.out_spraytab
    for nthread in range(G.number_of_nodes()):
      tstructname = f'T{nthread}_DATA'
      spraytab['structs'] += [tstructname]
      # Add base fields
      spraytab['struct_fields'][tstructname] = ['int thread_index;', f'BYTE act_called_flags[T{nthread}_NUM_ACTS];', ]
      # Add act's fields
      for nact in range(len(gdata[nthread]['acts'])):
        acttype, acttimeofs, actname, actparam = gdata[nthread]['acts'][nact]
        assert(acttype in ACT_TYPES)
        if actname in NORMAL_ACT_NAMES:
          # normal act
          spraytab['struct_fields'][tstructname] += [f'ACTVARS_{actname} a{nact}_{actname}_vars;']
        elif actname in SPECIAL_ACT_NAMES:
          # special act
          assert(actname[0] == '!')
        else:
          raise RuntimeError(f'unknown {actname=}')

  def _gen_act_defs(self):
    G = self._pm.G
    for nid in G.nodes:
      if nid in self._act_counters:
        self.out_spraytab['privdefs'][f'T{nid}_NUM_ACTS'] = self._act_counters[nid]
        assert(self._act_counters[nid] == len(self._pm.gdata[nid]['acts']))
        for nact in range(self._act_counters[nid]):
          _tup = self._pm.gdata[nid]['acts'][nact]
          timeofs = _tup[1]
          self.out_spraytab['privdefs'][f'T{nid}_ACT{nact}_TOFS'] = f'TIMEFIX({timeofs})'

  def _gen_privdefs(self):
    G = self._pm.G
    '''what's left:
    "V_XXX()": "((ACTVARS_XXX*)CUR_A1)"
    "XXX_RING_SIZE": "3",
    '''
    dyn_defs = {}
    dyn_defs['USERPROC_COUNT'] = self._pm.cached_number_of_userprocs
    for nid in G.nodes:
      if nid in self._g_list:
        dyn_defs[f'g{nid}_DECL()'] = f'DWORD WINAPI g{nid}(LPVOID lpParam)'
        dyn_defs[f'g{nid}_PRE()'] = 'DEF_THREAD_PRE()'
        dyn_defs[f'g{nid}_POST()'] = 'DEF_THREAD_POST(DEF_THRET)'
      else:
        dyn_defs[f't{nid}_DECL()'] = f'DWORD WINAPI t{nid}(LPVOID lpParam)'
        dyn_defs[f't{nid}_PRE()'] = 'DEF_THREAD_PRE()'
        dyn_defs[f't{nid}_POST()'] = 'DEF_THREAD_POST(DEF_THRET)'

    static_defs = {
      "__TICK": "(((DWORD*)0x7ffe0000)[2])",
      "TICKMS": "(__TICK/10000)",
      "ELAPSED(ms)": "(TICKMS - Z(tick_start) >= ms)",
      "THREAD_INDEX(P)": "(*((int*)P))",
      "ASSERT(e)": "{ if (!(e)) { printf(\"--------- Check failed - %s\\n\", #e);  *(int*)0 = 1; } }",
      "TIMEFIX(T)": "T//(T/3)",
      "DEF_THREAD_PRE()": "XARGSETUP(); CUR_A1 = lpParam; printf(__FUNCTION__\": enter\\n\")",
      "DEF_THREAD_POST(retcode)": "printf(__FUNCTION__\": leave\\n\"); XARGCLEANUP(); return retcode",
      "DEF_THRET": "101990",
    }
    self.out_spraytab['privdefs'] = {**dyn_defs, **static_defs}


  def _gen_intermed_g_procs(self):
    # Generate intermediate reprs for all procs
    G = self._pm.G
    for e in self._hlpvis.tlist_for_e.keys():
      tlist = self._hlpvis.tlist_for_e[e]
      if len(tlist) > 1:
        _thrcreat_lines = []
        for nt in tlist:
          _thrcreat_lines += [f'if (THREAD_INDEX(CUR_A1) == {nt}) {{ _CALL(t{nt}); }}']

        self._g_list += [e]
        self._proc_intermeds[f'g{e}'] = ProcIntermed(
          s_work_threadcreation=['CHILD_A1 = CUR_A1;', *_thrcreat_lines])

        self._proc_intermeds[f't{e}'] = ProcIntermed()
      else:
        assert(len(tlist) == 1)
        self._proc_intermeds[f't{e}'] = ProcIntermed()
        pass # skip


  def _gen_intermed_thread_to_iter_calls(self):
    G = self._pm.G
    gdata = self._pm.gdata
    for nid in G.nodes:
      self._proc_intermeds.setdefault(f't{nid}', ProcIntermed()).s_run_loop += [
        'CHILD_A1 = CUR_A1;',
        f'while (!Z(need_exit)) {{  _CALL(t{nid}_iter);  }}'
      ]

  def _gen_intermed_acts(self):
    G = self._pm.G
    gdata = self._pm.gdata
    # This loop is not DFS. We're numbered nids as t in DFS order. But we're walking here with `for nid in G.nodes:`. The order is not DFS (check nx docs).
    for nid in G.nodes:
      if not 'acts' in gdata[nid]:
        continue

      act_lines = []
      extra_sections = {}

      for acttype, acttimeofs, actname, actparam in gdata[nid]['acts']:
        actnum = self._alloc_new_act_for_t(nid)

        ### Create _cond and _extrastmt based on |acttype|
        if acttype == 'one-shot':
          _cond = f'ELAPSED(T{nid}_ACT{actnum}_TOFS) && !Z(t{nid}data).act_called_flags[{actnum}]'
          _extrastmt = f' Z(t{nid}data).act_called_flags[{actnum}] = TRUE;'

        elif acttype == 'upidx_eq':
          upidx = actparam
          _cond = f'ELAPSED(T{nid}_ACT{actnum}_TOFS) && Z(cur_userproc_idx) == {upidx}'
          # userproc indices start from 1, so compare with NUMBER OF, not NUMBER OF-1
          if upidx == self._pm.cached_number_of_userprocs:
            _extrastmt = 'Z(need_exit) = TRUE;'
          else:
            _extrastmt = 'Z(cur_userproc_idx)++;'

        elif acttype == 'trigger':
          _cond = f'ELAPSED(T{nid}_ACT{actnum}_TOFS)'
          _extrastmt = ''

        elif acttype == 'always':
          _cond = 'TRUE'
          _extrastmt = ''

        else: raise RuntimeError()

        ### Convert act pseudoname to lines, with respect to _cond and _extrastmt; fill |extra_sections| and |act_lines|
        if actname == '!hlt':
          act_lines += ['Sleep(30)']
        elif actname == '!crthread':
          child_nid = actparam
          e = self._hlpvis.e_for_t[child_nid]
          if len(self._hlpvis.tlist_for_e[e]) > 1:
            target_fn = f'g{e}'
          else:
            assert(len(self._hlpvis.tlist_for_e[e]) == 1)
            target_fn = f't{child_nid}'
          act_lines += [f'if ({_cond}) {{ Z(hThread{child_nid}) = CreateThread(0, 0, {target_fn}, &Z(t{child_nid}data), 0, &Z(tid));{_extrastmt}}}']
          # we also need to fill `init - thread inidices` section here
          extra_sections.setdefault('s_init_fillthreadindices', []).append(f'Z(t{child_nid}data).thread_index = {child_nid};')

        elif actname == '!wake':
          pass
        elif actname == '!call_userproc':
          act_lines += [f'if ({_cond}) {{ _CALL(userproc{actparam});  {_extrastmt} }} ']
        else:
          if actname in ['cocrel', 'loadlib' ]: #if acttype in billet_acts: ...
            act_lines +=  [f'if ({_cond}) {{  CHILD_A1 = Z(t{nid}data.{actname}{actnum}_vars); _CALL(A_runonce_{actname}); {_extrastmt} }} ']
            _acts = extra_sections.setdefault('s_init_acts', [])
            _acts.append(f'CHILD_A1 = &Z(t{nid}data.a{actnum}_{actname}_vars);')
            _acts.append(f'_CALL(A_init_{actname});')
            _acts = extra_sections.setdefault('s_uninit_acts', [])
            _acts.append(f'CHILD_A1 = &Z(t{nid}data.a{actnum}_{actname}_vars);')
            _acts.append(f'_CALL(A_uninit_{actname});')
            pass
          else:
            raise RuntimeError()
        pass # continue filling act_lines

      # add formed proc intermed
      self._proc_intermeds[f't{nid}_iter'] = ProcIntermed(s_iter_acts=act_lines,
                                                          **extra_sections)

    return # from _gen_intermed_acts


  def _thread_has_neighbors(self, nid) -> bool:
    e = self._hlpvis.e_for_t[nid]
    neighbor_nids = self._hlpvis.tlist_for_e[e]
    assert(nid in neighbor_nids)  # we're in this list too
    assert(len(neighbor_nids) >= 1)
    return len(neighbor_nids) > 1

  def _gen_proc_opts(self):
    G = self._pm.G
    for nid in G.nodes:
      if nid in self._g_list:
        self.out_spraytab['proc_opts'][f'g{nid}'] = {'is_from_decl': 1}
      else:
        # check if this nid (thread) has neighbors (another threads to run from same entry fn)
        if self._thread_has_neighbors(nid):
          # this thread shares e with other threads, so it's not from decl\
          pass
        else:
          # we're the only thread for entry fn, so from decl
          self.out_spraytab['proc_opts'][f't{nid}'] = {'is_from_decl': 1}

  def _gen_lines(self):
    ### Convert procs' intermediate repr to source code lines and put it into |spraytab|
    spraytab = self.out_spraytab
    for procname in self._proc_intermeds.keys():
      print('procname ', procname)
      intermed = self._proc_intermeds[procname]

      assert(not procname in spraytab['procs'])
      spraytab['procs'].append(procname)

      if not procname in spraytab['lines']:
        spraytab['lines'][procname] = []

      if intermed.s_init_globals:
        spraytab['lines'][procname] += ['// init - globals']
        spraytab['lines'][procname] += intermed.s_init_globals
      if intermed.s_init_fillthreadindices:
        spraytab['lines'][procname] += ['// init - fill thread indices']
        spraytab['lines'][procname] += intermed.s_init_fillthreadindices
      #if intermed.s_init_childargs:
      #  spraytab['lines'][procname] += ['// init - child args']
      #  spraytab['lines'][procname] += intermed.s_init_childargs
      if intermed.s_init_wakers:
        spraytab['lines'][procname] += ['// init - wakers']
        spraytab['lines'][procname] += intermed.s_init_wakers

      if intermed.s_run_loop:
        spraytab['lines'][procname] += ['// run - loop']
        if self._enable_dbgprints:
          spraytab['lines'][procname] += [f'printf("{procname} - running loop...\\n");']
        spraytab['lines'][procname] += intermed.s_run_loop

      if intermed.s_iter_acts:
        spraytab['lines'][procname] += ['// iter - acts']
        spraytab['lines'][procname] += intermed.s_iter_acts

      if intermed.s_work_threadcreation:
        spraytab['lines'][procname] += ['// work - thread creation']
        spraytab['lines'][procname] += intermed.s_work_threadcreation

      if intermed.s_uninit_waitforthreads:
        spraytab['lines'][procname] += ['// uninit - waitforthreads']
        spraytab['lines'][procname] += intermed.s_uninit_waitforthreads
      if intermed.s_uninit_acts:
        spraytab['lines'][procname] += ['// uninit - acts']
        spraytab['lines'][procname] += intermed.s_uninit_acts
      if intermed.s_uninit_wakers:
        spraytab['lines'][procname] += ['// uninit - wakers']
        spraytab['lines'][procname] += intermed.s_uninit_wakers

  def _alloc_new_act_for_t(self, t):
    if not t in self._act_counters:
      ret = 0
      self._act_counters[t] = 1
    else:
      ret = self._act_counters[t]
      self._act_counters[t] += 1
    return ret




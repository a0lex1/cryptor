from dataclasses import dataclass, field
from typing import List, Dict

# Intermediate repr of function's body
@dataclass
class ProcIntermed:
  ### INIT
  s_init_globals: List[str] = field(default_factory=list)
  s_init_fillthreadindices: List[str] = field(default_factory=list)
  #s_init_childargs: List[str] = field(default_factory=list)
  s_init_acts: List[str] = field(default_factory=list)
  s_init_wakers: List[str] = field(default_factory=list)
  ### RUN
  s_run_loop: List[str] = field(default_factory=list)
  ### ITER
  s_iter_acts: List[str] = field(default_factory=list)
  ### WORK
  s_work_threadcreation: List[str] = field(default_factory=list)
  ### UNINIT
  s_uninit_waitforthreads: List[str] = field(default_factory=list)
  s_uninit_acts: List[str] = field(default_factory=list)
  s_uninit_wakers: List[str] = field(default_factory=list)


# Intermediate representation of entire program being generated
@dataclass
class ProgramIntermed:
  conceptually_empty: bool = None
  # Sections
  structs: List[str] = field(default_factory=list)
  struct_fields: Dict[str, List[str]] = field(default_factory=dict)
  zvars: List[str] = field(default_factory=list)
  privdefs: List[str] = field(default_factory=list)
  # Procedures
  proc_intermeds: Dict[str, ProcIntermed] = field(default_factory=dict) #OrderImportant
  # Cache
  cached_depfiles: List[str] = field(default_factory=list)  # ['act_cocrel.cpp', ]


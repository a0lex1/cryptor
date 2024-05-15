from functools import partial
from typing import List

from c2.sprayer.fg.replers.host import Host
from c2.sprayer.fg.replers.module import Module
from c2.sprayer.fg.replers.exceptions import *
from c2.sprayer.fg.replers.textcmd_replacer import TextcmdReplacer
from c2.sprayer.ccode.name_bind_string import NameBindString


class ReplersReplacer(Host):
  def __init__(self, num_slots, modules:List[Module],
               fn_isgood_in=None, fn_isgood_out=None, fn_isgood_inout=None):
    self.__num_slots = num_slots
    self.__modules = modules
    self.__fn_isgood_in = fn_isgood_in
    self.__fn_isgood_out = fn_isgood_out
    self.__fn_isgood_inout = fn_isgood_inout
    handler_map = self.__make_handlers_map()
    self.__textcmd_replacer = TextcmdReplacer(handler_map)
    self.__connect_modules()
    self.__clear()

  def replace_in(self, text:str, pick_history):
    self.__cur_pick_history = pick_history
    self.__cur_fmt_vars = []
    self.__cur_id = 0
    #self.__cur_input_text = text
    self.__slot_cmds = {}
    self.__slot_fn_createresults = {}
    new_text = self.__textcmd_replacer.replace_in(text)
    if len(self.__cur_fmt_vars):
      ret = NameBindString(new_text, self.__cur_fmt_vars)
    else:
      ret = new_text
    self.__clear()
    return ret

  def __clear(self):
    self.__cur_pick_history = None
    self.__cur_fmt_vars = None
    self.__cur_id = None
    #self.__cur_input_text = None
    self.__slot_cmds = None
    self.__slot_fn_createresults = None

  def __make_handlers_map(self):
    handler_map = {}
    for nmod in range(len(self.__modules)):
      mod = self.__modules[nmod]
      handler_map = mod._get_handler_map()
      for cmd_name in handler_map.keys():
        cmd_handler = handler_map[cmd_name]
        handler_map[cmd_name] = partial(self.__cbk_bridge, cmd_handler, cmd_name)
    return handler_map

  # Bridge from underlying TextcmdReplacer's callback to a ReplerHandler callback
  def __cbk_bridge(self, _handler, _cmd,  nslot:int|None, args, piece_loc):
    if nslot == 0:
      raise BadSlotIdError(f'slot can\'t be 0 conceptually, need 1..{self.__num_slots}')
    if type(nslot)==int and nslot>self.__num_slots:
      raise BadSlotIdError(f'slot can\'t be > {self.__num_slots} (actually it is {nslot=})')
    if nslot == None:
      # a command without slot number
      _fn_createresult = _handler(args, piece_loc)
      return _fn_createresult()
    else:
      # a commant WITH slot number
      if nslot in self.__slot_cmds:
        slot_cmd = self.__slot_cmds[nslot]
        if _cmd != slot_cmd:
          raise SlotMismatchError()
        return self.__slot_fn_createresults[nslot]()
      else:
        fn_createresult = _handler(args, piece_loc)
        self.__slot_cmds[nslot] = _cmd
        self.__slot_fn_createresults[nslot] = fn_createresult
        return fn_createresult()

  def __connect_modules(self):
    for nmod in range(len(self.__modules)):
      mod = self.__modules[nmod]
      mod._connect_host(self)

  # Host impl
  def _add_fmt_obj(self, obj):
    self.__cur_fmt_vars.append(obj)

  def _get_next_fmt_obj_id(self) -> int:
    _id = self.__cur_id
    self.__cur_id += 1
    return _id

  def get_fn_isgood_in(self):
    return self.__fn_isgood_in

  def get_fn_isgood_out(self):
    return self.__fn_isgood_out

  def get_fn_isgood_inout(self):
    return self.__fn_isgood_inout


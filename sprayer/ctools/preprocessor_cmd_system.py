import sys
from dataclasses import dataclass

from c2.sprayer.ctools.preprocessor import Preprocessor
from c2.sprayer.ctools.macro_follower import MacroFollower


# Exception classes
class PreprocessorCmdSystemException(Exception): pass
class SubcommandDepthLimitReached(PreprocessorCmdSystemException): pass
class UnknownControlCommand(PreprocessorCmdSystemException): pass
class UnclosedCommands(PreprocessorCmdSystemException): pass
class WrongNumberOfArguments(PreprocessorCmdSystemException): pass


# min_args, max_args - both min and max are included in ranges
# register these through _register_cmd_pair()
@dataclass
class CmdInfo:
  cmd_name:str=None
  min_args:int=None
  max_args:int=None


# A common way of using Preprocessor to build an opencmd/closecmd system (for collectors, etc.)
class PreprocessorCmdSystem:
  @dataclass
  class CmdLocation:
    open_not_close:bool=None
    cmd_index:int=None

  def __init__(self, macro_follower:MacroFollower, control_chars, skip_comments=True):
    self.__preprocessor = Preprocessor(macro_follower, control_chars, skip_comments)
    self.__preprocessor._handle_normal_line = self.__preproc_normal_line
    self.__preprocessor._handle_macro = self.__preproc_macro

    self.cur_opencmd_stack = [] # public; todo: make protected for derived only

    self.__opencmds = []
    self.__closecmds = []
    self.__max_subcommand_depth = None
    self.__initialized = False

  def initialize(self):
    self._setup() # derived registers its commands here
    self.__initialized = True


  # interface
  def input_line(self, line):
    assert(self.__initialized)
    self.__preprocessor.input_line(line)

  def finalize(self):
    if len(self.cur_opencmd_stack):
      print('Current cmd stack:', self.cur_opencmd_stack)
      raise UnclosedCommands('some commands not closed')


  # override this in derived
  def _setup(self):
    # called when initializing, call _register_cmd_pair() here from derived
    raise NotImplementedError()

  def _cmdsys_handle_outside_line(self, line):
    # you can use self._cur_opencmd_stack inside your handlers
    raise NotImplementedError()

  def _cmdsys_handle_inside_line(self, line):
    raise NotImplementedError()

  def _cmdsys_opencmd_hook(self, macro_name, macro_opts):
    # override only if you want
    # Note: called before item is added to tself._cur_opencmd_stack, so self._cur_opencmd_stack can be empty here
    pass

  def _cmdsys_closecmd_hook(self, macro_name, macro_opts):
    # override only if you want; opencmd still can be obtained from self._cur_opencmd_stack
    pass

  def _set_max_subcommand_depth(self, max_subcommand_depth:int):
    self.__max_subcommand_depth = max_subcommand_depth

  # call this from derived
  def _register_cmd_pair(self, opencmd_info:CmdInfo, closecmd_info:CmdInfo):
    assert(not opencmd_info.cmd_name in map(lambda item: item.cmd_name, self.__opencmds))
    assert(not closecmd_info.cmd_name in map(lambda item: item.cmd_name, self.__closecmds))
    self.__opencmds.append(opencmd_info)
    self.__closecmds.append(closecmd_info)


  # internal
  def __preproc_normal_line(self, line):
    # Normal line can be either inside or outside in terms of the mechanism of this class.
    if len(self.cur_opencmd_stack):
      # We're INSIDE some command.
      self._cmdsys_handle_inside_line(line)
    else:
      self._cmdsys_handle_outside_line(line)

  def __preproc_macro(self, macro_name, macro_opts):
    assert(len(self.__opencmds) == len(self.__closecmds))
    cmdloc = self.__find_cmd(macro_name)
    if cmdloc == None:
      raise UnknownControlCommand(f'unknown command - `{macro_name}`, not in open nor close list ({macro_opts=})')
    if cmdloc.open_not_close:

      ### OPEN COMMAND ARRIVED ###

      self.__check_macro_opts(macro_opts, macro_name, self.__opencmds[cmdloc.cmd_index])

      if len(self.cur_opencmd_stack) == self.__max_subcommand_depth:
        print('Current cmd stack:', self.cur_opencmd_stack)
        raise SubcommandDepthLimitReached(f'subcommand({macro_name}, {macro_opts}) breaks the max subcommand depth ({self.__max_subcommand_depth}), see log')

      self._cmdsys_opencmd_hook(macro_name, macro_opts)
      self.cur_opencmd_stack.append(macro_name)

    else:

      ### CLOSE COMMAND ARRIVED ###

      self.__check_macro_opts(macro_opts, macro_name, self.__closecmds[cmdloc.cmd_index])

      opencmd_was = self.__opencmds[cmdloc.cmd_index]
      assert(len(self.cur_opencmd_stack))
      assert(self.cur_opencmd_stack[-1] == opencmd_was.cmd_name)

      self._cmdsys_closecmd_hook(macro_name, macro_opts)
      self.cur_opencmd_stack.pop()


  # returns CmdLocation if cmd found, None otherwise
  def __find_cmd(self, macro_name):
    opencmd_names = list(map(lambda item: item.cmd_name, self.__opencmds))
    if macro_name in opencmd_names:
      return PreprocessorCmdSystem.CmdLocation(True, opencmd_names.index(macro_name))
    closecmd_names = list(map(lambda item: item.cmd_name, self.__closecmds))
    if macro_name in closecmd_names:
      return PreprocessorCmdSystem.CmdLocation(False, closecmd_names.index(macro_name))
    return None


  def __check_macro_opts(self, macro_opts, _macro_title, cmd_info:CmdInfo):
    if cmd_info.min_args != None:
      if len(macro_opts) < cmd_info.min_args:
        raise WrongNumberOfArguments(f'macro {_macro_title} - autocheck number of args failed, got {len(macro_opts)}, but minimum is {cmd_info.min_args}')
    if cmd_info.max_args != None:
      if len(macro_opts) > cmd_info.max_args:
        raise WrongNumberOfArguments(f'macro {_macro_title} - autocheck number of args failed, got {len(macro_opts)}, but maximum is {cmd_info.max_args}')








import re
from sortedcollections import OrderedSet

from c2.sprayer.ctools.preprocessor_cmd_system import PreprocessorCmdSystem, CmdInfo


class TouchCollector(PreprocessorCmdSystem):
  def _setup(self):
    self._register_cmd_pair(CmdInfo('touchlist_begin', max_args=0), CmdInfo('touchlist_end', max_args=0))
    self._register_cmd_pair(CmdInfo('extraheaders_begin', max_args=0), CmdInfo('extraheaders_end', max_args=0))
    self._register_cmd_pair(CmdInfo('extralibs_begin', max_args=0), CmdInfo('extralibs_end', max_args=0))
    self.cur_touchlist = [] # output
    self.cur_extra_headers = OrderedSet() # output, unique (because of set)
    self.cur_extra_libs = OrderedSet() # output, unique (because of set)

  ### TODO: VALIDATION ###

  def _cmdsys_handle_outside_line(self, line):
    pass

  def _cmdsys_handle_inside_line(self, line):
    if self.cur_opencmd_stack[-1]   == 'touchlist_begin':
      code = self.__parse_touchlist_line(line)
      if code != None:
        self.cur_touchlist.append(code)
      
    elif self.cur_opencmd_stack[-1] == 'extraheaders_begin':
      headername = self.__parse_extraheaders_line(line)
      self.cur_extra_headers.add(headername)
      
    elif self.cur_opencmd_stack[-1] == 'extralibs_begin':
      libname = self.__parse_extralibs_line(line)
      self.cur_extra_libs.add(libname)
      
    else:
      raise RuntimeError()

  def __parse_touchlist_line(self, line):
    if re.match(r'^\s*//.*?$', line):
      # skip comments
      return None
    m = re.match(r'^\s*TRASHER_TOUCH\((.*?)\);$', line)
    if not m:
      print('This line is not a TRASHER_TOUCH line:')
      print(line)
      raise RuntimeError('when inside touchlist_begin, only TRASHER_TOUCH() lines are allowed (+comments), no others')
    code = m[1]
    return code

  def __parse_extraheaders_line(self, line):
    return line

  def __parse_extralibs_line(self, line):
    return line


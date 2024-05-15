import argparse
from typing import List, Tuple, Any

from c2.base.stage.handler import Handler
from c2.base.stage.prop_change_info import PropChangeInfo, substitute_propchangeinfo_macros


class TextHandler(Handler):
  def handle_property_change(self, propchange_info:PropChangeInfo, new_data:Any) -> None:
    # do nothing, only validate
    assert(propchange_info.catname == 'text')
    assert(type(new_data) == str)
    

class TextPrintHandler(TextHandler):
  def _parse_argv(self):
    # self._argv
    parser = argparse.ArgumentParser()
    parser.add_argument('--no_stdout', action='store_true')
    parser.add_argument('--stderr', action='store_true')
    self._args = parser.parse_args(self._argv)

  def handle_property_change(self, propchange_info:PropChangeInfo, new_data:Any) -> None:
    super().handle_property_change(propchange_info, new_data)
    if not self.__args.no_stdout:
      sys.stdout.write(new_data)
    if self.__args.stderr:
      sys.stderr.write(new_data)


#StageRunnerExecutor will wrap in try/except, calling uninit in except...?
class TextWriteHandler(TextHandler):
  def __init__(self):
    self.__prev_file_path = None
    self.__f = None
    
  def _parse_argv(self):
    parser = argparse.ArgumentParser()
    parser.add_argument('-f',  '--file', required=True)
    parser.add_argument('-a',  '--append', action='store_true')
    parser.add_argument('-p',  '--print', action='store_true')
    parser.add_argument('-pe', '--print_stderr', action='store_true')
    self._args = parser.parse_args(self._argv)
    
  def handle_property_change(self, propchange_info:PropChangeInfo, new_data:Any) -> None:
    super().handle_property_change(propchange_info, new_data)
    file_path = self._args.file
    if self._args.append:
      mode = 'a'
    else:
      mode = 'w'
    # For every property change, substitute macros to args again and see if file_path changed
    # If so, reopen the file
    file_path = substitute_propchangeinfo_macros(file_path, propchange_info)
    if file_path != self.__prev_file_path:
      # file_path changed (or this is the first time, e.g. when self.__prev_file_path==None)
      if self.__f:
        self.__f.close()
      self.__f = open(file_path, mode)
      self.__prev_file_path = file_path
      
    self.__f.write(new_data)
    return

  def uninit(self):
    if self.__f:
      self.__f.close()
      self.__f = None



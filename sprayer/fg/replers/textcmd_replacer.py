import re
from typing import Callable, List, Tuple, Dict

#                      slot       args       piece_loc        (ret)
FnHandleCmd = Callable[[int|None, List[str], Tuple[int,int]], str]


# Currently works through re.sub() + split()
# Supports slots
class TextcmdReplacer:
  def __init__(self, handler_map:Dict[str, FnHandleCmd]):
    self.__handler_map = handler_map
    handler_names = self.__handler_map.keys()
    # inserting user data into the regular expression
    retext = f'({"|".join(handler_names)})(\d*)\(([a-zA-Z0-9\-_, ]*)\)'
    self.__re = re.compile(retext)

  def replace_in(self, text:str) -> str:
    if 0==len(self.__handler_map):
      return text
    def fnrepl(matchobj):
      cmd_name = matchobj[1]
      cmd_slot = int(matchobj[2]) if matchobj[2] != '' else None
      cmd_args = [_.strip() for _ in matchobj[3].split(',')]
      handler = self.__get_handler_for_cmd(cmd_name)
      assert(handler != None)
      piece_loc = matchobj.span()
      assert(type(piece_loc) == tuple) # can it be anything else?
      ### CALL THE HANDLER
      ret = handler(cmd_slot, cmd_args, piece_loc)
      ### RETURN WHAT HANDLER RETURNED
      return ret
    return re.sub(self.__re, fnrepl, text)

  def __get_handler_for_cmd(self, cur_cmd_name) -> FnHandleCmd | None:
    if cur_cmd_name in self.__handler_map:
      return self.__handler_map[cur_cmd_name]
    return None


def test_textcmd_replacer():
  t = TextcmdReplacer({'format_dosk': lambda nslot, args, piece_loc: f'FormatDoskReply({args}){piece_loc}',
                       'kill_yourself': lambda nslot, args, piece_loc: f'SuicideReply({args}){piece_loc}'})
  r = t.replace_in('hi lalala\n'
                   'do you want to format_dosk(5, 3, lala)\n'
                   'hshs\n'
                   'kill_yourself(5-10, abc d), ok?')
  expected = ('hi lalala\n'
              'do you want to FormatDoskReply([\'5\', \'3\', \'lala\'])(25, 48)\n'
              'hshs\n'
              'SuicideReply([\'5-10\', \'abc d\'])(54, 80), ok?')
  if r != expected:
    print('Got', r)
    print('Expected', expected)
    raise RuntimeError('unexpected string, see log')


if __name__ == '__main__':
  test_textcmd_replacer()




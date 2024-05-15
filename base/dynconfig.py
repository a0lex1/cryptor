import sys, json, re
from typing import List

from c2.common.utils import strargs2map


# Dynconfig has no dependencies to/from Unischema, Jen and DynJen; it's a separate mechanism
# But it is still infra...?

class Dynconfig:
  def __init__(self):
    self._programs = {}

  # def dispfn(self, argdict, input_lines) <- input_lines without \n
  def _add_program(self, progname, dispfn):
    assert(not progname in self._programs)
    self._programs[progname] = dispfn

  def _finalize(self): # hook me
    pass

  def load_from_lines(self, lines: List[str]):
    cur_prog_name = None
    cur_prog_argdict = None
    cur_prog_input_lines = None
    for nline in range(len(lines)):
      line = lines[nline]
      if '#' in line:
        line = line[0:line.index('#')]
      line = line.rstrip()
      if line == '': # skip empty lines
        continue
      if line.startswith('$$$'):
        # control line(s) start(s) with $$$
        if cur_prog_name:
          # New program means we need to execute current program (flush input lines) first
          #print(f'[line {nline}] calling program {cur_prog_name} with argdict {cur_prog_argdict}')
          ### CALL PROGRAM ###
          self._programs[cur_prog_name](cur_prog_argdict, cur_prog_input_lines)
        # open new proc line reader
        m = re.match('^\$\$\$([a-zA-Z0-9_]+) (.+?)$', line)
        cur_prog_name, raw_args = m.groups()
        if not cur_prog_name in self._programs:
          raise RuntimeError(f'[line {nline}] unknown program - {cur_prog_name}, raw args: {raw_args}')
        cur_prog_argdict = strargs2map(raw_args)
        cur_prog_input_lines = []
        #print(f'[line {nline}] opening line reader for proc {cur_prog_name}')
      else:
        # not a control line, a usual line
        if not (cur_prog_name):
          raise RuntimeError(f'[line {nline}] unexpected non-control (no current prog) - {line}')
        #print(f'[line {nline}] adding line to current proc')
        cur_prog_input_lines.append(line)
      pass

    ### EOF, CALL LAST PROGRAM ###
    if cur_prog_name:
      self._programs[cur_prog_name](cur_prog_argdict, cur_prog_input_lines)

    self._finalize() # chance for hook
    return


class DynconfigWithProperties(Dynconfig):
  def __init__(self):
    super().__init__()
    self._props = {}
    self._add_program('add_property_json', self._prg_add_property_json)

  def props(self):
    return self._props

  def _prg_add_property_json(self, argdict, input_lines):
    assert(len(argdict) == 1)
    propname = argdict['/property']
    assert(propname)
    jsontext = '\n'.join(input_lines)
    dictval = json.loads(jsontext)
    #print(f'adding property `{propname}`')
    self._add_property(propname, dictval)

  def _add_property(self, k, v):
    assert(not k in self._props) # no overwrite!
    self._props[k] = v


_test_dynconfig_text = \
'''
# HELLO FROM COMMENT 1
# comment 2
# comment 3
$$$add_property_json /property animals
{
  "elephant": {
    "children": {
      "one": 1,
      "two": 2
    }
  },
  "tiger": {
    "three": 3
  }
}
$$$add_property_json /property humans1
{
  "humans are shit": true,
  "test sexy value": 1,
  "somedict": {
    "aaa": 1,
    "bbb": 2
  }
}

$$$add_property_json /property humans2
{
  "humans are shit": true,
  "test sexy value": 1,
  "somedict": {
    "aaa": 1,
    "bbb": 2
  }
}

$$$add_property_json /property humans3
{
  "humans are shit": true,
  "test sexy value": 1,
  "somedict": {
    "aaa": 1,
    "bbb": 2
  }
}'''

def test_dynconfig(argv):
  b = DynconfigWithProperties()
  b.load_from_lines(_test_dynconfig_text.split('\n'))
  print(b.props())
  assert(b.props()['animals'] == { "elephant": { "children": { "one": 1, "two": 2 } }, "tiger": { "three": 3 } })
  humexpect = { "humans are shit": True, "test sexy value": 1, "somedict": { "aaa": 1, "bbb": 2 } }
  assert(b.props()['humans1'] == humexpect  )
  assert(b.props()['humans2'] == humexpect  )
  assert(b.props()['humans3'] == humexpect  )


if __name__ == '__main__':
  test_dynconfig(sys.argv[1:])










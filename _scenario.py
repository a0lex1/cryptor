# Indenepnded class, can be in common/
class Scenario:
  def __init__(self, out_dir, subs=None):
    self.out_dir = out_dir
    if subs == None:
      subs = []
    self.subs = subs
    self.bat_lines = {}
    self.order = []

  def add_stage(self, batname, commands:list=None):
    if commands == None:
      commands = []
    assert(not batname in self.bat_lines)
    self.bat_lines[batname] = commands
    #self.bat_lines[batname].append(commands)
    self.order.append(batname)

  # sugar
  def add_cmd(self, command):
    cur_stage = self.order[-1]
    arr = self.bat_lines[cur_stage]
    arr.append(command)

  #possible: export_json(self):
  def export_bat(self):
    o = ''
    for stagename in self.order:
      o += f'echo echo > {self.out_dir}\\{stagename}.bat\n'
      for cmd in self.bat_lines[stagename]:
        nline = 0
        #if '>' in cmd:
        #  breakpoint()
        cmd = self._replace_subs(cmd)
        cmd = self._escape(cmd)
        o += f'echo {cmd} ^&^& (echo OK) ^|^| (echo ***Err in {stagename}.bat--act {nline}*** ^&^& goto exit) ' +\
             f'>> {self.out_dir}\\{stagename}.bat\n'
        nline += 1
      o += f'echo :exit >> {self.out_dir}\\{stagename}.bat\n'
      o += '\n'
    return o

  def _escape(self, line):
    line = line.replace('>', '^>')
    line = line.replace('<', '^<')
    line = line.replace('|', '^|')
    line = line.replace('&', '^&')
    line = line.replace('%', '%%')
    return line

  def export_bat_to_file(self, batpath):
    batpath = self._replace_subs(batpath)
    batpath = batpath.replace('%~dp0', self.out_dir)
    open(batpath, 'w').write(self.export_bat())

  def _replace_subs(self, line):
    for subk in self.subs.keys():
      while subk in line:
        line = line.replace(subk, self.subs[subk])
    return line

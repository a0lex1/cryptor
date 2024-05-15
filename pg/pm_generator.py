from c2.pg.program_model import ProgramModel


class PMGenerator:
  #def __init__(self, num_usercodes, opts:dict, pm:ProgramModel):
  def __init__(self, opts:dict, pm:ProgramModel):
    self.opts = opts
    self._pm = pm
    
  def execute(self):
    raise NotImplementedError()



class PMGeneratorEmpty(PMGenerator):
  def execute(self):
    assert(self.opts == {})



class PMGeneratorAlpha(PMGenerator):
  def execute(self):
    #self._pm.G[] = ...
    raise RuntimeError('todo')



class PMGeneratorFull(PMGenerator):
  def execute(self):
    raise RuntimeError('todo')


from typing import Any, Callable, Iterable, Dict, List


class StageRunner:
  def __init__(self):
    self.__fn_next_stage = None
    self.__next_stage_name = None
    self.__counter = -1 # will be 0 after first proceed()
    self.__props = {}      # {'call_graph': G, 'log': None}   (set to None before every stage)
    self.__prop2cat = {}   # {'call_graph': 'graph', 'log': }  (registration info)
    self.__changed_props = None

  ### --- public ---
  def stages_left(self) -> bool:
    return self.__fn_next_stage != None

  def stage_name(self) -> str:
    return self.__next_stage_name

  def stage_index(self): #delme
    return self.__counter

  def stage(self):
    self.__clear_props()
    # Ensure all values are None
    assert(list(self.__props.values()).count(None) == len(self.__props.values()))

    self.__changed_props = None

    # remember old fn, we're gonna need to compare it
    oldfn = self.__fn_next_stage

    ### call derived class
    self.__fn_next_stage()

    # detect forget-to-set_next_stage mistake (causes dead loop)
    if self.__fn_next_stage == oldfn:
      raise RuntimeError(f'stupid programmer forget to call _proceed() at stage \'{self.__next_stage_name}\'. if you\'re making such mistakes, consider not being a programmer')
    # following check is excessive cuz we have 'for chpropname...' checking code block instead.
    #if not set(self.__changed_props.keys()).issubset(set(self.__props.keys)):
    #  raise RuntimeError(f'some changed props returned by handler are not registered')

    if self.__changed_props != None:
      # Validate and copy changed props
      for chpropname in self.__changed_props.keys():
        chpropdata = self.__changed_props[chpropname]
        if chpropdata == None:
          raise RuntimeError(f'stupid programmer used None as property\'s `{chpropname}` data')
        if not chpropname in self.__props:
          raise RuntimeError(f'stupid programmer returned nonexisting prop name (`{chpropname}`) in changed props')
        assert(chpropname in self.__prop2cat)
        self.__props[chpropname] = chpropdata

  ### --- public - props ---
  def get_all_props(self) -> Iterable:
    return self.__props.keys()

  def is_prop_changed(self, propname) -> bool:
    return self.__props[propname] != None

  def get_prop_data(self, propname) -> Any:
    return self.__props[propname]

  def get_prop_category(self, propname) -> str:
    return self.__prop2cat[propname]

  ### --- protected for derived(s) ---
  def _register_prop(self, propname, propcat):       # 'call_graph', 'graph'
    assert(not propname in self.__props)
    assert(not propname in self.__prop2cat)
    self.__props[propname] = '#ClearMe'
    self.__prop2cat[propname] = propcat
  
  # From every stage's fn, implementation should call _proceed; changed props must be registered
  def _proceed(self, fn_next_stage:Callable, title:str, description:str=None, changed_props:Dict[str,Any]=None): #   { 'graph': self.__skel.G, 'any_prop': AnyData }
    assert (description == None)
    if not fn_next_stage:
      assert (title == None)
      assert (description == None)
    else:
      assert (type(title) == str)
    self.__fn_next_stage = fn_next_stage
    self.__next_stage_name = title
    self.__counter += 1
    # save changed props, they will be validated in stage() after calling __fn_next_stage
    self.__changed_props = changed_props

  ### --- private for internal use ---
  def __clear_props(self):
    for propname in self.__props.keys():
      self.__props[propname] = None


############# TEST CODE ###################

# A helper class for women if low boobz 
class _BoobInflator(StageRunner):
  def __init__(self):
    super().__init__()
    self._register_prop('log', 'cat1')
    self._register_prop('shit', 'cat2')
    self._proceed(self.__st_takeoff_bra, 'takeoff bra')
  def __st_takeoff_bra(self):
    print('taking off bra... done')
    my_log = 'hi from takeoff bra\n'
    my_log += 'line2\n'
    self._proceed(self.__st_connect_air_pipe, 'connect air pipe', changed_props={'log': my_log})
  def __st_connect_air_pipe(self):
    print('connecting air pipe...done')
    self._proceed(self.__st_open_air, 'open air', changed_props={'shit': 'bla'})
  # stage without changed props
  def __st_open_air(self):
    print('opening air...air opened')
    self._proceed(self.__st_close_air, 'close air') # no changed props!
  def __st_close_air(self):
    print('closing air..air closed, bobs were inflated successfully! done!')
    self._proceed(None, None, changed_props={'log': 'all done', 'shit': 'sex'})


def _test_stage_runner():
  inflator = _BoobInflator()
  assert(list(inflator.get_all_props())== ['log', 'shit'])

  assert(inflator.get_prop_category('log') == 'cat1')
  assert(inflator.get_prop_category('shit') == 'cat2')

  assert(inflator.stages_left())
  inflator.stage()
  #assert(len(inflator.get_prop_ischanged_map()) == 1)
  #assert(inflator.get_prop_ischanged_map()['log'].count('\n') == 2)
  assert(inflator.is_prop_changed('log'))
  assert(inflator.get_prop_data('log').count('\n') == 2) # check prop's data
  assert(not inflator.is_prop_changed('shit'))

  assert(inflator.stages_left())
  inflator.stage()
  assert(inflator.is_prop_changed('shit'))
  assert(not inflator.is_prop_changed('log'))

  # A stage without changed props
  assert(inflator.stages_left())
  inflator.stage()
  assert(not inflator.is_prop_changed('shit'))
  assert(not inflator.is_prop_changed('log'))

  assert(inflator.stages_left())
  inflator.stage()
  assert(inflator.is_prop_changed('shit'))
  assert(inflator.is_prop_changed('log'))
  assert(inflator.get_prop_data('log') == 'all done')
  assert(inflator.get_prop_data('shit') == 'sex')

  assert(not inflator.stages_left())


def _test():
  _test_stage_runner_props()

if __name__ == '__main__':
  _test()


from c2.sprayer.vp.vrpicker import *
from c2.sprayer.vp.vls_shape import *


class VRPickerFactory:
  def create_vrpicker(self, vls, state:VRPickerState, opts, rng) -> VRPicker: raise NotImplementedError()
  def create_vrpicker_state(self) -> VRPickerState: raise NotImplementedError()
  def create_vrpicker_state_initializer(self) -> VRPickerStateInitializer: raise NotImplementedError()
  def create_vrpicker_state_printer(self) -> VRPickerStatePrinter: raise NotImplementedError()

def create_vrpicker_factory(vrpicker_name):
  if vrpicker_name == 'seqbased':
    return SeqbasedVRPickerFactory()
  else:
    return InsularVRPickerFactory()


class SeqbasedVRPickerFactory(VRPickerFactory):
  def create_vrpicker(self, vls, state, opts, rng):
    return SeqbasedVRPicker(vls, state, opts, rng)
  def create_vrpicker_state(self, vls_shape):
    return SeqbasedVRPickerState(vls_shape)
  def create_vrpicker_state_initializer(self):
    return SeqbasedVRPickerStateInitializer()
  def create_vrpicker_state_printer(self):
    return SeqbasedVRPickerStatePrinter()


class InsularVRPickerFactory(VRPickerFactory):
  def create_vrpicker(self, vls, state, opts, rng):
    return InsularVRPicker(vls, state, opts, rng)
  def create_vrpicker_state(self, vls_shape):
    return InsularVRPickerState(vls_shape)
  def create_vrpicker_state_initializer(self):
    return InsularVRPickerStateInitializer()
  def create_vrpicker_state_printer(self):
    return InsularVRPickerStatePrinter()


def _test_factory(vrpicker_name, opts, rng):
  import io
  fac = create_vrpicker_factory(vrpicker_name)
  vls = ...
  vls_shape = vls_shape_from_vls(vls)
  state = fac.create_vrpicker_state(vls_shape)
  state_initer = fac.create_vrpicker_state_initializer()
  state_initer.init_state_from_vls(state, vls)
  state_printer = fac.create_vrpicker_state_printer()
  vrpicker = fac.create_vrpicker(vls, state, opts, rng)
  buf = io.StringIO()
  state_printer.print(state, buf)
  assert(buf != '') #idk, just want something

def test_vrpicker_factory():
  _test_factory('seqbased', {'weight_type': 'natural'})
  _test_factory('insular', {'weight_type': 'natural', 'coast_increase_type': 'proportional'})

if __name__ == '__main__':
  test_vrpicker_factory()


from c2.sprayer.vp.test_random_var_picker import test_random_var_picker # old
from c2.sprayer.vp.diagonal_vrpicker import test_diagonal_vrpicker
from c2.sprayer.vp.vls_shape import test_vls_shape
from c2.sprayer.vp.test_vrpickers import VRPickersTest


def test_var_picking():
  test_random_var_picker()
  test_diagonal_vrpicker()
  test_vls_shape()
  VRPickersTest([]).execute() # no args, do the default test

if __name__ == '__main__':
  test_var_picking()




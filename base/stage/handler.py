from dataclasses import dataclass, field
from typing import List, Dict, Callable, Any

from c2.base.stage.prop_change_info import PropChangeInfo, substitute_propchangeinfo_macros

# {
#    'apple': {
#      'eat'    : Handler(...),
#      'squeeze': Handler(...),
#      ...
#    },
#    'another_category': {
#      'another_operation': ...,
#

# Skeleton for building handlers
class Handler:
  # |argv| may contain macros that evaluates differently in different calls to handle_property_change()
  # (for example, $(StageName) -> PropChangeInfo.stagename -- will be different on evey stage)
  # Derived class(es) should to reevaluate it in every handle_property_change() if there is something to reevaluate (log file paths, etc.)
  def init(self, argv: List[str]):
    self._argv = argv
    self._parse_argv()

  # called once; a chance for derived to work with _argv
  def _parse_argv(self):
    pass

  def handle_property_change(self, propchange_info: PropChangeInfo, new_data: Any) -> None:
    raise NotImplementedError()

  def uninit(self, argv: List[str]):
    pass


@dataclass
class HandlerTable:
  __registered_ops: Dict[str, Dict[str, Handler]] = field(default_factory=dict)

  def register_operation_for(self, prop_cat_name, op_name, handler:Handler):
    self.__registered_ops.setdefault(prop_cat_name, {}).setdefault(op_name, {})
    self.__registered_ops[prop_cat_name][op_name] = handler

  def get_operations_for(self, prop_cat_name) -> Dict[str, Callable]:
    return self.__registered_ops[prop_cat_name]



class TestHandler(Handler):
  def __init__(self, title):
    self.__title = title

  def handle_property_change(self, propname: str, catname: str, new_data: Any, args: List[str]) -> None:
    print(f'{self.__title}\' property change: {propname=} {catname=} {new_data=} {args=}')


def test_handler_table(argv=None):
  ht = HandlerTable()
  th1, th2, th3 = TestHandler('classic'), TestHandler('rock'), TestHandler('jazz')
  ht.register_operation_for('log', 'print', th1)
  ht.register_operation_for('graph', 'show', th2)
  ht.register_operation_for('graph', 'save', th3)
  ops = ht.get_operations_for('log')
  print(ops)
  assert (list(ops.keys()) == ['print'])
  ops = ht.get_operations_for('graph')
  print(ops)
  assert (list(ops.keys()) == ['show', 'save'])


if __name__ == '__main__':
  test_handler_table()

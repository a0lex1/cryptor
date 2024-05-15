import jsonschema
from typing import List

from c2.test.case import Case
from c2.infra.jen import Jen


# Base for case generators
class CaseGenerator:
  def set_source_material(self, jendoc_casetest_opts: dict, jen_order: List[str],
               gentypes:List[str]=None):
    self._jendoc_casetest_opts = jendoc_casetest_opts
    self._jen_order = jen_order
    assert (gentypes != None)
    self._gentypes = gentypes
    self._export_rvas = {}  # {'ExportedFunc': 0xRVA}
    self._first_case_index = None

  def number_of_cases(self) -> int:
    jen = Jen(self._jendoc_casetest_opts, self._jen_order)
    jen.build()
    njen_iters = jen.number_of_iterations()
    # each casetest_opts iter generates test for every payload from gentypes
    total_cases = njen_iters * self._actual_number_of_gentypes()
    return total_cases

  def __iter__(self) -> Case:
    self._init_first_iter()

    jen = Jen(self._jendoc_casetest_opts, self._jen_order)
    jen.build()

    for niter in range(jen.number_of_iterations()):
      inst = jen.iteration(niter)
      jsonschema.validate(inst, self._jendoc_casetest_opts)
      yield from self._gen_case_with_casetest_opts(inst)


  # override me, chance to correct gentypes
  def _actual_number_of_gentypes(self) -> int:
    return len(self._gentypes)

  # override me
  def _init_first_iter(self):
    pass

  def _gen_case_with_casetest_opts(self, paytest_opts) -> Case:
    raise NotImplementedError('implement this in derived class')





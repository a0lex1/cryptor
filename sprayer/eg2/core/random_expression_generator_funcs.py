from c2.sprayer.misc._ensure_objvars_set import ensure_objvars_set


class RandomExpressionGeneratorFuncs:
  def __init__(self,
               fn_probab_var=lambda lev: 1 / (lev + 1),  # 1, 0.5, 0.25, ...,
               fn_probab_const=lambda lev: 1 / (lev + 1),
               fn_probab_op=lambda lev: 1 / (lev + 1),
               fn_probab_op_plus=lambda lev: 1,
               fn_probab_op_minus=lambda lev: 1,
               fn_probab_op_mul=lambda lev: 1,
               fn_probab_const_byte=lambda lev: 1,
               fn_probab_const_word=lambda lev: 1,
               fn_probab_const_dword=lambda lev: 3,
               fn_probab_const_isflag=lambda lev: 1):
    self.fn_probab_var = fn_probab_var
    self.fn_probab_const = fn_probab_const
    self.fn_probab_op = fn_probab_op
    self.fn_probab_op_plus = fn_probab_op_plus
    self.fn_probab_op_minus = fn_probab_op_minus
    self.fn_probab_op_mul = fn_probab_op_mul
    self.fn_probab_const_byte = fn_probab_const_byte
    self.fn_probab_const_word = fn_probab_const_word
    self.fn_probab_const_dword = fn_probab_const_dword
    self.fn_probab_const_isflag = fn_probab_const_isflag
    ensure_objvars_set(self, 'fn_')



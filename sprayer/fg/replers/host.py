# We split ReplersReplacer to modules which implement separate commands. We did it to have an ability
# to debug the parts separately from parts enabled in production.
class Host:
  def _add_fmt_obj(self, obj):
    raise NotImplementedError()
  def _get_next_fmt_obj_id(self) -> int:
    raise NotImplementedError()
  def get_fn_isgood_in(self):
    raise NotImplementedError()
  def get_fn_isgood_out(self):
    raise NotImplementedError()
  def get_fn_isgood_inout(self):
    raise NotImplementedError()


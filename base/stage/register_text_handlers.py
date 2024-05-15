from c2.base.stage.handler import handler_table
from c2.base.stage.text_handlers import TextPrintHandler, TextWriteHandler


def register_text_handlers(htable:HandlerTable, register_print=True, register_write=True):
  if register_print:
    htable.register_operation_for('text', 'print', TextPrintHandler())
  if register_write:
    htable.register_operation_for('text', 'write', TextWriteHandler())

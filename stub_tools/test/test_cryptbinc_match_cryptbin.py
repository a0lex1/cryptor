oh. cryptbin doesn't have decrypt functionality. can't just encode/decode. can only test matching of encoded data.

class Test:
  def __init__(self, input_data=None, cryptbin_path=None, cryptbin_argv=None):
    if cryptbin_argv == None:
      cryptbin_argv = []
    self.input_data = input_data
    self.output_data = None
    self.cryptbin_path = cryptbin_path
    self.cryptbin_argv = cryptbin_argv # allowed: -k -x -w -r --tail_count --tail_key

  def execute(self):
    ss


def test_cryptbin():
  test = Test("a", cryptbin_argv=["-k", "12", "-x", "13", "-w", "4", ])
















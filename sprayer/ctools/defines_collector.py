class DefinesCollector:
  def __init__(self):
    self._collected_definitions = []
  def get_collecteddefs(self):
    return self._collected_definitions
  def collect_definitions(self, header_text):
    for line in header_text.split('\n'):
      if line.startswith('#define '):
        macro_name = line.split(' ')[1]
        self._collected_definitions.append(macro_name)

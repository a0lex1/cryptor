#TODO: urllib
def parse_scheme_address(s):
  z = s.index('://')
  scheme, addr = s[:z], s[z+3:]
  return scheme, addr


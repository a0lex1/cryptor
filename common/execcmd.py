import os

# pass expect_ret=None if you don't want to expect particular code
def execcmd(cmd, verbose=True, expect_ret=0):
  if verbose:
    print('[ ] [ EXECUTING ]', cmd)
  ret_code = os.system(cmd)
  if expect_ret != None:
    if ret_code != expect_ret:
      raise RuntimeError(f'cmd returned: {ret_code}, expected: {expect_ret} - {cmd}')
  return ret_code


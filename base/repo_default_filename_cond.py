import os


# Common concept. Distinguishes the rules of what files are important in repository
def repo_default_filename_cond(file: str):
  if file.startswith('_'):
    # these are marked as temporary/debug
    return False
  if not os.path.isdir(file):
    # allow repository dir to contain ANY files
    return False
  return True



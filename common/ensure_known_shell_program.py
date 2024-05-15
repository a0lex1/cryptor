import shutil

def ensure_known_shell_program(progname):
  if not shutil.which(progname):
    raise RuntimeError(f'{progname} not in %PATH% ?')


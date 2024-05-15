import os

from ..config import RAR_EXE_PATH

def rar_cmdline(files, archive_name):
  rfiles = [os.path.realpath(file) for file in files]
  rarchive_name = os.path.realpath(archive_name)
  return f'"{RAR_EXE_PATH}" a -ep1 -m5 {rarchive_name} {" ".join(rfiles)}' # no -r




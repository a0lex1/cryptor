import fnmatch
from typing import List

def fnmatch_one_of(path, masks:List[str]) -> bool:
  for mask in masks:
    if fnmatch.fnmatch(path, mask):
      return True
  return False

import shutil, os

#Vulnerable to Race Condition
def recreate_dir(dir_path: str):
  if os.path.isdir(dir_path):
    shutil.rmtree(dir_path, ignore_errors=True)
  elif os.path.isfile(dir_path):
    raise RuntimeError('danger, file is placed where the dir is expected')
  os.makedirs(dir_path, exist_ok=False)


import glob, shutil, os

def clear_dir(dir_path):
  files = glob.glob(OutBase+'/.*') # warning, it was /*, then changed to /.* because of https://stackoverflow.com/a/5756937
  for file in files:
      if os.path.isdir(file):
        #print(f'removing dir {file}')
        shutil.rmtree(file)
      else:
        #print(f'removing file {file}')
        os.remove(file)


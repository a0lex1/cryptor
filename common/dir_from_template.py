import sys
import os
import shutil

###

def expand_macros(text, macros_map):
  for m in macros_map:
    text = text.replace(m, macros_map[m])
  return text

def file_expand_macros(file_path, macros_map, silent=False):
  x = file_path
  if not silent:
    print(x)
  f = open(x, "r")
  if not silent:
    print(f)
  new_contents = expand_macros(f.read(), macros_map)
  open(file_path, 'w').write(new_contents)

def copy_make_path(src, dst):
  if not os.path.exists(os.path.dirname(dst)):
    os.makedirs(os.path.dirname(dst))
  shutil.copyfile(src, dst)

def dir_from_template(source_dir, dest_dir, macros_map, silent=False):
  for source_subdir, _source_dirs, source_files in os.walk(source_dir):
    rel_dir = source_subdir[len(source_dir):].lstrip('/').lstrip('\\')

    dest_subdir = os.path.join(dest_dir, expand_macros(rel_dir, macros_map))
    os.makedirs(dest_subdir, exist_ok=True)

    for source_file in source_files:
      source_path = os.path.join(source_subdir, source_file)
      dest_path = os.path.join(dest_dir, os.path.join(expand_macros(rel_dir, macros_map), expand_macros(source_file, macros_map)))

      if not silent:
        print(source_path)
        print('===>')
        print(dest_path)
        print('')
        print('')

      copy_make_path(source_path, dest_path)
      file_expand_macros(dest_path, macros_map, silent)

###

def dir_from_template_main():
  if len(sys.argv) < 4:
    print('Usage: dir_from_template.py <source_dir> <dest_dir> <$macro1$=value[, ...]>')
    exit()

  source_dir = sys.argv[1]
  dest_dir = sys.argv[2]
  macro_map = {}

  if os.path.exists(dest_dir):
    print('Warn: Destination directory exists - '+dest_dir)

  args = sys.argv[3:]
  for i in range(len(args)):
    k, v = args[i].split('=')
    macro_map[k] = v

  dir_from_template(source_dir, dest_dir, macro_map)


###

if __name__ == "__main__":
  dir_from_template_main()

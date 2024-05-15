import argparse, re, pprint, random, os, sys

print('TODO! This spoils p2code/p2code_end (or democode/democode_end) order!')
exit()

if __name__ == '__main__':
  parser = argparse.ArgumentParser(os.path.basename(__file__))
  parser.add_argument('-m', '--map_file', required=True)
  parser.add_argument('-o', '--order_file', required=True)
  args = parser.parse_args()

  statics_found = False
  symnames = []

  for line in open(args.map_file, 'r').readlines():
    # 
    # 0000:00000000       ___safe_se_handler_table   0000000000000000     <absolute>
    #
    # 0001:00000160       ??0exception@std@@QEAA@AEBV01@@Z 0000000140001160 f i main.obj
    #
    # 0001:000001c0       ??_Ebad_alloc@std@@UEAAPEAXI@Z 00000001400011c0 f i * CIL library *:* CIL module *
    #
    # 0001:00000360       __local_stdio_printf_options 0000000140001360 f i main.obj
    #
    # Static symbols < end marker, those don't exist (linker says)
    #
    line = line.rstrip()
    if line == ' Static symbols':
      statics_found = True
      break
    m = re.findall('([a-zA-Z0-9]{4}):([a-zA-Z0-9]{8}) +(.*?) ([a-zA-Z0-9]{16}).*?', line)
    # |m| is a list of tuples where we need [2]
    #print(line, m)
    if not m:
      continue
    assert(len(m) == 1)
    seg, ofs, symname, rva_plus_base = m[0]
    symnames.append(symname)

  # IDK. Maybe statics are optional.
  assert(statics_found)

  random.shuffle(symnames)

  f = open(args.order_file, 'w')
  for symname in symnames:
    f.write(symname + '\n')
  f.close()


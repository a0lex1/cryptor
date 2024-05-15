import argparse, re, io, os, sys, pprint


_sd = os.path.dirname(__file__)
dllpath = sys.argv[1]
dlltitle = os.path.basename(dllpath)
dlltitle = dlltitle.split('.')[0]
dumpexp_file = f'{dlltitle}.txt'

cmd = f'dumpbin.exe /exports {dllpath} > {dumpexp_file}'
print(f'executing: {cmd}')
not os.system(cmd) or exit(-1)

funcnames = []

buf = open(dumpexp_file, 'r').read()

for line in buf.split('\n'):
  m = re.match('\s+\d+\s+[A-Z0-9]+\s+([A-Z0-9]+ )?([\w\d]+)', line)
  if not m:
    continue
  funcnames.append(m[2])

def wr(str, fio):
  print(str)
  fio.write(str+'\n')


with open(f'{dlltitle}.dll.def', 'w') as f:
  wr(f'LIBRARY {dlltitle}', f)
  wr('EXPORTS', f)
  for funcname in funcnames:
    #wr(f'  X{funcname}={funcname}', f)
    wr(f'  {funcname}', f)

# TODO: /MACHINE:{ARM|ARM64|ARM64EC|ARM64X|EBC|X64|X86}
not os.system(f'lib /def:{dlltitle}.dll.def /out:{dlltitle}_Win32.dll.lib /machine:X86') or exit(-1)
not os.system(f'lib /def:{dlltitle}.dll.def /out:{dlltitle}_x64.dll.lib /machine:X64') or exit(-1)

#os.unlink(dumpexp_file)




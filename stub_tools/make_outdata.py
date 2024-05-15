import os, sys, json, re

if len(sys.argv) != 2:
  print('usage: script <dir>')
  exit(1)

# 'export_name' from module.def
# 'seeds' from seedfile


dp = sys.argv[1]

data = open(fr'{dp}/module.def', 'r').read()
m = re.findall('EXPORTS\s+([a-zA-Z0-9_]+)=EvilProc', data)
print(m)
assert(m)

seeddict = json.load(open(fr'{dp}/seedfile', 'r'))

outdata = {
  'export_name': m[0],
  'seeds': seeddict
}


json.dump(outdata, open(fr'{dp}/_OUTDATA_.json', 'w'), indent=2)


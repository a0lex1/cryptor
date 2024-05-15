import argparse, os, sys

from c2.infra.parse_worker import parse_worker
from c2.common.buildsol import buildsol


#
# Usage: build.py  [--only prj1[ prj2]]  [--rebuild|--clean] 
#

def build_main(argv):
  parser = argparse.ArgumentParser(os.path.basename(__file__))

  g = parser.add_mutually_exclusive_group(required=False)
  g.add_argument('--rebuild', action='store_true')
  g.add_argument('--clean', action='store_true')

  #parser.add_argument('-u', '--unnecessary', nargs='*', action='append', help='build including unnecessary configurations/platforms')
  parser.add_argument('--only', nargs='*', action='append')
  parser.add_argument('--worker', required=False, help='example: 3/4')
  parser.add_argument('--dry', action='store_true', help='don\'t actually build, print the order of actions')

  args = parser.parse_args(argv)

  worker_index, worker_count = None, None
  if args.worker != None:
    worker_index, worker_count = parse_worker(args.worker)

  onlies = None
  if args.only:
    onlies = sum(args.only, [])

  oper = 'build'

  if args.rebuild:
    oper = 'rebuild'
  elif args.clean:
    oper = 'clean'

  print(f'[operation: {oper} (whitelist: {onlies} (if None, nothing excluded))]')

  _sd = os.path.dirname(__file__)

  # testbin - all configs/platforms (including *Dll), tester - all without *Dll
  xxx = {
    'p2gen64': lambda: buildsol(fr'{_sd}\p2gen\p2gen64\p2gen64.sln', oper, ['Debug', 'Release'], ['x64']),
    'p2gen86': lambda: buildsol(fr'{_sd}\p2gen\p2gen86\p2gen86.sln', oper, ['Debug', 'Release'], ['x86']),
    'binhide': lambda: buildsol(fr'{_sd}\stub_tools\binhide\binhide.sln', oper, ['Debug', 'Release'], ['x86', 'x64']),
    'testbin': lambda: buildsol(fr'{_sd}\test\testbin\testbin.sln', oper, ['Debug', 'Release', 'DebugDll', 'ReleaseDll'], ['x86', 'x64']),
    'exechlp': lambda: buildsol(fr'{_sd}\tools\exechlp\exechlp.sln', oper, ['Release'], ['x64']),
    'lta1'   : lambda: buildsol(fr'{_sd}\test\ldrtest_apps\lta1\lta1.sln', oper, ['Debug', 'Release'], ['x86', 'x64'])
  }

  for nxxx in range(len(xxx)):
    detail_name = list(xxx.keys())[nxxx]
    detail_cbk = list(xxx.values())[nxxx]

    if worker_index != None:
      if nxxx % worker_count != (worker_index - 1):
        print(f'[-] #{nxxx}  skipping, not our part')
        continue

    if onlies:
      if not detail_name in onlines:
        print(f'[-] #{nxxx}  skipping, {detail_name=} not on {onlies=}')
        continue

    print(f'[>] #{nxxx}  building xxx {detail_name}')

    # Execute xx's callback from table
    if not args.dry:
      detail_cbk()

    if onlies:
      onlines.remove(detail_name)

    nxxx += 1


  if onlies and onlies != []:
    raise RuntimeError(f'unexpected onlies left - {onlies}')


if __name__ == '__main__':
  build_main(sys.argv[1:])






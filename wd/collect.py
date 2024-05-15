import argparse, sys

from c2.wd.collect_popular_imports import Z
from c2.wd.collect_touchprjs import Y
from c2.wd.collect_resdbs import X

from c2.infra.parse_worker import parse_worker


def collect_main(argv):
  parser = argparse.ArgumentParser()
  parser.add_argument('--light', action='store_true', help='Light collection for test/debug')
  parser.add_argument('--worker', required=False, help='example: 3/4')
  args = parser.parse_args(argv)

  worker_index, worker_count = None, None
  if args.worker:
    worker_index, worker_count = parse_worker(args.worker)
    assert(worker_count == 2) # by design now

  if worker_index == 1:
    # touchprjs depend on popular imports, so collect popular imports first
    collect_popular_imports(argv)
    collect_touchprjs_main(argv)
  elif worker_index == 2:
    collect_resdbs_main(argv)
  else:
    raise RuntimeError()



if __name__ == '__main__':
  collect_main(sys.argv[1:])

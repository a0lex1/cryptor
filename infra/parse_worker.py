from typing import Tuple


def parse_worker(workerstr:str) -> Tuple[int, int]:
  idx, cnt = workerstr.split('/')
  idx, cnt = int(idx), int(cnt)
  assert(idx > 0)
  assert(cnt > 0)
  assert(idx <= cnt)
  return idx, cnt


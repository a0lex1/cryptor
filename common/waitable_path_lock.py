import threading, os, sys

import win32event, win32file, win32api


class WaitablePathLock:
  def __init__(self, path:str):
    self._path = path
    self._hMutex = None
    self._mutex_name = self.__path2mutexname(self._path)

  def __enter__(self):
    self.__lock()
    return self

  def __exit__(self, exc_type, exc_val, exc_tb):
    self.__unlock()

  def __lock(self):
    assert(self._hMutex == None)
    self._hMutex = win32event.CreateMutex(None, False, self._mutex_name)
    dwWait = win32event.WaitForSingleObject(self._hMutex, win32event.INFINITE)
    assert(dwWait == win32event.WAIT_OBJECT_0)
    
  def __unlock(self):
    assert(self._hMutex != None)
    win32event.ReleaseMutex(self._hMutex)
    win32file.CloseHandle(self._hMutex)
    self._hMutex = None

  def __path2mutexname(self, path):
    realp = os.path.realpath(path)
    objname = realp.replace('\\', '_')
    objname = objname.replace('/', '_')
    objname = objname.replace(':', '_')
    #TODO: more chars to escape?
    mutname = f'WaitablePathLock_{objname}'
    return objname


def _test_simple():
  lock = WaitablePathLock('C:\\windowsssszz2231\\blablablaaaq\\qqqq.txt')
  for i in range(10):
    with lock:
      print('printing like with locked lock')

class _Tester:
  def __init__(self):
    self._path = 'd:\\win\\superdir28392'
    self._inside = False

  def _threadfunc(self, nthread):
    lock = WaitablePathLock(self._path)
    print(f'hi from thread {nthread} ({self._path=}, mutex name: {lock._mutex_name})')
    for i in range(150):
      # Try without __enter__ to ensure there is a race condition
      with lock:
        assert(not self._inside)
        self._inside = True

        for _ in range(10000): __ = _+_ # make some delay

        self._inside = False

    print(f'goodbye from thread {nthread}')

  def execute(self):
    num_threads = 20
    threads = []
    for nthread in range(num_threads):
      #print(f'creating thread {nthread}/{num_threads}')
      t = threading.Thread(target=self._threadfunc, args=[nthread])
      t.start()
      threads.append(t)
    for t in threads:
      t.join()

def _test_multithreaded():
  tester = _Tester()
  tester.execute()

def test_waitable_path_lock(argv):
  _test_simple()
  _test_multithreaded()

if __name__ == '__main__':
  test_waitable_path_lock(sys.argv[1:])


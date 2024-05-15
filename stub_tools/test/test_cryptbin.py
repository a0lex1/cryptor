import sys, random, string

from c2.stub_tools.cryptbin import Rearranger

def _test_on(data):
  r = Rearranger(None, random.Random())
  for i in range(len(r.decode_poses)):
    print(f'#define REARRANGE_DEC_POS{i} {r.decode_poses[i]}')
  o = r.rearrange(data)
  n = r.rearrange(o, decode=True)
  print('source =>', data)
  print('encoded=>', o)
  print('decoded=>', n)
  assert(data == n)
  print('test ok')

def test_cryptbin_rearranger(argv):
  for i in range(0, 64, 3):
    data = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits + ' ') for _ in range(i))
    if not data:
      data = ''
    datab = data.encode('ascii')
    print('data', data, 'datab', datab)
    _test_on(datab)
    _test_on(data)

if __name__ == '__main__':
  test_cryptbin_rearranger(sys.argv[1:])



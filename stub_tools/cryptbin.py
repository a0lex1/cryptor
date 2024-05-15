'''
╔═╗╦═╗╦ ╦╔═╗╔╦╗╔╗ ╦╔╗╔  ┌┬┐┬ ┬┌─┐  ┌┬┐┌─┐┌┬┐┌┬┐┬ ┬ "
║  ╠╦╝╚╦╝╠═╝ ║ ╠╩╗║║║║   │ ├─┤├┤    ││├─┤ ││ ││└┬┘   .py
╚═╝╩╚═ ╩ ╩   ╩ ╚═╝╩╝╚╝ " ┴ ┴ ┴└─┘  ─┴┘┴ ┴─┴┘─┴┘ ┴ 
'''

import os, sys, struct, argparse, pathlib, random, string

from c2.infra.cli_seed import CLISeed, DEFAULT_SEED_SIZE, textualize_seed
from c2.infra.seed_get_or_generate import seed_get_or_generate

class Rearranger:
  def __init__(self, poses, rng, num_poses=8):
    self.poses = poses
    self._rng = rng
    self._num_poses = num_poses
    if not self.poses:
      self.init_poses()
    self.decode_poses = [self.poses.index(i) for i in range(len(self.poses))]
  def init_poses(self):
    #poses = [5,0,2,1,6,4,3,7] #example
    self.poses = [i for i in range(self._num_poses)]
    self._rng.shuffle(self.poses)
  def rearrange(self, data, decode=False):
    gs = len(self.poses)
    gc = len(data) // gs
    gcm = len(data) % gs
    o = type(data)()
    poses = self.poses if not decode else self.decode_poses
    for g in range(gc):
      #group #g
      frm = g*gs #from index
      v = data[frm:frm+gs] # cur part
      for n in range(len(v)):
        z = poses[n]
        o += v[z:z+1]
    if gcm: #trailer
      o += data[gc*gs:]
    return o

def cryptbin_main(argv):
  parser = argparse.ArgumentParser('cryptbin')
  parser.add_argument('-i', '--input_bin', required=True)
  parser.add_argument('-k', '--key', type=lambda x: int(x, 0))
  parser.add_argument('-o', '--output_bin', default='')
  parser.add_argument('-x', '--xval', default=None, type=lambda x: int(x, 0))
  parser.add_argument('-e', '--output_header', default='')
  parser.add_argument('-w', '--width', type=int, default=4)
  parser.add_argument('-r', '--rearrange', action='store_true')
  parser.add_argument('--tail_count', type=int, default=0)
  parser.add_argument('--tail_key', default=None, type=lambda x: int(x, 0))

  cli_seed = CLISeed(None, DEFAULT_SEED_SIZE)
  cli_seed.add_to_argparser(parser)

  args = parser.parse_args(argv)

  cli_seed.set_parsed_args(args)

  seed = seed_get_or_generate(cli_seed, DEFAULT_SEED_SIZE)
  print('cryptbin.py using seed {textualize_seed(seed)}')
  rng = random.Random(seed)

  if args.key == None:
    assert(args.xval == None)

  width = args.width
  if width == 1:
    widthmax = 0xff
  elif width == 2:
    widthmax = 0xffff
  elif width == 4:
    widthmax = 0xffffffff
  else:
    print(f'Unsupported width - {width}')

  xval_is_rand = False
  xval = 0
  if args.xval != None:
    xval = args.xval
    if xval == 0:
      xval = rng.randint(0, widthmax)
      if xval % 2 == 0:
        xval += 1
      xval_is_rand = True
    else:
      if xval % 2 == 0:
        print('xval must NOT be % 2')
        exit(-1)
  else:
    print('xval is disabled')
  assert(xval <= widthmax)
  print(f'xval: {xval:08X} ({xval})')

  key_is_rand = False
  key = args.key
  if key != None:
    if key > widthmax:
      raise RuntimeError(f'ERROR: key is greater than widthmax (0x{widthmax:x})')
    if key == 0:
      print('Generating <<<random>>> key...')
      key = rng.randint(0, widthmax)
      key_is_rand = True
    assert(key <= widthmax)
    print(f'key: 0x{key:08X} ({key})')
  else:
    print('key (xor) is disabled')

  tail_key_is_rand = False
  tail_key = args.tail_key
  if tail_key != None:
    if tail_key > widthmax:
      raise RuntimeError(f'ERROR: {tail_key=} is greater than widthmax (0x{widthmax:x})')
    if tail_key == 0:
      print('Generating <<<random>>> tail key')
      tail_key = rng.randint(0, widthmax)
      tail_key_is_rand = True
    assert(tail_key <= widthmax)
    print(f'tail key: 0x{tail_key:08X} ({tail_key})')
  else:
    print('tail encryption disabled')


  input_realpath = os.path.realpath(args.input_bin)
  input_dirname = os.path.dirname(input_realpath)
  title = pathlib.Path(input_realpath).stem
  print(f'input_realpath: {input_realpath}')
  print(f'input_dirname: {input_dirname}')
  print(f'title: {title}')

  output_bin = args.output_bin
  if output_bin == '':
    output_bin = f'{input_dirname}/{title}.CRYPTED.bin'

  output_header = args.output_header
  if output_header == '':
    output_header = f'{input_dirname}/{title}.CRYPTED.h'

  print(f'output_bin: {output_bin}')
  print(f'output_header: {output_header}')

  input_data = open(args.input_bin, 'rb').read()
  inp_len = len(input_data)
  print(f'input data len: {inp_len}')

  if inp_len % width != 0:
    raise RuntimeError(f'ERROR: input data length must be aligned to DWORD (now {inp_len})')

  elemcount = inp_len // width
  print(f'elemcount: {elemcount}, one elem is {width} bytes')

  if key:
    print(f'crypting with key 0x{key:08X} (xval = 0x{xval:08X})')
  else:
    print(f'crypting WITHOUT xor key')

  print_times = 10
  print_every = elemcount // print_times

  output_data = b''
  new_key = key
  # body
  for nelem in range(elemcount - args.tail_count):
    assert(nelem < (elemcount - args.tail_count))
    if nelem != 0 and nelem % print_every == 0:
      perc = nelem/elemcount * 100
      print(f'done crypting {nelem}/{elemcount} ({round(perc, 2)}%) elems (elem size={width} bytes)')
    if width == 1:
      fmt = 'B'
    elif width == 2:
      fmt = 'H'
    elif width == 4:
      fmt = 'L'
    v = struct.unpack(fmt, input_data[nelem*width : (nelem+1)*width])[0]

    if new_key:
      z = v ^ new_key
    else:
      z = v

    assert(v <= widthmax)
    assert(z <= widthmax)
    output_data += struct.pack(fmt, z)

    if xval:
      new_key = (new_key * xval) & widthmax
      #print(f'new_key={new_key:X}')
      pass

  # rearrange if needed
  rearr = None
  if args.rearrange:
    rearr = Rearranger(None, rng, 8)
    print(f'rearranging poses: {rearr.poses}, decode poses: {rearr.decode_poses} ...')
    output_data = rearr.rearrange(output_data)
    print('done rearranging')

  tailfrom, tailto = elemcount - args.tail_count, elemcount
  print(f'encoding tail (elems from {tailfrom} to {tailto}...')
  for nelem in range(tailfrom, tailto):
    assert(nelem >= (elemcount - args.tail_count))
    v = struct.unpack(fmt, input_data[nelem*width : (nelem+1)*width])[0]
    z = v ^ tail_key
    assert(v <= widthmax)
    assert(z <= widthmax)
    output_data += struct.pack(fmt, z)

  if args.tail_count != 0:
    print(f'NOTE: the last {args.tail_count} elems ({args.tail_count*width} bytes) are XORed with tail key 0x{tail_key:x}')


  open(output_bin, 'wb').write(output_data)
  print(f'Output binary file saved - {output_bin}')
  
  c_key_types = {1: 'unsigned char', 2: 'unsigned short', 4: 'unsigned long'}
  
  hdr = \
f'''#pragma once

#define CRYPTBIN_WIDTH {width}
#define CRYPTBIN_COUNT {elemcount} // can be calculated size/width
#define CRYPTBIN_TAIL_COUNT {args.tail_count}
'''
  if tail_key != None:
    hdr += \
f'''#define CRYPTBIN_TAIL_XORKEY ((CRYPTBIN_KEY_TYPE)0x{tail_key:X})
'''

  if key:
    hdr += \
f'''#define CRYPTBIN_KEY_TYPE {c_key_types[width]}
#define CRYPTBIN_KEY ((CRYPTBIN_KEY_TYPE)0x{key:X})
'''
    if xval:
      hdr += f'#define CRYPTBIN_XVAL ((CRYPTBIN_KEY_TYPE)0x{xval:X})\n'
    else:
      hdr += '// no CRYPTBIN_XVAL\n'
  else:
    hdr += '// no CRYPTBIN_KEY_TYPE, CRYPTBIN_KEY, CRYPTBIN_XVAL\n'
  if args.rearrange:
    hdr += '#define CRYPTBIN_REARR_PATSIZE 8\n'
    for i in range(len(rearr.decode_poses)):
      hdr += f'#define CRYPTBIN_REARR{i} {rearr.decode_poses[i]}\n'
  else:
    hdr += '// no CRYPTBIN_REARR*\n'
  open(output_header, 'w').write(hdr)
  print(f'Output header file saved - {output_header}')

  print('Done crypting')


if __name__ == '__main__':
  cryptbin_main(sys.argv[1:])




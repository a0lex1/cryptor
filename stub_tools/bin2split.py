import os, sys, argparse, struct, random, numpy
from pathlib import Path

script_root = os.path.dirname(__file__)

def h_header(fheader, title: str, input_len: int, key: int):
  fheader.write(
f'''// {title}.h
#pragma once

//#ifdef __cplusplus
//extern "C" {{
//#endif

#define BINSPLIT_KEY ((unsigned)0x{key:08X})
#define BINSPLIT_TOTAL_DWCOUNT ((unsigned){input_len//4})
#define BINSPLIT_TOTAL_BYTECOUNT ((unsigned){input_len})

//extern unsigned g_dwBinsplitMarker;

// Prototype routines
void BinsplitSimpleCoalesce(unsigned char* buffer, unsigned dwXorKey);

typedef struct _BINSPLIT_CHUNK_DESCRIPTOR {{
  unsigned* dwords;
  unsigned num_dwords;
}} BINSPLIT_CHUNK_DESCRIPTOR;

extern const unsigned g_BinsplitChunkTableCount;
extern BINSPLIT_CHUNK_DESCRIPTOR g_BinsplitChunkTable[];

''')

def h_footer(fheader):
  fheader.write(
f'''
//#ifdef __cplusplus
//}}
//#endif

// Random number to update the file: {random.randint(0, 0xffffffff)}
''')

def c_header(cheader, title: str, key: int, input_len):
  assert(input_len % 4 == 0)
  cheader.write(
f'''#include "./{title}.h"
#include <memory.h>

//unsigned g_dwBinsplitMarker;

void BinsplitSimpleCoalesce(unsigned char* buffer, unsigned dwXorKey) {{
  unsigned cur_dest_dword = 0;
  for (unsigned i=0; i<g_BinsplitChunkTableCount; i++) {{
    unsigned* chunk_dwords = g_BinsplitChunkTable[i].dwords;
    unsigned chunk_dwcount = g_BinsplitChunkTable[i].num_dwords;
    
    unsigned char* copy_dest = &buffer[cur_dest_dword * 4];
    memcpy(copy_dest, chunk_dwords, chunk_dwcount * 4);
    
    cur_dest_dword += chunk_dwcount; 
  }}
}}

''')

# input_data must be aligned to DWORD
def gen_chunks(X, Y, input_data, fout_h, fout_c, tabs: bool, title: str):
  sp = '\t' if tabs else '  '
  
  # validate input
  inp_len = len(input_data)
  if inp_len % 4 != 0:
    print(f'len(input_data) must be DWORD-aligned, but it is {inp_len}, mod is {inp_len % 4}')
    assert(0)
    
  dwcount = inp_len // 4
  # generate chunksizes array
  left_dwords = dwcount
  chunksizes = []
  while left_dwords != 0:
    R = random.randint(X, Y)
    if R > left_dwords:
      R = left_dwords
    chunksizes.append(R)
    left_dwords -= R
  print(chunksizes)
  fout_h.write(f'// chunksizes = {str(chunksizes)}\n')
  assert(numpy.sum(chunksizes) == dwcount)
  
  cur_dw_index = 0
  nchunk = 0
  # print chunks using generated chunksizes array
  for chunksize in chunksizes:
    ### .h chunk
    fout_h.write(
f'''#define BINSPLIT_HAS_CHUNK_{nchunk}
#define BINSPLIT_CHUNK_{nchunk}_DWCOUNT {chunksize} // {chunksize:08X}
extern const unsigned chunk_{nchunk}_dword_count;
extern unsigned chunk_{nchunk}_dwords[];

''')
    ### .cpp chunk (comment)
    fout_c.write(f'// RANDOM SIZED CHUNK{sp}#{nchunk}{sp}({chunksize} DWORDS)\n')
    ### .cpp chunk
    fout_c.write(
f'''unsigned const int chunk_{nchunk}_dword_count = {chunksize};
unsigned chunk_{nchunk}_dwords[] = {{''')
    elems_on_line = 8
    cur_elem = 0
    for c in range(chunksize):
      if cur_elem % elems_on_line == 0:
        fout_c.write('\n')
        fout_c.write('    ')
      ifrom = (cur_dw_index + c) * 4
      ito = ifrom + 4
      x = struct.unpack('L', input_data[ifrom : ito])
      fout_c.write(f'0x{x[0]:08x}, ')
      cur_elem += 1
    fout_c.write('\n')
    fout_c.write('};\n\n')

    cur_dw_index += chunksize
    nchunk += 1
    pass

  fout_c.write('\n')
  fout_c.write(f'// Total: input data: {inp_len} bytes ({dwcount} DWORDS), {len(chunksizes)} chunks\n')
  fout_c.write('\n')
  # write chunk index table
  fout_c.write(
f'''const unsigned g_BinsplitChunkTableCount = {len(chunksizes)};
BINSPLIT_CHUNK_DESCRIPTOR g_BinsplitChunkTable[] =  {{
''')
  # some chunks might be dropped (they are calculated average)
  # so we must use the actual number of the chunks written, e.g. |num_chunks_done|
  for nchunk in range(len(chunksizes)):
    fout_c.write(\
f'''    {{ chunk_{nchunk}_dwords, chunk_{nchunk}_dword_count }},
''' \
    )
  fout_c.write(
f'''}};
''')

  return
  
def bin2split_generate(X: int, Y: int, input_data, fout_h, fout_c, tabs: bool, title: str, key: int):
  inp_len = len(input_data)
  h_header(fout_h, title, inp_len, key)
  c_header(fout_c, title, key, inp_len)
  r = gen_chunks(X, Y, input_data, fout_h, fout_c, tabs, title)
  h_footer(fout_h)
  return r

#########################################################################################


if __name__ == '__main__':
  if len(sys.argv) == 2 and sys.argv[1] == '--test':
    test_binary_data = b'\xda\xba\xca\xda\x77\x99\x11\x44\x67\x99\xa9\x8a'
    key = 0xdabadead
    print(f'--test: generating (key={key:08X}) ...')
    fout_h = open(f'{script_root}/test_binary_data.h', 'w')
    fout_c = open(f'{script_root}/test_binary_data.cpp', 'w')
    bin2split_generate(1, 11, test_binary_data, fout_h, fout_c, False, 'test_binary_data', key)
    print('--test: has been generated.')
    exit(0)
    
  parser = argparse.ArgumentParser(os.path.basename(__file__))
  parser.add_argument('-i', '--input_bin', required=True)
  parser.add_argument('-k', '--key', required=True, type=lambda x: int(x, 0))
  parser.add_argument('-o', '--output_dir', default='')
  parser.add_argument('-t', '--tabs', action='store_true')
  parser.add_argument('-x', '--rand_dwcount_from', required=True, type=int)
  parser.add_argument('-y', '--rand_dwcount_to', required=True, type=int)
  #parser.add_argument('-v', dest='verbose', action='store_true')
  args = parser.parse_args()

  if args.key > 0xffffffff:
    print('ERROR: key is greater than DWORD')
    exit(-1)

  X = args.rand_dwcount_from #1 
  Y = args.rand_dwcount_to #21

  # realpath was here, not tested then
  infile = args.input_bin
  title = Path(infile).stem
  outdir = args.output_dir
  
  if os.path.getsize(infile) > 1024 * 1024 * 256:
    print('File is bigger than 256 MB !')
    exit(-2)
  
  if outdir == '':
    ourdir = os.path.dirname(infile)

  print(f'key: 0x{args.key:08X} (dec: {args.key})')
  print(f'infile: {infile}')
  print(f'title: {title}')
  print(f'outdir: {outdir}')
  
  input_data = open(infile, 'rb').read()
  
  print(f'{len(input_data)} bytes has been read from {infile}')

  out_h_path = f'{outdir}/{title}.h'
  out_c_path = f'{outdir}/{title}.cpp'
  fout_h = open(out_h_path, 'w')
  fout_c = open(out_c_path, 'w')
  
  print('generating ...')
  bin2split_generate(X, Y, input_data, fout_h, fout_c, args.tabs, title, args.key)
  print('has been generated.')










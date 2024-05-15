
#BIN2MEDIA_OFFSET
# 40 if FindResourceA(RT_BITMAP)
# 54 if raw

import argparse, struct, math, random, os, sys

class BMPCodec:
  def __init__(self):
    self.orig_length = None
  def encode(self, fin, fout):
    data = fin.read()
    self.orig_length = len(data)
    ###
    output_len = 54 + self.orig_length
    square = self.orig_length // 4
    orig_square = square
    remainder = self.orig_length % 4
    if remainder != 0:
      square += 1
    side_size = math.ceil(math.sqrt(square))
    padding_size = side_size ** 2 * 4 - self.orig_length
    print('encode: input len', self.orig_length, '(use for -d -l <self.orig_length>)')
    print('encode: square', square)
    print('encode: orig_sqaure', orig_square)
    print('encode: remainder', remainder)
    print('encode: padding size', padding_size)
    ###
    fout.write(b'BM')  # Type
    fout.write(struct.pack('I', output_len))  # Size
    fout.write(struct.pack('H', 0))  # Reserved1
    fout.write(struct.pack('H', 0))  # Reserved2
    fout.write(struct.pack('I', 54))  # Offset
    ###
    fout.write(struct.pack('I', 40))  # DIBHeaderSize
    fout.write(struct.pack('I', side_size))  # Width
    fout.write(struct.pack('I', side_size))  # Height
    fout.write(struct.pack('H', 1))  # ColourPlanes
    fout.write(struct.pack('H', 32))  # BitsPerPixel
    fout.write(struct.pack('I', 0))  # CompressionMethod
    fout.write(struct.pack('I', 0))  # RawImageSize ####### TODO: mspaint places real value
    fout.write(struct.pack('I', 0))  # HorizontalResolution
    fout.write(struct.pack('I', 0))  # VerticalResolution
    fout.write(struct.pack('I', 0))  # NumberOfColours
    fout.write(struct.pack('I', 0))  # ImportantColours
    ###
    fout.write(data)
    r = random.randint(0, self.orig_length - padding_size - 1)  # use data from random pos as padding
    fout.write(data[r:r + padding_size])

  def decode(self, fin, fout):
    fout.write(fin.read()[54:54 + self.orig_length])

class PNGCodec:
  def __init__(self):
    self.orig_length = None
  def encode(self, fin, fout):
    raise NotImplementedError()
  def decode(self, fin, fout):
    raise NotImplementedError()

if __name__ == '__main__':
  parser = argparse.ArgumentParser(os.path.basename(__file__))
  parser.add_argument('-c', '--codec', required=True, choices=['bmp', 'png'])
  parser.add_argument('-e', '--encode', action='store_true')
  parser.add_argument('-d', '--decode', action='store_true')
  parser.add_argument('-i', '--input_file', required=True)
  parser.add_argument('-o', '--output_file', required=True)
  parser.add_argument('-l', '--orig_length', required=False)
  parser.add_argument('-a', '--append_info_header', required=False)

  args = parser.parse_args()
  if (not args.encode and not args.decode) or (args.encode and args.decode):
    print('bad mode')
    exit(-11)
    
  if args.append_info_header and args.decode:
    print('-x is for encode only')
    exit(-1)

  if args.encode and args.orig_length != None:
    print('no need to specify length in encode mode')
    exit(-1)

  if args.decode and args.orig_length == None:
    print('need to specify length in decode mode')
    exit(-1)

  orig_length = int(args.orig_length) if args.orig_length != None else None

  print(f'mode: {"ENCODE" if args.encode else "DECODE"}')
  print('input_file', args.input_file)
  print('output_file', args.output_file)
  if args.decode:
    print('orig_length (for decode)', orig_length)

  codec = {'bmp': BMPCodec, 'png': PNGCodec}[args.codec]()

  if args.encode:
  
    print('encoding')
    codec.encode(open(args.input_file, 'rb'), open(args.output_file, 'wb'))
    print('done encoding')
    
    if args.append_info_header:
      ofs = 40 if type(codec) == BMPCodec else None
      open(args.append_info_header, 'a').write(
f'''#define BIN2MEDIA_OFFSET {ofs}
#define BIN2MEDIA_ORIG_LEN {codec.orig_length}

''')

  else:
    print('decoding')
    codec.decode(open(args.input_file, 'rb'), open(args.output_file, 'wb'), orig_length)
    print('done decoding')


import argparse, fnmatch, random, os, sys

from c2.infra.cli_seed import CLISeed
from c2.infra.seed import DEFAULT_SEED_SIZE
from c2.infra.seed_get_or_generate import seed_get_or_generate

#import bin2media
#bin2media.BMPCodec(), bin2media.PNGCodec() # TODO ? or separate ?

parser = argparse.ArgumentParser(os.path.basename(__file__))
parser.add_argument('-a', '--append_info_header', required=True)
g = parser.add_mutually_exclusive_group(required=True)
g.add_argument('-d', '--input_dir', help='rsrc dir') #
g.add_argument('-r', '--rc_file')
parser.add_argument('-i', '--input_file', required=True)
parser.add_argument('-f', '--force', action='store_true')
parser.add_argument('-t', '--resource_type', required=False)

cliseed = CLISeed(os.getcwd(), DEFAULT_SEED_SIZE)
cliseed.add_to_argparser(parser)

args = parser.parse_args()
cliseed.set_parsed_args(args)

seed = seed_get_or_generate(cliseed, DEFAULT_SEED_SIZE)
rng = random.Random(seed)
print(f'<addresource.py rng probe: {rng.randint(0, sys.maxsize)}>')

j = os.path.join
if args.input_dir:
  files = [f for f in os.listdir(args.input_dir) if fnmatch.fnmatch(f, '*.rc')]
  if len(files) != 1:
    raise RuntimeError(f'multiple .rc files found - {files}')
  rc_file = j(args.input_dir, files[0])
  print(f'[+] found rc file in input dir: {rc_file}')
else:
  rc_file = args.rc_file

print(f'[ ] reading rc file {rc_file}')
rc_data = open(rc_file, 'r').read()

magic_comment = '//###added by addresource.py'
if magic_comment in rc_data:
  if args.force:
    print('[ ] resource already added; -f : adding another')
  else:
    print('[-] ERROR: resource already added; use -f to force add')
    exit(-1)

##########################################
# COLLISION POSSIBLE !!!!!!!!!!!!!!!!!!!!!
##########################################
RSRC_ID = rng.randint(100, 1000) # collision possible! and too great number! if max=10000, FindResourceA returns not found!
print(f'[ ] resource ID will be: {RSRC_ID}')

#BAD: #RSRC_FILE = args.input_file.replace('\\', '\\\\') #This would give us absolute path if the input argument is absolute
RSRC_FILE = os.path.relpath(args.input_file, os.path.dirname(rc_file))
RSRC_FILE = RSRC_FILE.replace('\\', '\\\\') #TODO: Do we need this? Does this work? If yes, remove comment
print(f'[ ] relpath to user file from RC file: {RSRC_FILE}')

if args.resource_type:
  RSRC_TYPE = args.resource_type
  print(f'[ ] -t: resource TYPE will be: {RSRC_TYPE}')
else:
  RSRC_TYPE = rng.choice(['BITMAP', 'ICON', 'CURSOR', 'MANIFEST'])
  print(f'[ ] PICKED *RANDOM* resource TYPE: {RSRC_TYPE}')

rc_data += f'\n{RSRC_ID} {RSRC_TYPE} "{RSRC_FILE}" {magic_comment}'
print(f'[ ] writing {rc_file}')
open(rc_file, 'w').write(rc_data)

print(f'[ ] writing info header file {args.append_info_header}')
defs = f'''
#define ADDRESOURCE_RES_ID {RSRC_ID}
#define ADDRESOURCE_RES_TYPE RT_{RSRC_TYPE} // either this
#define ADDRESOURCE_RES_TYPE_STR "{RSRC_TYPE}" // or this
\n'''
#if args.offset:
#  defs += f'#define ADDRESOURCE_OFFSET {args.offset}\n'

open(args.append_info_header, 'a').write(defs)

print('[+] bin2resource.py done')




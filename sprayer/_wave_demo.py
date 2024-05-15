import argparse, random, os
import matplotlib
matplotlib.use('TkAgg') # sexy
import matplotlib.pyplot as plt

from c2.sprayer._wave import adjust_sinwaves, RandomSinWaveCoeff


if __name__ == '__main__':
  parser = argparse.ArgumentParser(os.path.basename(__file__))
  parser.add_argument('-n', '--num_iters', type=int, default=10)
  parser.add_argument('-s', '--show', action='store_true')

  subpa = parser.add_subparsers(required=True, dest='command')

  aswp = subpa.add_parser('adjust_sinwaves')
  #num_sins, seed
  #W, H, positive, amplify_to_height, round_to, extramul:
  aswp.add_argument('--sins', type=int, default=5)
  aswp.add_argument('--seed', type=int, default=None)
  aswp.add_argument('--width', type=int, required=True)
  aswp.add_argument('--height', type=int, required=True)

  aswp.add_argument('-p', '--positive', action='store_true')
  aswp.add_argument('-a', '--amplify_to_height', action='store_true')
  g = aswp.add_mutually_exclusive_group(required=False)
  g.add_argument('-i', '--round_to_integer', action='store_true')
  g.add_argument('-z', '--precision', type=int, default=3)
  #aswp.add_argument('-e', '--extra_mul', type=int)

  args = parser.parse_args()

  assert(args.command == 'adjust_sinwaves')

  rng = random.Random(args.seed)
  for _ in range(args.num_iters):
    wavez = adjust_sinwaves(RandomSinWaveCoeff(args.sins, rng), args.width, args.height,
                            positive=args.positive, amplify_to_height=args.amplify_to_height,
                            round_to=None if args.round_to_integer else args.precision,)
                            #extramul=1 if not args.extra_mul else args.extra_mul)
    print(wavez)
    if args.show:
      plt.plot(wavez)
      plt.show()

  print(f'{args.num_iters} test iters done')


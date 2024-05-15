def add_strlist_to_argparser(strlist, parser, **kwargs):
  for s in strlist:
    parser.add_argument(f'--{s}', **kwargs)

def strlist_from_parsed_args(orig_strlist, args):
  ret = []
  for s in orig_strlist:
    assert(s in args.__dict__)
    a = args.__dict__[s]
    if a == True:
      ret += [s]
    else:
      assert(a == False)
  return ret


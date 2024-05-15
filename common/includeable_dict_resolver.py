import copy, os, sys, json, jsonschema, argparse
from pprint import pprint

# !) overrides |subject|'s contents
# !) you can access your document - self.subject
# !) copies fields that are neighbors to '$include' field too, BUT without expanding $include(s) in it (just copy it), eg.:
#   {'x': 1, 'y': {'$include': '22.json', 'some1': {'sub': {'$include': '33.json' }}}, } -> 22.json included, some1 is copied AS IS, its $include IS NOT PROCESSED!
class IncludeableDictResolver:
  #fn_afterload -> def fn_afterload(jpath_l, node), called after successful load of node from file; gets jpath (to key which content has been loaded) and loaded node itself
  def __init__(self, subject:dict, root_path, fn_afterload=None):
    self.subject = subject
    self.root_path = root_path
    self._fn_afterload = fn_afterload

  # returns |subject| for sugaring things like x=IncludeableDictResolver(...).resolve()
  def resolve(self):
    while True:
      n = self.resolve_once()
      if n == 0:
        break
    return self.subject

  def resolve_once(self, node=None, cur_path=None) -> int:
    _RECURSE = self.resolve_once
    # { 'a': 1, 'b': 2, 'c': {'$include':'x'}, }
    if node == None:
      node = self.subject
    if cur_path == None:
      cur_path = []
    num = 0
    for key in node.keys():
      value = node[key]
      if type(value) == dict:
        #if len(v) == 1 and '$include' in v: # we can have more than one
        if '$include' in value:
          inclpath = value['$include']
          assert(type(inclpath) == str)

          #SecurityLogic
          def interpret_path(p:str):
            if len(p) >= 2 and p[0] == '/':
              if not '..' in p: # detects ... too
                return p[1:]
            return None

          path2 = interpret_path(inclpath)
          if not path2:
            raise RuntimeError(f'Validation failed for include path {inclpath}')

          path3 = os.path.join(self.root_path, path2)

          loaded_node = json.load(open(path3, 'r'))
          # copy original fields to loaded_node; v-> current node
          for _k in value.keys():
            if _k == '$include': # copy all except this of course
              continue
            _v = value[_k] # copy field

            #assert(type(_v) != dict) # now only non-recursive mode ###now don't do this
            assert(not _k in loaded_node) # it shouldn't have it now

            loaded_node[_k] = copy.deepcopy(_v)

          # original fields have been copied
          if self._fn_afterload:
            # call user's callback
            self._fn_afterload(cur_path + [key], loaded_node)

          # replace the node to what we've formed by loading+processing
          node[key] = loaded_node
          num += 1

        else:
          # type(v) is dict, but $include not in v; treat it's a normal subdict, recurse into it
          num += _RECURSE(value, cur_path + [key])
      else:
        # type(v) is not dict.  no interest in fields
        pass
    return num



_sd = os.path.dirname(__file__)

def _onetest(doc, root_path, expect_total, expectation):
  def fn_afterload(jpath_l, node):  # just for test
    return
  r = IncludeableDictResolver(doc, root_path, fn_afterload)
  total = 0
  while True:
    n = r.resolve_once()
    print(f'resolve_once() -> {n}')
    if n == 0:
      break
    total += n
  print('total', total)
  assert(total == expect_total)
  assert(r.subject == expectation)
  pass

def _test():
  # one includes one
  _onetest(json.load(open(f'{_sd}/../test/td/includer1.json', 'r')),
           f'{_sd}/../',
           1, # one stage
           {'a': 1,
            'b': {'c': {'me': 'included', 'meold': 5, 'meinfo': {'myshit': {'shit_numbers': [1, 2, 3]}, 'sex': 'euro'}},
                  'd': {'e': 5}}}
           )
  # one includes one that includes another one
  _onetest(json.load(open(f'{_sd}/../test/td/includer2.json', 'r')),
           f'{_sd}/../',
           2, # must be two stages
           {'E': 7, 'Q': {'M': {'me': 'included', 'meold': 6, 'meinfo': {'hi': 'iam-includee2', '2 included': True}}, 'P': {'Z': 5}}}
           )


def test_common_includeable_dict_resolver(argv):
  _test()

def _main(argv):
  parser = argparse.ArgumentParser(os.path.basename(__file__))
  parser.add_argument('-i', '--input_file', required=True)
  parser.add_argument('-r', '--root_path', required=True)
  parser.add_argument('-w', '--pprint_width', default=None, type=int)
  args = parser.parse_args()
  #root_path = args.root_path if args.root_path else CRYPTOR_ROOT
  root_path = args.root_path
  ppextr = {'width': args.pprint_width} if args.pprint_width != None else {}
  j = json.load(open(args.input_file, 'r'))
  resolver = IncludeableDictResolver(j, root_path)
  resolver.resolve()
  pprint(resolver.subject, **ppextr)
  

if __name__ == '__main__':
  #test_common_includeable_dict_resolver(sys.argv[1:])

  _test()

  _main(sys.argv[1:])




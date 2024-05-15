import sys
from enum import Enum, auto
from pprint import pprint

from c2.common.test_schemas import test_schema_3

class SchemaVarInitType(Enum):
  NullValues = auto()
  DefaultValues = auto()

# if styp==NullValues, default_key_name must be None
# in case you're using schema2instance for creating JEN document from unischema, set default_key_name to "$jdefault"
# extra_prop_key indicates extra props copied as inst's node props
# extra_prop_key not managed for non-dict fields
def schema2instance(styp:SchemaVarInitType, root:dict, outdict:dict,
                    default_key_name='default',
                    extra_prop_key=None,
                    fn_convertvalue=None,
                    #value_if_no_default='<no_default_in_schema>' #need to fallback to default if
                    fn_nodefault_fallback=lambda node: '<no_default_in_schema>' #lambda node: node['default']
                    ):
  _RECURSE = schema2instance
  assert(styp != SchemaVarInitType.NullValues or default_key_name == None)
  assert(root['type'] == 'object')

  if fn_convertvalue == None:
    # by default, no convertion
    fn_convertvalue = lambda typ, val: val

  props = root['properties']

  for propname in props.keys():
    prop = props[propname]
    typ = prop['type']

    if typ == 'object':
      outdict[propname] = {}

      if extra_prop_key:
        if extra_prop_key in prop:
          # merging dicts with operator | < wtf,where?
          outdict[propname] = { **prop[extra_prop_key] }


      _RECURSE(styp, prop, outdict[propname], default_key_name, extra_prop_key, fn_convertvalue, fn_nodefault_fallback)

    elif typ == 'string' or typ == 'number' or typ == 'boolean'\
            or typ == 'array':
      # arrays not supported by convert_value()

      # In this case, extra_prop_key not managed (not copied). only in `object` fields.

      if styp == SchemaVarInitType.NullValues:
        outdict[propname] = None
      elif styp == SchemaVarInitType.DefaultValues:
        if default_key_name in prop:
          # by default, fn_convertvalue just retuns unmodified value
          outdict[propname] = fn_convertvalue(typ, prop[default_key_name])
        else:
          #outdict[propname] = value_if_no_default
          if fn_nodefault_fallback == None:
            raise RuntimeError(f'{propname=}: default key not present AND no fallback fn is set')
          outdict[propname] = fn_nodefault_fallback(prop)
      else:
        raise RuntimeError()

    else:
      raise RuntimeError(f'Dont know how to handle node of type {prop["type"]}')
  return


def _test_useless():
  print('test_schema_3 =')
  pprint(test_schema_3)
  newschema = {}
  schema2instance(SchemaVarInitType.NullValues, test_schema_3, newschema, None, None, None)
  print('schema2instance ( test_schema_3, NullValues ) =')
  pprint(newschema)
  print()

  newschema = {}
  schema2instance(SchemaVarInitType.DefaultValues, test_schema_3, newschema, None, None, None)
  print('schema2instance ( test_schema_3, DefaultValues ) =')
  pprint(newschema)
  print()

def _test_schema2instance_with_jif():
  schema = {
    'type': 'object',
    'properties': {
      'a': {
        'type': 'object',
        'properties': {
          'x': {'type': 'number'}
        }
      },
      'b': {
        '$j': { # dont forget this fucking shit
          '$jif': ['a.x', 5]
        },
        'type': 'object',
        'properties': {
          'y': {'type': 'string'}
        }
      }
    }
  }

  new_schema = {}
  schema2instance(SchemaVarInitType.DefaultValues, schema, new_schema, 'default', '$j')
  assert(new_schema == {'a': {'x': '<no_default_in_schema>'}, 'b': {'$jif': ['a.x', 5], 'y': '<no_default_in_schema>'}})
  pass

def test_common_schema2instance(argv):
  _test_useless()
  _test_schema2instance_with_jif()

if __name__ == '__main__':
  test_common_schema2instance(sys.argv[1:])



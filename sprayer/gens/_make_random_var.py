from c2.sprayer.ccode.var import *


def make_random_var(rng, types=integer_var_types,
                    nvknown=(0, 0), nvuninit=(0, 0), nvunk=(0, 0)):
  typ = rng.choice(types)
  nknown = rng.randint(nvknown[0], nvknown[1])
  nuninit = rng.randint(nvuninit[0], nvuninit[1])
  nunk = rng.randint(nvunk[0], nvunk[1])
  values = [rng.randint(0, type_classes[typ].max()) for i in range(nknown) if type_classes[typ]] +\
           [ValueUninitialized() for i in range(nuninit)] +\
           [ValueUnknown() for i in range(nunk)]
  rng.shuffle(values)
  return Var(typ, values)


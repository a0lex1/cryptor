import random
import matplotlib.pyplot as plt

from c2.common.dice_percent import dice_percent


# I've got too low math IQ to come up with something greater than this
class StickyRandomFunction:
  def __init__(self, H:int, probab_change_percent:int, max_change:int, rng):
    assert(0 <= max_change <= H)
    self.__H = H
    self.__probab_change_percent = probab_change_percent
    self.__max_change = max_change
    self.__rng = rng
    self.__prev_y = None

  def f(self):
    if dice_percent(self.__rng, self.__probab_change_percent):
      if self.__prev_y != None:
        if self.__max_change == 0:
          change = 0
        else:
          change = self.__rng.randint(1, self.__max_change)
        if self.__rng.choice([1, 2]) == 1:
          self.__prev_y -= change
        else:
          self.__prev_y += change
        return self.__fix_y(self.__prev_y)
    self.__prev_y = self.__rng.randint(0, self.__H)
    return self.__fix_y(self.__prev_y)

  def __fix_y(self, y:int):
    if y < 0:
      y = -y
    if y > self.__H:
      y %= self.__H
    return y


### DEMO CODE ###

def _demo():
  rng = random.Random()
  obj = StickyRandomFunction(65535, 95, 1000, rng)

  for x in range(1000):
    plt.plot(x, obj.f(), '+')
  plt.show()

  exit()


def _old_unused_code():
  rngs = [
    #lambda: random.triangular(0, 50),
    #lambda: random.betavariate(50, 20),
    #lambda: random.expovariate(10),
    #lambda: random.gammavariate(10, 20),
    #lambda: random.gauss(0.0, 1.0),
    lambda: random.lognormvariate(1, 2),
    lambda: random.vonmisesvariate(1, 2),
  ]
  for rng in rngs:
    for x in range(1000):
        prng = rng
        plt.plot(x, prng(), 'x')
    #plt.legend(numpoints=1)
    #plt.xlim(0, 0.1)
    #plt.ylim(0, 0.1)
    plt.show()


if __name__ == '__main__':
  _demo()


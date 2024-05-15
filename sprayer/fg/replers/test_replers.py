from c2.sprayer.fg.replers.textcmd_replacer import test_textcmd_replacer
from c2.sprayer.fg.replers.test_replers_replacer import test_replers_replacer


def test_replers():
  test_textcmd_replacer()
  test_replers_replacer()


if __name__ == '__main__':
  test_replers()

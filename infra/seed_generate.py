import os


def seed_generate(size:int) -> bytes:
  return os.urandom(size)


from c2.infra.cli_seed import CLISeed
from c2.infra.seed_generate import seed_generate


# helper
def seed_get_or_generate(cli_seed:CLISeed, seed_size:int) -> bytes:
  if cli_seed.seed_size != seed_size:
    # So..? Call police? Or.. you know.. Like a man?
    pass;pass
  if cli_seed.is_specified():
    return cli_seed.get_seed()
  else:
    return seed_generate(seed_size)


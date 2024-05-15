from c2.test.seed_test import SeedTest


def full_seed_test_main():
  SeedTest(['--crpo_spg_fg', 'new', '--crpo_spg_rg', 'old']).execute()

if __name__ == '__main__':
  full_seed_test_main()
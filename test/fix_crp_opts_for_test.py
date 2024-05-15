def fix_crp_opts_for_test(crp_opts, dont_disable_trasher=False):
    # fix some things in config
  # decays are very slow, turn off for this test
  crp_opts['num_cpp_decays_sx'] = '0..0'
  crp_opts['num_c_decays_sx'] = '0..0'
  if not dont_disable_trasher:
    crp_opts['trasher_enabled'] = False
    if 'trasher' in crp_opts:
      del crp_opts['trasher']
  # we don't want for evil to Sleep() even in Release[Sprayed] configurations, cut it
  crp_opts['spg']['sgsleep1_sx'] = '10..20'
  crp_opts['spg']['sgsleep2_sx'] = '10..20'

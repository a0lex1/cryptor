import sys

from c2.common.dict_keychar_expander import test_common_dict_keychar_expander
from c2.common.iteration_generator import test_common_iteration_generator
from c2.common.get_all_keys import test_common_get_all_keys
from c2.common.string_repl_positions import test_common_string_repl_positions
from c2.common.merge_dicts import test_common_merge_dicts
from c2.common.schema2instance import test_common_schema2instance
from c2.common.get_schema_props import test_common_get_schema_props
from c2.common.jpath import test_common_jpath
from c2.common.waitable_path_lock import test_waitable_path_lock
from c2.common.includeable_dict_resolver import test_common_includeable_dict_resolver
from c2.common.pe_common import test_common_pe_common
from c2.common.update_hardlinks import test_update_hardlinks
from c2.common.mirror_directory import test_mirror_directory
from c2.common.mix_lists import test_mix_lists
from c2.common.line_reader import test_line_reader
from c2.common.sort_by_values import test_sort_by_values, sample_sort_by_values_randomize_equal

from c2.base.stage.handler import test_handler_table
from c2.base.stage.rules import test_rules
from c2.base.stage.test_text_handlers import test_text_handlers
#from c2.base.stage.stage_runner_executor import test_stage_runner_executor
#from c2.base.stage.stage_runner import test_stage_runner #after we delete below
from c2.base.dynconfig import test_dynconfig
from c2.base.stage_runner import test_stage_runner2

from c2.test.test_opt_validation import test_opt_validation

from c2.infra.test_jen import test_jen
from c2.infra.dyn_jen import test_dyn_jen
from c2.infra.cli_config import test_cli
from c2.infra.test_unischema import test_unischema
from c2.infra.jif_resolver import test_jif_resolver
from c2.infra.test_cli_config_aggregator import test_cli_config_aggregator #SepTest
from c2.infra.test_cli_config_aggregator_with_jen import test_cli_config_aggregator_with_jen
from c2.infra.arg_processor import test_arg_processor
from c2.infra.option_string import test_validate_option_string
from c2.infra.argparse_prediction import test_argparse_prediction
from c2.infra.seed_db import test_seed_db
from c2.infra.cli_seed import test_cli_seed
from c2.infra.cli_conf_to_argv import test_cli_conf_to_argv
from c2.infra.testloop_runner import test_testloop_runner

from c2.test.test_all_unischemas import test_all_unischemas

from c2.evp.getprot import test_getprot
from c2.evp.prot_checks import test_is_enough_prot_for_scn
from c2.evp.test_prot_logic import TestProtLogicCLI
from c2.evp.test_evpgen_simple import test_evpgen_simple

from c2.chains.parse_descrip import test_chains_parse_descrip
from c2.chains.calldb import test_chains_calldb

from c2.trasher.test_popularimports2touchprj import test_popularimports2touchprj
from c2.trasher.test_touchgen import test_touchgen
from c2.trasher.test_trash_add import TestTrashAddMainCLI
from c2.trasher.common.is_ms_dll import test_is_ms_dll

from c2.pg.billet import billet_main

from c2.sprayer._struct_reorderer import test_struct_reorderer
from c2.sprayer.ccode.evaluator import test_ccode_evaluator
from c2.sprayer.ccode.machine_int import test_ccode_machine_int
from c2.sprayer.ctools.parse_c_define import test_parse_c_define
from c2.sprayer.ctools.split_c_var_decl import test_split_c_var_decl
from c2.sprayer.ctools.test_preprocessor_cmd_system import test_preprocessor_cmd_system
from c2.sprayer.misc.spraytab_utils import test_spraytab_utils
from c2.sprayer.test.test_vargen import test_vargen
from c2.sprayer.test.spraytest_project import test_spraytest_project
from c2.sprayer.test.roletest_bundle import test_BasicRoleTestBundle
from c2.sprayer.gens.nid_dfs import test_nid_dfs_order_checker
from c2.sprayer.gens.multishoulder_tree_gen import test_multishoulder_tree_generator
from c2.sprayer.gens.distribute_randomly import test_distribute_randomly
from c2.sprayer.vp.test_var_picking import test_var_picking
from c2.sprayer.fg.replers.test_replers import test_replers

from c2.test.test_graph_factory import test_graph_factory

# It was working when I commented it out, but I moved it to papers/old_code because we don't need it right now.
# The current prototype impl of subser is introducing its own StmtGenBase things and I don't want it to mess with other code.
#from c2.sprayer.__stmt._subser import test_subser

# we are test-for-test for following
from c2.test.paytest_case_generator import test_paytest_case_generator
#from c2.test.case_runner import test_caserunner #excessive


def test_all(argv):
  # Note: some test_* may not use |argv|, they stub it like declaring it fn(argv=None) (the last I remember is test_arg_processor)
  test_common_dict_keychar_expander(argv)
  test_common_iteration_generator(argv)
  test_common_get_all_keys(argv)
  test_common_string_repl_positions(argv)
  test_common_merge_dicts(argv)
  test_common_schema2instance(argv)
  test_common_get_schema_props(argv)
  test_common_jpath(argv)
  test_waitable_path_lock(argv)
  test_common_includeable_dict_resolver(argv)
  test_common_pe_common(argv)
  test_update_hardlinks(argv)
  test_mirror_directory(argv)
  test_mix_lists(argv)
  test_line_reader(argv)
  test_sort_by_values() # sort_by_values.py
  sample_sort_by_values_randomize_equal() # sort_by_values.py

  test_handler_table(argv)
  test_rules()
  test_text_handlers(argv)
  #test_stage_runner() #NEW!
  #test_stage_runner_executor() #NEW!
  test_dynconfig(argv)
  test_stage_runner2(argv) #DEPRECATED!

  test_opt_validation(argv)

  test_jen(argv)
  test_dyn_jen(argv)
  test_cli(argv)
  test_unischema(argv)
  test_jif_resolver(argv)
  test_cli_config_aggregator(argv)
  test_cli_config_aggregator_with_jen(argv)
  test_arg_processor(argv)
  test_validate_option_string(argv)
  test_argparse_prediction(argv)
  test_seed_db(argv)
  test_cli_seed(argv)
  test_cli_conf_to_argv(argv)
  test_testloop_runner(argv)

  test_all_unischemas(argv)

  test_getprot(argv)
  test_is_enough_prot_for_scn(argv)
  TestProtLogicCLI(argv).execute()
  test_evpgen_simple(argv)

  test_chains_parse_descrip(argv)
  test_chains_calldb(argv)

  test_popularimports2touchprj(argv)
  test_touchgen(argv)
  TestTrashAddMainCLI([*argv, '--special']).execute() # use this tool to test your particular workdir's touch repository
  test_is_ms_dll(argv)

  billet_main(argv)

  test_ccode_evaluator(argv)
  test_ccode_machine_int(argv)
  test_parse_c_define(argv)
  test_split_c_var_decl(argv)
  test_preprocessor_cmd_system(argv)
  test_spraytest_project(argv)
  test_BasicRoleTestBundle(argv)
  test_nid_dfs_order_checker()
  test_multishoulder_tree_generator()
  test_distribute_randomly()
  test_spraytab_utils(argv)
  test_struct_reorderer(argv)
  test_var_picking()
  test_replers()

  test_graph_factory(argv)

  #test_subser(argv)

  # test the test tools theirselves
  test_paytest_case_generator(argv)
  #test_caserunner(argv) # excessive


if __name__ == '__main__':
  test_all(sys.argv[1:])



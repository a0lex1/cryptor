## Cryptor - a PE file protector framework

Key functionalities:

  - Generates CMake projects
  - PE loader code is **sprayed** around random **call graph**
  - Both x86, x64 of both EXE and DLL are supported
  - VirtualAlloc/VirtualProtect are called from random threads
  - contains resource extractor to mimic the resources of other binaries
  - trash code is added everywhere
  - antiemulation is present
  - **proggen**, a special tool is used to generate random threads at random entrypoints
  - **chaingen** is used to generate chains of API calls

Written in Python and C/C++, has full covering unit tests.

## Dependencies
See requirements.txt in the root directory.
You will also need any Visual Studio and CMake.

## Preparation
Since this python project depends on environment vars, we need some preparation before we can get things done.
If you cloned this repo into C:\github\cryptor, create C:\temp\cryptor, C:\wrk\cryptor and 
place C:\paths.json with the following contents somewhere:
```
{
  "cur": {
    "prjdir": "C:\\github\\cryptor",
    "tmpdir": "C:\\temp\\cryptor",
    "wrkdir": "C:\\wrk\\cryptor",
    "pythonpath": "C:\\github"
  }
}
```

Use scripts/make_startup_bats.py to create startup bat files in any directory:

```
mkdir C:\start
C:\github\cryptor\scripts\make_startup_bats.py C:\paths.json -o C:\start
```

Now C:\start contains startup bat files for opening PyCharm, starting unit tests and opening cryptor shell.

Start C:\start\shell_cur.bat

Now run:
```
py -m cryptor.cryptor_cli
```

```
usage: cryptor_cli.py [-h] [--bla BLA] -i INPUT_FILE -o OUT_DIR [--solution_name SOLUTION_NAME] [--log_file LOG_FILE] [--log_stdout] [--pay PAY]
                      [--pay_cpu PAY_CPU] [--pay_bin_type PAY_BIN_TYPE] [--pay_dll_evil_from_dllmain {true,false}] [--pay_stomp {true,false}]
                      [--pay_postfn_rva PAY_POSTFN_RVA] [--pay_postfn_decl_args PAY_POSTFN_DECL_ARGS]
                      [--pay_postfn_fromdll_call_args PAY_POSTFN_FROMDLL_CALL_ARGS] [--pay_postfn_fromexe_call_args PAY_POSTFN_FROMEXE_CALL_ARGS]
                      [--pay_export_decl_args PAY_EXPORT_DECL_ARGS] [--pay_export_def_call_args PAY_EXPORT_DEF_CALL_ARGS]
                      [--pay_export_name PAY_EXPORT_NAME] [--crp CRP] [--crp_no_check_bin {true,false}] [--crp_rearrange {true,false}]
                      [--crp_soi_mul_percent_sx CRP_SOI_MUL_PERCENT_SX] [--crp_no_spread_section_load {true,false}]
                      [--crp_fixup_tls_pointer {true,false}] [--crp_evp_protlogic_initial_prots CRP_EVP_PROTLOGIC_INITIAL_PROTS]
                      [--crp_evp_protlogic_exact {true,false}] [--crp_evp_protlogic_probab_unnecess_reprot CRP_EVP_PROTLOGIC_PROBAB_UNNECESS_REPROT]
                      [--crp_evp_protlogic_shuffle {true,false}] [--crp_ae_method CRP_AE_METHOD] [--crp_store_method CRP_STORE_METHOD]
                      [--crp_alloc_method CRP_ALLOC_METHOD] [--crp_spg_rg CRP_SPG_RG] [--crp_spg_fg CRP_SPG_FG]
                      [--crp_spg_rgdumb_dumb_funcs CRP_SPG_RGDUMB_DUMB_FUNCS] [--crp_spg_rgspray_graph CRP_SPG_RGSPRAY_GRAPH]
                      [--crp_spg_rgspray_route_limit CRP_SPG_RGSPRAY_ROUTE_LIMIT] [--crp_spg_rgspray_route_bits CRP_SPG_RGSPRAY_ROUTE_BITS]
                      [--crp_spg_rgspray_root_order CRP_SPG_RGSPRAY_ROOT_ORDER] [--crp_spg_rgspray_proc_order CRP_SPG_RGSPRAY_PROC_ORDER]
                      [--crp_spg_rgold_do_optimize {true,false}] [--crp_spg_rgold_graph CRP_SPG_RGOLD_GRAPH]
                      [--crp_spg_rgold_force_lines_scatter {true,false}] [--crp_spg_fgmin_reserved CRP_SPG_FGMIN_RESERVED]
                      [--crp_spg_fgnew_avg_nodes_for_branch_sx CRP_SPG_FGNEW_AVG_NODES_FOR_BRANCH_SX]
                      [--crp_spg_fgnew_condgen_eg_l_maxlev CRP_SPG_FGNEW_CONDGEN_EG_L_MAXLEV]
                      [--crp_spg_fgnew_condgen_eg_r_maxlev CRP_SPG_FGNEW_CONDGEN_EG_R_MAXLEV] [--crp_spg_fgnew_condgen_logging {true,false}]
                      [--crp_spg_fgnew_condgen_prefer_arridx {true,false}] [--crp_spg_fgnew_trash_stmts {true,false}]
                      [--crp_spg_fgnew_dbgbreak_notreached {true,false}] [--crp_spg_fgnew_dbgbreak_elses {true,false}] [--crp_spg_holders {true,false}]
                      [--crp_spg_sgsleep1_sx CRP_SPG_SGSLEEP1_SX] [--crp_spg_sgsleep2_sx CRP_SPG_SGSLEEP2_SX] [--crp_spg_rgpxlx_inline {true,false}]
                      [--crp_program CRP_PROGRAM] [--crp_pg_dbgchecks {true,false}] [--crp_pg_release_sleeps {true,false}]
                      [--crp_pg_dbgbreaks_before CRP_PG_DBGBREAKS_BEFORE] [--crp_pg_dbgbreaks_after CRP_PG_DBGBREAKS_AFTER]
                      [--crp_pg_user_headers CRP_PG_USER_HEADERS] [--crp_pg_entryproc_fromdecl {true,false}]
                      [--crp_pg_entryproc_name CRP_PG_ENTRYPROC_NAME] [--crp_pg_entryproc_isroot {true,false}] [--crp_pg_generator CRP_PG_GENERATOR]
                      [--crp_pg_alphagen_reserved CRP_PG_ALPHAGEN_RESERVED] [--crp_pg_fullgen_num_threads_sx CRP_PG_FULLGEN_NUM_THREADS_SX]
                      [--crp_pg_fullgen_percent_thread_sharedfn_sx CRP_PG_FULLGEN_PERCENT_THREAD_SHAREDFN_SX]
                      [--crp_pg_fullgen_percent_residents_sx CRP_PG_FULLGEN_PERCENT_RESIDENTS_SX]
                      [--crp_pg_fullgen_timeofs_waker_poll_start_sx CRP_PG_FULLGEN_TIMEOFS_WAKER_POLL_START_SX]
                      [--crp_pg_fullgen_timeofs_last_thread_sx CRP_PG_FULLGEN_TIMEOFS_LAST_THREAD_SX]
                      [--crp_pg_fullgen_timeofs_last_userproc_sx CRP_PG_FULLGEN_TIMEOFS_LAST_USERPROC_SX] [--crp_pg_processor CRP_PG_PROCESSOR]
                      [--crp_trasher_enabled {true,false}] [--crp_trasher_num_mods_sx CRP_TRASHER_NUM_MODS_SX]
                      [--crp_trasher_trash_percent_sx CRP_TRASHER_TRASH_PERCENT_SX] [--crp_trasher_use_all {true,false}]
                      [--crp_trasher_touchprjs CRP_TRASHER_TOUCHPRJS] [--crp_num_cpp_decays_sx CRP_NUM_CPP_DECAYS_SX]
                      [--crp_num_c_decays_sx CRP_NUM_C_DECAYS_SX] [--crp_allow_tls {true,false}] [--sys SYS] [--sys_portable_binhide {true,false}]
                      [--rnd RND] [--rnd_seeds_bh RND_SEEDS_BH] [--rnd_seeds_cb RND_SEEDS_CB] [--rnd_seeds_mdf RND_SEEDS_MDF]
                      [--rnd_seeds_sg RND_SEEDS_SG] [--rnd_seeds_gds RND_SEEDS_GDS] [--rnd_seeds_ar RND_SEEDS_AR] [--rnd_seeds_rsg RND_SEEDS_RSG]
                      [--rnd_seeds_trs RND_SEEDS_TRS] [--rnd_seeds_grb RND_SEEDS_GRB] [--rnd_seeds_cpd RND_SEEDS_CPD] [--rnd_seeds_evp RND_SEEDS_EVP]
                      [--bld BLD] [--bld_target_configs BLD_TARGET_CONFIGS] [--bld_target_projects BLD_TARGET_PROJECTS]
cryptor_cli.py: error: the following arguments are required: -i/--input_file, -o/--out_dir
```

## Crypting binary file with default options


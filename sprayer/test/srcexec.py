from c2.sprayer.test.helper_main_cpp import HelperMainCPP
from c2.sprayer.test.spraytest_project import SpraytestProject


# expected_ret=None -> expect |helper_cpp.retcode|
def srcexec(prj_dir, progname, helper_cpp:HelperMainCPP, expected_ret:int=None):
  st = SpraytestProject(prj_dir, progname)
  st.put(allow_exist=True)
  open(st.get_main_cpp_path(), 'w').write(helper_cpp.produce())
  st.fast_compile(sprayed_build=False)
  if expected_ret == None:
    expected_ret = helper_cpp.retcode
  return st.run_fast_compiled_program(expect_code=expected_ret)





import argparse, json, os, sys

'''
  Usage: make_startup_bats.py paths.json -o start/
  Example paths.json (e.g. config):
  ...
  "old": {
    "prjdir": "C:\\r\\c2",
    "tmpdir": "C:\\v\\temp\\r2",
    "wrkdir": "C:\\v\\r2",
    "pythonpath": "C:\\r",
    #"cppbuild": "C:\\v\\r2\\cppbuild"    # in this example, cppbuild is inside wrkdir # UPD: not using here anymore
    #                                     # later, wrkdir will be removed as concept and all of its dirs are moved to higher level (here) control
  },
'''

NUM_WORKERS = 8

class MakeStartupBatsCLI:
  def __init__(self):
    self.__out_dir = None
    self.__config = None
    
  def _put_common_bats(self):
    open(f'{self.__out_dir}/pycharm.bat', 'w').write(
      r'@REM don\'t forget to cd to some good dir cuz #PycharmYellowBug'+'\n'
      r'start "" "C:\Program Files\JetBrains\PyCharm Community Edition 2023.2.1\bin\pycharm64.exe" %*'+'\n'
      )
    open(f'{self.__out_dir}/setenv_shared.bat', 'w').write(
      r'call "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" && (echo OK) || (echo FAIL && goto exit)'+'\n'
      r':exit'+'\n'
      )
    open(f'{self.__out_dir}/__exec_and_pause.bat', 'w').write(
      r'%*'+'\n'
      r'pause'+'\n'
      )


  def _putbat(self, prj):
    prjnode = self.__config[prj]
    prj_dir = prjnode["prjdir"]
    # execute pycharm from tmpdir
    open(f'{self.__out_dir}/pycharm_{prj}.bat', 'w').write(
      fr'call %~dp0\setenv_{prj}.bat && (echo OK) || (echo FAIL && goto exit)'+'\n'
      fr'cd {prjnode["tmpdir"]}'+'\n'
      fr'call %~dp0\pycharm.bat {prj_dir} && (echo OK) || (echo FAIL && goto exit)'+'\n'
      fr':exit'+'\n'
      )
    open(f'{self.__out_dir}/shell_{prj}.bat', 'w').write(
      fr'call %~dp0\setenv_{prj}.bat && (echo OK) || (echo FAIL && goto exit)'+'\n'
      fr'cmd && (echo OK) || (echo FAIL && goto exit)'+'\n'
      fr':exit'+'\n'
      )
    open(f'{self.__out_dir}/build_{prj}.bat', 'w').write(
      fr'call %~dp0\setenv_{prj}.bat && (echo OK) || (echo FAIL && goto exit)'+'\n'
      fr'{prj_dir}/scripts/conemu_split.py /arg --worker /workers {NUM_WORKERS} /cmd %~dp0\__exec_and_pause.bat py -m c2.build && (echo OK) || (echo FAIL && goto exit)'+'\n'
      fr':exit'+'\n'
      )
    open(f'{self.__out_dir}/test_{prj}.bat', 'w').write(
      fr'call %~dp0\setenv_{prj}.bat && (echo OK) || (echo FAIL && goto exit)'+'\n'
      fr'{prj_dir}/scripts/conemu_split.py /arg --tst_worker /workers {NUM_WORKERS} /cmd %~dp0\__exec_and_pause.bat py -m c2.all && (echo OK) || (echo FAIL && goto exit)'+'\n'
      fr':exit'+'\n'
      )
    open(f'{self.__out_dir}/setenv_{prj}.bat', 'w').write(
      fr'call %~dp0\setenv_shared.bat && (echo OK) || (echo FAIL && goto exit)'+'\n'
      fr'set CRP_WORK_DIR={prjnode["wrkdir"]}'+'\n'
      #fr'set CPPBUILD_DIR={prjnode["cppbuild"]}'+'\n'
      fr'set PYTHONPATH={prjnode["pythonpath"]}'+'\n'
      fr':exit'+'\n'
      )

  # This tool puts files to CUR DIR
  def main(self, argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('config', help='json file with paths of different installations (tmpdir, wrkdir, etc.)')
    parser.add_argument('-o', '--out_dir', required=True, help='where to place bats')
    args = parser.parse_args(argv)
    self.__out_dir = args.out_dir
    self.__config = json.load(open(args.config, 'r'))
    print('out_dir:', self.__out_dir)
    print('config:', self.__config)
    self._put_common_bats()
    for prj in self.__config.keys():
      self._putbat(prj)


if __name__ == '__main__':
  MakeStartupBatsCLI().main(sys.argv[1:])


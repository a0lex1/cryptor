# Standalone script, no need to configure any env, run it from anywhere.

import argparse, os, sys

_sd = os.path.dirname(os.path.abspath(__file__))

parser = argparse.ArgumentParser(os.path.basename(__file__))
parser.add_argument('-w', '--work_dir', required=True)
args = parser.parse_args()

if not os.path.isdir(args.work_dir):
  os.makedirs(args.work_dir)

os.mkdir(args.work_dir+'/hs')
os.mkdir(args.work_dir+'/tmp')
os.mkdir(args.work_dir+'/loccrypts')
os.mkdir(args.work_dir+'/resdbs')
os.mkdir(args.work_dir+'/popular_imports')
os.mkdir(args.work_dir+'/touchprj')
os.mkdir(args.work_dir+'/web')


'''
# will probably be needed later
open(f'{args.work_dir}/shell.bat', 'w').write(
''call %~dp0\setenv.bat
cmd
'')

open(f'{args.work_dir}/setenv.bat', 'w').write(
fr''call "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat"

set PYTHONPATH=%PYTHONPATH%;{_sd}

set CRP_WORK_DIR=%~dp0
'')

'''


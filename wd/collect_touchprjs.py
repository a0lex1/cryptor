import os

from c2.tools.collect_popular_imports import collect_popular_imports_main
from c2.wd.touchprj_from_popular_imports import X
#from c2.wd.collect_exports...

# program this need multiple touchprjs

#TODO:
#  tools/collect_popular_imports.py ... --prj popular
#  touchprj_from_popular_imports.py --csv x.csv --prj popular
#  tools/collect_exports.py .. --prj expcollect
#  touchprj_from_collected_exports.py --prj expcollect <<<<<<<<< implement this
#
#
#  




def collect_touchprjs_main(argv):
  if 'bla:lightcollection!' in argv: #--bla
    collect_popular_imports_main(aaaaaaaa)
  else:
    pass


if __name__ == '__main__':
  collect_touchprjs_main(sys.argv[1:])


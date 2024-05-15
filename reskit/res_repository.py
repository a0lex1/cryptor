import os
from typing import List
from dataclasses import dataclass

from c2.base.repo_default_filename_cond import repo_default_filename_cond
from c2.common.clear_dir import clear_dir


@dataclass
class ResRepository:
  __repo_dir:str

  def list_dbs(self) -> List[str]:
    return [x for x in os.listdir(self.__repo_dir) if repo_default_filename_cond(self.__dbdir(x))]

  def list_res_dirs_in_db(self, dbname) -> List[str]:
    return [x for x in os.listdir(self.__dbdir(dbname)) if repo_default_filename_cond(f'{self.__dbdir(dbname)}/{x}')]

  def get_res_dir_path(self, dbname, resname, for_error=False) -> str:
    if not for_error:
      return f'{self.__dbdir(dbname)}/{resname}'
    else:
      return f'{self.__dbdir(dbname)}/!{resname}'

  def get_db_log_path(self, dbname) -> str:
    return self.__dbdir(dbname)

  #def get_res_log_path(self): #can be

  def get_testcompile_files_path(self, dbname, resname) -> str:
    return self.get_res_dir_path(dbname, resname)


  def db_exists(self, dbname):
    return os.path.isdir(self.__dbdir(dbname))

  def create_db(self, dbname):
    os.makedirs(self._dbdir(dbname))

  def clear_db(self, dbname):
    clear_dir(self.__dbdir(dbname))

  def __dbdir(self, dbname):
    return f'{self.__repo_dir}/{dbname}'






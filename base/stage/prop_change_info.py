from dataclasses import dataclass


@dataclass
class PropChangeInfo:
  propname: str = None
  catname: str = None
  stagename: str = None


# like VS macros: $(Example)
def substitute_propchangeinfo_macros(subject: str, info: PropChangeInfo) -> str:
  subject = subject.replace('$(PropName)', info.propname)
  subject = subject.replace('$(CatName)', info.catname)
  subject = subject.replace('$(StageName)', info.stagename)
  return subject

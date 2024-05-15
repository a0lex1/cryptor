import argparse, os, sys
from typing import List

from c2.infra.cli_config_aggregator import CLIConfigAggregator
from c2.infra.arg_processor import ArgProcessor


# A pattern for creating CLI tools
# adds --bla automatically
class ToolCLI:
  def __init__(self, argv):
    self._argv = argv
    self._args = None
    self._agr = None
    self._parser = None
    self.__arg_processors = []     # [ ]
    self._progname = None # should be set from _do_initialize()

  def execute(self):
    self._initialize() # call derived so it can register their stuff
    self.__print_notes_if_exist()
    self.__manage_args()
    self._do_work()

  def __manage_args(self):
    if self._progname == None:
      raise RuntimeError('_progname should be set be derived class in _setup() or earlier')
    self._agr = CLIConfigAggregator()
    self._parser = argparse.ArgumentParser(self._progname)
    self._parser.add_argument('--bla', required=False)
    self._setup_args() # call derived

    self._agr.add_to_argparser(self._parser)
    for arg_processor in self.__arg_processors:
      arg_processor.add_to_argparser(self._parser)

    self._args = self._parser.parse_args(self._argv)
    self._agr.set_parsed_args(self._args)
    for arg_processor in self.__arg_processors:
      arg_processor.set_parsed_args(self._args)

    self._on_args_parsed() # call derived class, reserved for future

  def _setup_args(self):
    raise NotImplementedError('implement in derived: You can fill: _agr, _parser, _arg_processors')

  def _initialize(self):
    raise NotImplementedError('implement in derived, do whatever you need before _setup')

  def _do_work(self):
    raise NotImplementedError('implement in derived, do main job')

  def _on_args_parsed(self):
    # implement in derived if you want; a chance to setup custom arg processor(s)
    pass

  def _notes(self) -> List[str]:
    # implement in derived if you want; return text description as array of notes (just strings)
    pass

  # for derived
  def _add_arg_processor(self, ap:ArgProcessor):
    assert(issubclass(type(ap), ArgProcessor)) # refactoring check
    self.__arg_processors.append(ap)

  def __print_notes_if_exist(self):
    notes = self._notes()
    if notes:
      print('-- Notes for this tool:')
      for note in notes:
        print('  !) '+note)
      print()




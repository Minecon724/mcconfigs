from datetime import datetime
from os import fsync

class Logger:
  levels = {}
  _files = {}

  def __init__(self, levels:dict, directory:str='logs'):
    self.levels = levels
    for i in levels.keys():
      self._files[i] = open(directory + '/' + levels[i] + '.log', 'a')
    if not 'global' in levels:
      self._files[i] = open(directory + '/global.log', 'a')

  def log(self, level, message:str, glbal=True):
    if level in self._files.keys():
      _file = self._files[level]
      msg = f'[{datetime.now().strftime("%H:%M:%S")} {level}] {message}\n'
      _file.write(msg)
      _file.flush()
      fsync(_file.fileno())
      if glbal:
        _global = self._files['global']
        _global.write(msg)
        _global.flush()
        fsync(_global.fileno())

  def close(self):
    for i in this._files.values():
      i.close()

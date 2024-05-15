import os

# print your name with {name:05d} to match
def get_next_filename_seqnum(path_prefix : str):
  cur_id = 0
  while True:
    try:
      cur_dir = f'{path_prefix}{cur_id:05d}/'
      #print('checking dir', cur_dir)
      if not os.path.isdir(cur_dir):
        return cur_id
    except OSError as e:
      if e.errno != errno.EEXIST:
        raise
    cur_id += 1
  pass

import hashlib  # only for sha256()
import os  # only for urandom()

BYTES = int(256 / 8)  # 256: 24 words, 128: 12 words

def rand(bytes=BYTES):
  return bytearray(os.urandom(bytes))

def xor(key1, key2):
  return bytearray([k1 ^ k2 for k1, k2 in zip(key1, key2)])

def raw_to_indices(key):
  checksum = hashlib.sha256(key).digest()[:1]
  binary = ''.join([bin(b)[2:].rjust(8, '0') for b in key+checksum])
  return [int(binary[i*11:i*11+11], 2) for i in range(int(len(binary) / 11))]

def raw_to_int(key):
  binary = ''.join([bin(b)[2:].rjust(8, '0') for b in key])
  return int(binary, 2)

def indices_to_raw(indices, bytes=BYTES):
  binary = ''.join([bin(i)[2:].rjust(11, '0') for i in indices])
  assert len(binary) == int((bytes*8+8)/11)*11, 'Unexpected key length'
  raw_key = bytearray([int(binary[i*8:i*8+8], 2) for i in range(bytes)])
  assert raw_to_indices(raw_key) == indices, 'Invalid Checksum'
  return raw_key

def int_to_raw(int_key, bytes=BYTES):
  binary = bin(int_key)[2:].rjust(int(bytes*8), '0')
  assert len(binary) == int(bytes*8), 'Unexpected key length'
  raw_key = bytearray([int(binary[i*8:i*8+8], 2) for i in range(bytes)])
  assert raw_to_int(raw_key) == int_key, 'Invalid Checksum'
  return raw_key

def words(indices):
  with open('bip39_wordlist.txt') as wordfile:
    wordlist = wordfile.read().splitlines()
    return [wordlist[i] for i in indices]

def indices(words):
  with open('bip39_wordlist.txt') as wordfile:
    wrds = [w[:4] for w in wordfile.read().splitlines()]
    return [wrds.index(w[:4]) for w in words]

def print_keys(names, keys, style):
  for name, key in zip(names, keys):
    if style == 'int':
      mnemonic = str(raw_to_int(key))
    elif style == 'indices':
      mnemonic = ' '.join([str(i) for i in raw_to_indices(key)])
    else:  # words
      mnemonic = ' '.join(words(raw_to_indices(key)))
    print('%s: %s' % (name, mnemonic))

def merge_keys(style, key=[0]*32):
  try:
    for n in range(3):
      part = input('%s> ' % ['a or x', 'b or y', 'c or z'][n]).strip()
      if style == 'int':
        part = int_to_raw(int(part))
      elif style == 'indices':
        part = indices_to_raw([int(i) for i in part.split()])
      else:  # words
        part = indices_to_raw(indices(part.split()))
      key = xor(key, part)
    print_keys(['real'], [key], style=style)
  except Exception as e:
    print(e)

def dice(bytes=BYTES, mix_rand=True):
  binary = ''
  while len(binary) < bytes*8:
    try:
      r, s = int(input()), int(input())
    except Exception as e:
      if isinstance(e, KeyboardInterrupt):
        break
      continue
    if r < 1 or r > 6 or s < 1 or s > 6:
      continue
    roll = r*6 + s - 7
    if roll < 32:
      binary += bin(roll)[2:].rjust(5, '0')
    else:
      if mix_rand:
        binary += ''.join([bin(b)[2:].rjust(8, '0') for b in rand(roll-31)])
      else:
        binary += bin(roll-32)[2:].rjust(2, '0')
    print(binary.count('0'), binary.count('1'), binary)
  return bytearray([int(binary[i*8:i*8+8], 2) for i in range(bytes)])

def manual(bytes=BYTES):  # Danger Will Robinson
  with open('bip39_wordlist.txt') as wordfile:
    wordlist = [w[:4] for w in wordfile.read().splitlines()]
    idxs = [wordlist.index(w[:4]) for w in input().split()]
    try:
      return indices_to_raw(idxs)
    except:
      for i, index in enumerate(idxs):
        for offset in range(len(wordlist)):
          fixed = idxs.copy()
          fixed[i] = (index+offset) % len(wordlist)
          try:
            print_keys(['works'], [indices_to_raw(fixed)], numeric=numeric)
          except:
            pass

def main(style='words'):
    real, a, b, x, y = rand(), rand(), rand(), rand(), rand()
    c, z = xor(xor(real, a), b), xor(xor(real, x), y)
    assert real == xor(a, xor(b, c)) and real == xor(x, xor(y, z)), 'Bad Keys'
    print_keys(['a', 'b', 'c', 'x', 'y', 'z', 'real'], [a, b, c, x, y, z, real],
               style=style)
    print('''Recovery proof: p1: ax, p2: by, p3: cx, p4: bz, p5: az
        p123: abc, p124: xyz, p125: xyz, p234: yxz, p235: bca, p345: cba''')
    while True:
      merge_keys(style=style)

if __name__ == '__main__':
  try: input = raw_input
  except NameError: pass
  main(style='words')

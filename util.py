import logging
import math
import os
from binascii import hexlify

def human_size(nbytes):
    suffixes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    if nbytes == 0: return '0 B'
    i = 0
    while nbytes >= 1024 and i < len(suffixes)-1:
        nbytes /= 1024.
        i += 1
    f = ('%s' % float('%.3g' % nbytes)).rstrip('0').rstrip('.')
    return '%s %s' % (f, suffixes[i])

def recursive_all_files(directory, ext_filter=None):
    all_files = []
    dir_content = []
    ret = []
    
    if os.path.isfile(directory):
        dir_content = [directory]
    else:
        if '*' in directory:
            dir_content = glob.glob(directory)
        else:
            try:
                dir_content = os.listdir(directory)
            except Exception as e:
                #print 'Exception listing contents of %s. Skipping' % (directory)
                return []

    for f in dir_content:
        if os.path.isdir(directory):
            rel_path = os.path.join(directory,f)
        else:
            rel_path = f
        if os.path.isfile(rel_path):
            all_files.append(rel_path)
        elif f == '.' or f == '..':
            pass
        else:
            all_files += recursive_all_files(rel_path,ext_filter)

    for f in all_files:
        if (ext_filter is None or os.path.splitext(f)[1] == '.%s' % ext_filter):
            ret.append(f)
    return ret


def configure_logger(log_level):
    log_levels = {0: logging.ERROR, 1: logging.WARNING, 2: logging.INFO, 3: logging.DEBUG}
    log_level = min(max(log_level, 0), 3) #clamp to 0-3 inclusive
    logging.basicConfig(level=log_levels[log_level],
            format='%(asctime)s - %(name)s - %(levelname)-8s %(message)s')

def entropy(s):
    rtn = 0
    for x in range(256):
        p_x = s.count(x)/len(s)
        if p_x > 0:
            rtn += - p_x*math.log(p_x,2)
    #print(f'entropy("{s}"): {rtn}')
    return rtn

# handle backward incompatible change introduced in v.4.3.0: https://github.com/VirusTotal/yara-python/releases/tag/v4.3.0
def iterate_matches(matches):
    #pre v4.3.0
    for matchobj in matches:
        if type(matchobj) is tuple:
            # (<offset>, <string identifier>, <string data>)
            yield matchobj[0], matchobj[1], matchobj[2]
        # >= v4.3.0
        else:
            name = matchobj.identifier
            for string in matchobj.instances:
                yield string.offset, name, string.matched_data

def percent_printable(string):
    string = string.replace(b'\x00', b'')
    if len(string) == 0:
        return 0
    printable_count = 0
    for c in string:
        if (c <= 0x7f and c >= 0x20) or c == b'\n' or c == b'\r' or c == b'\t':
            printable_count += 1
    return float(printable_count)/float(len(string))
    
def yara_escape(string):
    rtn = b''
    escape = list(range(0,9)) + list(range(0x0B, 0x20)) + list(range(0x7F, 0x100))
    for c in bytearray(string):
        if c == 0x09:
            rtn += b'\\t'
        elif c == 0x0A:
            rtn += b'\\n'
        elif c in escape:
            rtn += (f'\\x{c:02X}').encode()
        elif c == 0x22:
            rtn += b'\\"'
        elif c == 0x5c:
            rtn += b'\\\\'
        else:
            rtn += chr(c).encode()
    #print(f'{string} -> {rtn.decode()}')
    return rtn.decode('utf-8')


def format_hex(string):
    h = hexlify(string).upper().decode()
    return ' '.join(h[i:i+2] for i in range(0, len(h), 2))

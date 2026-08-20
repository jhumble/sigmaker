#!/usr/bin/env python3
import hashlib
import os
import tempfile
import time
import datetime
import yara
import logging
import re
import uuid
from binascii import hexlify, unhexlify
from argparse import ArgumentParser
from concurrent.futures import ProcessPoolExecutor
from suffix_tree import Tree
from util import *



def physical_cores():
    """Best-effort count of physical (not logical) cores available to us.

    Scanning is memory-bandwidth bound, so hyperthreads buy far less than their
    core count suggests and the useful ceiling is physical cores.  Bounded by
    the CPU affinity mask so a taskset/cgroup-restricted process does not
    oversubscribe what it was actually given.
    """
    try:
        available = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        available = os.cpu_count() or 2

    cores = set()
    try:
        with open('/proc/cpuinfo') as fp:
            phys = core = None
            for line in fp:
                if line.startswith('physical id'):
                    phys = line.split(':', 1)[1].strip()
                elif line.startswith('core id'):
                    core = line.split(':', 1)[1].strip()
                elif not line.strip():
                    if phys is not None and core is not None:
                        cores.add((phys, core))
                    phys = core = None
            if phys is not None and core is not None:
                cores.add((phys, core))
    except OSError:
        pass

    if cores:
        return max(1, min(len(cores), available))
    # No /proc/cpuinfo: half the logical CPUs is the same number on any SMT box.
    return max(1, available // 2)


# Half the physical cores, capped at 8.  Deliberately conservative on both
# counts: this runs on a shared analysis server where a dozen analysts may be
# working at once, and several concurrent sigmaker runs must not bog the box
# down.  Leaving half the cores free also keeps a workstation usable for other
# work while a scan is going.  Raise it with -j when you have the machine to
# yourself.
DEFAULT_WORKERS = min(8, max(1, physical_cores() // 2))

_worker_rule = None


def _init_scan_worker(rule_source):
    """Compile the rule once per worker process instead of once per file."""
    global _worker_rule
    _worker_rule = yara.compile(source=rule_source)


def _scan_paths(paths):
    """Return (matching pattern identifiers, [(path, error), ...]) for `paths`.

    Runs in a worker process, so it returns data rather than logging. The
    identifier set is bounded by the number of patterns in the rule, so there is
    nothing large to ship back to the parent.
    """
    matched = set()
    errors = []
    for path in paths:
        try:
            for match in _worker_rule.match(path):
                for offset, name, data in iterate_matches(match.strings):
                    matched.add(name)
        except Exception as e:
            errors.append((path, str(e)))
    return matched, errors


def parse_args():
    usage = "config_extractor.py [OPTION]... [FILES]..."
    arg_parser = ArgumentParser(description=usage)
    arg_parser.add_argument('-v', '--verbose', action='count', default=0,
        help='Increase verbosity. Can specify multiple times for more verbose output')
    arg_parser.add_argument("-p", "--percent", dest="percent", type=int, action="store", default=51,
      help="percent of files each string must show up in to be included. Default: 51")
    arg_parser.add_argument("-R", "--recursive", action="store_true", default=False,
      help="use recursion")
    arg_parser.add_argument("-m", "--min", dest="minimum", type=int, action="store", default=5,
      help="Minimum string length to be included in output")
    arg_parser.add_argument("-M", "--max", dest="maximum", type=int, action="store", default=128,
      help="Maximum string length to be included in output")
    arg_parser.add_argument("-n", "--name", action="store", default='',
      help="rule name to use when building the yara rule")
    arg_parser.add_argument("-r", "--reference", action="store", default='',
      help="reference to add to yara metadata")
    arg_parser.add_argument("-t", "--tags", action="append", default=[],
      help="tags to add to yara rule. Can specify multiple times for multiple tags")
    arg_parser.add_argument("-o", "--output", action="store", default=None,
      help="Path to save the final generated rule to")
    arg_parser.add_argument("-f", "--filter", dest="filter", action="store_true", default=False,
      help="Filter strings by %% null bytes and entropy")
    arg_parser.add_argument("-B", "--bytes", dest="bytes", type=int, action="store", default=0,
      help="Byte to read from each file. Default of 0: read full file")
    arg_parser.add_argument("-s", "--strings", type=int, action="store", default=200,
      help="Max strings in output yara rule. If more than this number of common strings are found, progressively tighter filters (entropy and %% null bytes) are applied if using -f or the strings are sorted from most to least prevalent and chopped to this # without -f")
    arg_parser.add_argument("-b", "--benign", dest="benign", action="append", default=[],
      help="directory full of benign files to use for excluding noisy strings. Can specify multiple times to use additional directories")
    arg_parser.add_argument("-j", "--parallel", dest="parallel", type=int, action="store", default=DEFAULT_WORKERS,
      help=f"Worker processes to use for the benign-file scan, which dominates runtime. 1 disables multiprocessing. Default on this machine: {DEFAULT_WORKERS}")
    arg_parser.add_argument("-P", "--prefix", dest="prefix", action="store", default="auto",
      help="Prefix for pattern names (e.g., 'auto' produces $auto_000, $auto_001). Default: 'auto'")
    arg_parser.add_argument('files', nargs='+')
    return arg_parser.parse_args()


        

class Sigmaker:
    # http://www.cs.ucf.edu/courses/cap5937/fall2004/Applications%20of%20suffix%20trees.pdf

    def __init__(self, percent=51, minimum=5, maximum=128, bytes_to_read=0, max_strings=9999, string_filter=False, parallel=DEFAULT_WORKERS):
        self.logger = logging.getLogger('Sigmaker')
        self.tree = None
        if parallel < 1:
            raise ValueError(f'Invalid parallel option: {parallel}. Must be >= 1')
        self.parallel = parallel
        self.strings = []
        self.null_filter = .8
        self.entropy_filter = 2.5
        self.string_filter = string_filter
        if max_strings < 1 or max_strings > 9999:
            self.logger.critical(f'Invalid max_strings (--strings) value: {max_strings}. Must be > 0 and < 10000')
            exit()
        else:
            self.max_strings = max_strings
    
        if isinstance(percent, int):
            self.percent = percent/100
        else:
            self.percent = percent
        if self.percent <= 0 or self.percent > 1:
            raise ValueError(f'Invalid percent option: {self.percent}')
        self.minimum = minimum
        if minimum < 1:
            raise ValueError(f'Invalid minimum length option: {self.minimum}')
        self.maximum = maximum
        if maximum < 2 or maximum < minimum:
            raise ValueError(f'Invalid maximum length option: {self.maximum}')
        if bytes_to_read <= 0:
            self.bytes_to_read = -1
        else:
            self.bytes_to_read = bytes_to_read
        
        

    def filter_strings(self, strings, null_filter=.8, entropy_filter=2.5):
        self.logger.debug("Reducing " + str(len(strings)) + " strings...\n")
        del_list = []
        strings = [s for s in strings if (s['string'].count(0)/len(s['string'])) <= null_filter and entropy(s['string']) >= entropy_filter]
        self.logger.debug(f'After filtering by entropy and null_percent: {len(strings)}')
            
        strings.sort(key=lambda d: len(d['string']), reverse=True)
        size = len(strings)
        for i in range(0,len(strings)):
            if i >= size:
                break
            else:
                del_list = []
                for j in range(i+1,len(strings)):
                    if strings[j]['string'] in strings[i]['string']:
                        self.logger.debug(f'"{strings[j]["string"]}" in "{strings[i]["string"]}". Removing')
                        del_list.append(j)
            size = size - len(del_list)
            for d in reversed(del_list):
                strings.pop(d)
        return strings

    def build_rule(self, strings, hashes=[], rule_name='', reference='', tags=[], prefix='auto'):
        i = 0
        date = datetime.datetime.now().isoformat().split('T')[0]
        rule_uuid = str(uuid.uuid4())
        if tags:
            tags = ': ' + ' '.join(tags)
        else:
            tags = ''
        meta = f"""
    meta:
        uuid = "{rule_uuid}"
        tlp = "amber"
        author = "Jeremy Humble" 
        date = "{date}"
        description = "Autogenerated from reference samples"
        hashes = "{",".join(hashes)}"
        references = "{reference}"
        scope = "detection"
        platform = "icet"
"""
        output = f'rule Classification_{rule_name}{tags}{{' + '\n'
        output += meta
        output += '\n    strings:\n'
        for string in strings:
            output += f'        ${prefix}_{i:03} = {self.emit_string(string["string"])} // {string["percent"]*100:.01f}%\n' 
            i+= 1
        output += '\n    condition:\n        any of them\n}'
        return output

                
        
    def emit_string(self, string):
        printable_wide = re.compile(rb'^([\x00\x09\x0d\x0a\x20-\x7e]\x00)*$')
        if percent_printable(string) < .66:
            return f'{{{format_hex(string)}}}'
        # we are potentially removing useful bytes for detection here, but in most cases this is unlikely and this allows for much cleaner looking rules for many utf16 strings
        if printable_wide.match(string.lstrip(b'\x00')):
            try:
                rtn = yara_escape(string.lstrip(b'\x00').decode("utf-16le").encode())
                return f'"{rtn}" wide'
            except Exception as e:
                self.logger.warning(f'Failed to decode {string} as utf16-le: {e}')
        try:
            rtn = yara_escape(string)
            return f'"{rtn}" ascii'
        except Exception as e:
            import traceback
            self.logger.critical(f'Failed to decode {string}: {e}')
            self.logger.critical(traceback.format_exc())
            exit()
             

    def scan_benign(self, benign_paths, rule_text, rule):
        """Return the set of pattern identifiers that match any benign file.

        This is where a run actually spends its time -- on a 26k-file corpus it
        is ~95% of wall clock -- and every file is independent, so it splits
        across processes cleanly.
        """
        matched = set()
        errors = []

        if self.parallel <= 1 or len(benign_paths) < 2:
            for path in benign_paths:
                self.logger.debug(f'Scanning {path}')
                try:
                    for match in rule.match(path):
                        for offset, name, data in iterate_matches(match.strings):
                            matched.add(name)
                except Exception as e:
                    errors.append((path, str(e)))
        else:
            workers = min(self.parallel, len(benign_paths))
            # Hand out more chunks than workers so that one chunk happening to
            # hold several large files cannot stall the whole pass, and stride
            # rather than slice so same-directory files (often similar sizes)
            # are spread across chunks instead of piled into one.
            chunks = [c for c in (benign_paths[i::workers * 4]
                                  for i in range(workers * 4)) if c]
            self.logger.info(f'Scanning {len(benign_paths)} benign files with {workers} workers')
            with ProcessPoolExecutor(max_workers=workers,
                                     initializer=_init_scan_worker,
                                     initargs=(rule_text,)) as pool:
                for chunk_matched, chunk_errors in pool.map(_scan_paths, chunks):
                    matched |= chunk_matched
                    errors.extend(chunk_errors)

        for path, err in errors:
            self.logger.warning(f'Failed to scan {path}: {err}')
        return matched

    def process(self, args, benign_dirs=[], recursive=False, output_path=None, rule_name='', reference='', tags=[], prefix='auto'):
        path_to_data = {}
        strings = []
        paths = []
        hashes = []
        total_bytes = 0
        for arg in args:
            matched = recursive_all_files(arg)
            if not matched:
                self.logger.warning(f'No files matched input {arg!r}')
            paths.extend(matched)
        if not paths:
            raise SystemExit(
                f'No input files matched {args}. Nothing to build a signature '
                f'from -- check the paths are correct and relative to the '
                f'current directory ({os.getcwd()}).')
        for path in paths:
            with open(path, 'rb') as fp:
                data = fp.read()
            hashes.append(hashlib.md5(data).hexdigest())
            if self.bytes_to_read != -1:
                data = data[:self.bytes_to_read]
            path_to_data[path] = data
            total_bytes += len(data)
        self.logger.info(f'Building suffix tree from {len(paths)} files ({human_size(total_bytes)} total)')
        expected_build_time = str(datetime.timedelta(seconds=int(total_bytes/77000))) # builds about 77KB/s on my machine
        self.logger.info(f'Expected build time: {expected_build_time}')

        # Build the Tree
        start = time.time()
        self.tree = Tree(path_to_data)
        self.logger.info(f'Built Ukkonen tree in {time.time()-start:4.2f}s')
        
        i = 0
        if recursive:
            results = self.tree.maximal_repeats(recursive=True)
        else:
            start = time.time()
            results = self.tree.maximal_repeats(recursive=False)
            self.logger.info(f'Parsed common strings in {time.time()-start:4.2f}s')

        for k, path in results:
            self.logger.debug(f'k: {k}, path: {path}')
            s = bytearray(path.S[path.start: path.end]) # self.S[self.start : self.end]
            #self.logger.debug(f'K: {k}, string: {s}')
            if path and k/len(paths) >= self.percent and k > 1 and len(s) >= self.minimum:
                if len(s) <= self.maximum:
                    strings.append({'count': k, 'percent': k/len(paths), 'string': s})
                else:
                    # Split long strings into chunks of maximum length
                    for i in range(0, len(s), self.maximum):
                        chunk = s[i:i + self.maximum]
                        if len(chunk) >= self.minimum:
                            self.logger.debug(f'Splitting long string ({len(s)} bytes) into chunk: {chunk}')
                            strings.append({'count': k, 'percent': k/len(paths), 'string': chunk})
            else:
                self.logger.debug(f'Filtered out {s}. Path: {path}, k/len(paths): {k/len(paths)}, k: {k}')

        """
        print(f'[+] Recursion: {recursive}')
        def print_tree(node):
            try:
                ld = node.is_left_diverse
            except Exception as e:
                ld = f'ERROR: {e}'
            print(f'Node: {str(node)}; is_left_diverse: {ld}')

        self.tree.root.post_order(print_tree)
        """

        # Neither the tree nor the raw result list is needed past this point,
        # and together they hold well over a gigabyte for a few MB of input.
        # Drop them before the benign scan forks worker processes.
        self.tree = None
        results = None

        i = 0
        start = time.time() 
        # filter_strings is O(n^2), so if the number before filtering is excessively high, chop them down some here
        limit = min(self.max_strings*4, 5000)
        if len(strings) > limit:
            self.logger.warning(f'{len(strings)} strings before filtering. Truncating to {limit} before filtering.')
            strings = sorted(strings, key=lambda x: (x['percent'], len(x['string'])), reverse=True)[:limit]

        if self.string_filter:
            strings = self.filter_strings(strings, self.null_filter, self.entropy_filter)
            while len(strings) > self.max_strings:
                self.logger.warning(f'Too many strings remain ({len(strings)} after filtering with null filter >{self.null_filter*100:2.1f}% and entropy filter > {self.entropy_filter:.2f}. tightening both by 5% to filter further') 
                self.null_filter = self.null_filter*.95
                self.entropy_filter = self.entropy_filter*1.05
                strings = self.filter_strings(strings, self.null_filter, self.entropy_filter)
        else:
            strings = self.filter_strings(strings, self.null_filter, self.entropy_filter)
            strings = sorted(strings, key=lambda x: x['percent'], reverse=True)
            strings = strings[:self.max_strings]
        self.logger.info(f'Filtered strings in {time.time()-start:4.2f}s')
        self.logger.info(f'{len(strings)} strings left after filtering. Building yara rule...')

        if not strings:
            self.logger.critical('No strings remaining after filtering')
            return 

        
        with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.txt') as fp:
            fp.write('\n'.join([str(string) for string in strings]))
            self.logger.info(f'Strings written to {fp.name}')

        rule_text = self.build_rule(strings, hashes=hashes, rule_name=rule_name, reference=reference, tags=tags, prefix=prefix)
        with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.yar') as fp:
            fp.write(rule_text)
            self.logger.info(f'Yara rule (Before benign filtering) written to {fp.name}')
    
        try:
            rule = yara.compile(source=rule_text)
        except Exception as e:
            self.logger.critical(f'Failed to compile rule: {e}')
            with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.yar') as fp:
                fp.write(rule_text)
                self.logger.critical(f'broken yara rule written to {fp.name}')
            return False

        to_remove = set()
        benign_paths = []
        for benign in benign_dirs:
            found = recursive_all_files(benign)
            self.logger.info(f'Testing with {len(found)} benign files from {benign}')
            benign_paths.extend(found)

        if benign_paths:
            start = time.time()
            for name in self.scan_benign(benign_paths, rule_text, rule):
                try:
                    # [-1] so that prefixes may themselves contain underscores
                    to_remove.add(int(name.split('_')[-1]))
                except ValueError:
                    self.logger.warning(f'Could not parse a pattern id out of {name}')
            self.logger.info(f'Scanned benign corpus in {time.time()-start:4.2f}s')
        self.logger.debug(f'Removing {to_remove}')
        for _id in sorted(list(to_remove ), reverse=True):
            try:
                del strings[_id]
            except Exception as e:
                self.logger.critical(f'Failed to remove {_id}: {e}')
        self.logger.info(f'{len(strings)} remain after yara filtering')
        #write filtered rule
        rule = self.build_rule(strings, hashes=hashes, rule_name=rule_name, reference=reference, tags=tags, prefix=prefix)
        if not output_path:
            with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.yar') as fp:
                output_path = fp.name
                fp.write(rule)
        else:
            with open(output_path, 'w') as fp:
                fp.write(rule)
        print(f'Rule written to {output_path}')
        
        
            
if __name__ == '__main__':
    options = parse_args()
    configure_logger(options.verbose)
    sm = Sigmaker(  options.percent, 
                    options.minimum, 
                    options.maximum, 
                    options.bytes, 
                    options.strings,
                    options.filter,
                    options.parallel)
    sm.process(options.files, options.benign, recursive=options.recursive, output_path=options.output, rule_name=options.name, reference=options.reference, tags=options.tags, prefix=options.prefix)

    """
    for recurse in [False, True]:
        print(recurse)
        start = time.time()
        sm.process(options.files, options.benign, recursive=recurse)
        delta = time.time() - start
        print(f'Recursion: {recurse}, time: {delta}')
    """

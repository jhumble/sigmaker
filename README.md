# sigmaker

Autogenerate YARA rules from collections of similar files.

sigmaker builds a [generalized suffix tree](https://en.wikipedia.org/wiki/Generalized_suffix_tree)
over a set of input samples, extracts the substrings common to some percentage of
them, optionally filters out anything that also appears in a corpus of benign
files, and emits the survivors as a YARA rule.

## Install

```sh
git clone git@github.com:jhumble/sigmaker.git
cd sigmaker
tools/setup.sh
```

`tools/setup.sh` creates `./venv`, installs the dependencies into it, and tells
you whether the compiled (Cython) extensions were built or whether it fell back
to pure Python. Nothing is installed into your system Python.

To use a different interpreter, pass it as an argument:

```sh
tools/setup.sh python3.13     # needs `sudo apt install python3.13-venv` first
```

Requires `build-essential` and the matching `python3.X-dev` package to compile
the extensions. If either is missing the install still succeeds — the tree code
is pure Python and simply runs about 1.7x slower.

## Run

`bin/sigmaker` is the entry point. It finds its own virtualenv, so there is no
`activate` step and no dependence on which `python3` happens to be first on your
`PATH`:

```sh
bin/sigmaker -p 99 -vv -s 5000 -b ~/RE/samples/benign -o out.yar sample1.exe sample2.bin
```

It resolves symlinks, so it can be linked onto your `PATH`:

```sh
sudo ln -s /opt/sigmaker/bin/sigmaker /usr/local/bin/sigmaker
```

Common options:

| flag | meaning |
|---|---|
| `-p N` | string must appear in N% of input files (default 51) |
| `-b DIR` | benign corpus; strings matching anything in it are dropped. Repeatable |
| `-m` / `-M` | min / max string length (default 5 / 128) |
| `-s N` | cap the rule at N strings |
| `-P NAME` | pattern name prefix, e.g. `-P auto` gives `$auto_000` |
| `-B N` | only read the first N bytes of each input file |
| `-j N` | worker processes for the benign scan. `1` disables multiprocessing. Defaults to `min(8, physical cores / 2)` |
| `--ignore-memory-limit` | run even when the estimated peak memory exceeds what is available |
| `-R` | use the recursive tree traversal (see below) |

## Memory is the binding constraint

A generalized suffix tree is far larger than the text it indexes. Measured across
nine runs on three malpedia families:

```
peak RSS  ~=  500 MB per MB of total input
```

Linear, with under 5% spread between families, so it is predictable enough to
plan around. **This, not runtime, is what limits how much you can feed it** — a
run that fits will finish, a run that does not will thrash and get OOM-killed
after several minutes of work.

sigmaker estimates the peak before building anything and compares it against
`MemAvailable`:

- over 75% of available memory — warns, and suggests a `-B` that would fit
- over 100% — refuses to start, unless you pass `--ignore-memory-limit`

The estimate is deliberately a little conservative (it assumes 550 MB/MB), since
being wrong low means an OOM kill and being wrong high only means a warning.

Rough capacity, assuming most of the machine is free:

| MemAvailable | input that fits |
|---|---|
| 8 GB | ~11 MB |
| 16 GB | ~22 MB |
| 32 GB | ~44 MB |
| 64 GB | ~87 MB |

To cut input down, `-B N` reads only the first N bytes of each file. The useful
value depends on how many samples you have: `-B (budget / number of samples)`.

Deduping near-identical samples helps twice — it avoids over-fitting the rule,
and every duplicated byte costs the same 500 MB/MB as a novel one.

## Where the time goes

Two phases matter, and which one dominates depends entirely on input size:

```
tree build + maximal_repeats   ~4.6 s per MB of input   (grows)
benign scan over 26k files     ~46 s at -j 4            (flat)
```

The benign scan is fixed work for a given corpus, so it dominates small runs and
becomes a rounding error on large ones — the crossover is around 10 MB of input.
On 18.7 MB of real samples the tree phases take 80s of a 143s run.

That phase is `-j`-parallel because every file is independent. The default is
`min(8, physical cores / 2)` — 4 on an 8-core workstation, 8 on anything 16-core
or larger. It is deliberately conservative on both counts: the shared analysis
server has a dozen analysts on it and two or three concurrent sigmaker runs must
not bog it down, and leaving half the cores free keeps a workstation usable
while a scan runs. Physical rather than logical cores because scanning is
memory-bandwidth bound, so hyperthreads add little.

Raise it with `-j 16` when you have the machine to yourself; `-j 1` restores the
old single-process behaviour, which is worth doing if you are debugging a scan.

Output does not depend on `-j`: the phase collects a set of matching pattern
identifiers, and set union does not care what order the workers finish in.

## Which interpreter

Stock CPython. The venv is built on `python3` (3.12 on Ubuntu 24.04) unless you
pass another interpreter to `tools/setup.sh`.

**PyPy is no longer used.** Older versions of this README recommended it as
"3-4x faster", but that number was measured against a version of the suffix-tree
fork that had an accidental O(n^2) loop in `maximal_repeats` — PyPy's JIT was
papering over a quadratic algorithm. With that fixed, the same workload that took
65s now takes 10.5s on plain CPython and 6.2s with the Cython extensions. PyPy
also cannot be combined with Cython (it runs C extensions through a slow
compatibility layer), and sigmaker leans on yara-python, which is itself a C
extension. CPython + Cython is the faster and simpler target.

Measured on 1047 KB across 2 samples, all producing byte-identical output:

| variant | build | maximal_repeats | total | peak RSS |
|---|---|---|---|---|
| original | 7.95s | 57.41s | 65.36s | 1890 MB |
| after the O(n^2) fix, pure Python | 6.69s | 3.83s | 10.52s | 1520 MB |
| + Cython | 3.17s | 2.98s | 6.15s | 1554 MB |
| + the `__slots__` and `left` fixes | 2.33s | 1.92s | 4.25s | 529 MB |

## The suffix-tree fork

`./suffix-tree` is a **fork** of [cceh/suffix-tree](https://github.com/cceh/suffix-tree),
nested inside this repo as a separate git checkout (deliberately not a submodule).
`tools/setup.sh` installs from that local directory when it is present and falls
back to GitHub when it is not.

**Do not replace it with upstream `suffix-tree` from PyPI.** The fork exists for
one reason: upstream's `maximal_repeats` walks the tree recursively, and a suffix
tree built over even a moderately sized binary is deep enough to blow Python's
stack. The fork adds non-recursive (`nr_`-prefixed) equivalents and a
`recursive=` parameter:

```python
tree.maximal_repeats(recursive=False)   # iterative — the default sigmaker uses
tree.maximal_repeats(recursive=True)    # upstream's recursion — small inputs only
```

sigmaker passes `recursive=False` unless you give it `-R`. The recursive path is
kept because it is the reference implementation the iterative one is tested
against: `tools/difftest.py` builds hundreds of corpora and asserts both paths
return the same multiset of results.

**Treat `-R` as a debugging aid, not an option.** How the recursive path fails
depends on how the package was built, and the compiled build fails worse:

| build | deep input |
|---|---|
| pure Python | `RecursionError` above a few thousand bytes — catchable, with a traceback |
| Cython | compiled calls bypass Python's recursion counter, so it runs past the limit and then **SIGSEGVs** on the C stack — no traceback, process just dies |

The iterative path handled 100 KB of repeating bytes in both builds.

Two things about the fork are easy to trip over:

- `Leaf` objects are given `left` and `is_left_diverse` attributes they do not
  have upstream, so that a single iterative traversal can walk leaves and
  internal nodes uniformly. (They used to be given an empty `children` dict for
  the same reason; that is gone now the traversals dispatch on type.)
- Every class in `node.py` **and** in `lca_mixin.py` must declare `__slots__`,
  including empty ones on the mixins. A single class without it gives every node
  a `__dict__`, and there are ~1.5 nodes per input byte — that one omission cost
  about 40% of peak memory.
- Because of that, *never* test for a leaf with `if not node.children`. An
  `Internal` node can legitimately have no children (the root of an empty tree),
  and it will then take the leaf branch and fail on `node.str_id`. Use
  `isinstance(node, Leaf)`.

## Development

Run the parity suite after any change to the tree traversals:

```sh
venv/bin/python tools/difftest.py 0
venv/bin/python tools/difftest.py 1
```

After editing anything under `suffix-tree/`, reinstall so the compiled
extensions are rebuilt:

```sh
venv/bin/pip install ./suffix-tree
```

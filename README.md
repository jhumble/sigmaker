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
| `-R` | use the recursive tree traversal (see below) |

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

Measured on 1047 KB across 2 samples:

| variant | build | maximal_repeats | total |
|---|---|---|---|
| before the O(n^2) fix | 7.95s | 57.41s | 65.36s |
| pure Python | 6.69s | 3.83s | 10.52s |
| Cython | 3.17s | 2.98s | 6.15s |

All three produce byte-identical output.

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

- `Leaf` objects are given `children = {}`, `left = {}` and `is_left_diverse`
  attributes they do not have upstream, so that a single iterative traversal can
  walk leaves and internal nodes uniformly.
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

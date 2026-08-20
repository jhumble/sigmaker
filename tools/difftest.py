"""Differential test: recursive vs non-recursive maximal_repeats.

Both implementations must return the same multiset of (count, substring).
A fresh Tree is built for each run because maximal_repeats mutates node state
(C, is_left_diverse, left), so reusing one tree would contaminate the second run.
"""
import random, sys, itertools
from collections import Counter
from suffix_tree import Tree


def repeats(d, recursive):
    t = Tree(d)
    out = t.maximal_repeats(recursive=recursive)
    return Counter((k, bytes(p.S[p.start:p.end])) for k, p in out)


def compare(d, label):
    try:
        rec = repeats(d, True)
    except RecursionError:
        return None  # recursive can't handle it; nothing to compare
    except Exception as e:
        print(f'  {label}: RECURSIVE raised {type(e).__name__}: {e}')
        return False
    try:
        nr = repeats(d, False)
    except Exception as e:
        print(f'  {label}: NON-RECURSIVE raised {type(e).__name__}: {e}')
        return False
    if rec != nr:
        only_r = rec - nr
        only_n = nr - rec
        print(f'  {label}: MISMATCH  input={d}')
        print(f'      only recursive ({sum(only_r.values())}): {list(only_r)[:8]}')
        print(f'      only non-recur ({sum(only_n.values())}): {list(only_n)[:8]}')
        return False
    return True


def main():
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    random.seed(seed)
    fails = passes = skips = 0

    cases = []

    # --- hand-picked edge cases ---
    cases.append(({}, 'empty-dict'))
    cases.append(({'a': b''}, 'single-empty-string'))
    cases.append(({'a': b'', 'b': b''}, 'two-empty-strings'))
    cases.append(({'a': b'x'}, 'single-char'))
    cases.append(({'a': b'aaaa'}, 'repeat-one-char'))
    cases.append(({'a': b'aaaa', 'b': b'aaaa'}, 'identical'))
    cases.append(({'a': b'abcabc', 'b': b'abcabc', 'c': b'abcabc'}, 'three-identical'))
    cases.append(({'a': b'hello world', 'b': b'hello there'}, 'common-prefix'))
    cases.append(({'a': b'\x00\x00\x00', 'b': b'\x00\x00\x00'}, 'null-bytes'))
    cases.append(({'a': bytes(range(256)), 'b': bytes(range(256))}, 'all-byte-values'))
    # start-of-string left context (exercises compute_left_diverse start==0 branch)
    cases.append(({'a': b'xabc', 'b': b'abc'}, 'start-of-string-ctx'))
    cases.append(({'a': b'abc', 'b': b'abc', 'c': b'zabc'}, 'start-vs-left-char'))

    # --- randomized: tiny alphabets maximize repeat structure ---
    for i in range(400):
        alpha = random.choice([b'ab', b'abc', b'abcd', bytes(range(8))])
        n = random.randint(1, 5)
        d = {}
        for j in range(n):
            ln = random.randint(0, 40)
            d[f's{j}'] = bytes(random.choice(alpha) for _ in range(ln))
        cases.append((d, f'rand-{i}'))

    for d, label in cases:
        r = compare(d, label)
        if r is None:
            skips += 1
        elif r:
            passes += 1
        else:
            fails += 1

    print(f'\nseed={seed}  pass={passes}  FAIL={fails}  skip={skips}')
    if not test_deep_input():
        fails += 1
    return 1 if fails else 0



def test_deep_input():
    """The reason this fork exists.

    A suffix tree over a long run of repeating bytes is one node deep per byte,
    so upstream's recursive traversal runs out of stack.  How it fails depends
    on the build:

      * pure Python -- RecursionError somewhere above a few thousand bytes.
      * Cython      -- compiled calls do not go through Python's recursion
                       counter, so it sails past the limit and then SIGSEGVs on
                       the C stack.  Silent process death, no traceback.

    The iterative path must handle it either way.  That second case is why
    sigmaker defaults to recursive=False and why -R should be considered a
    debugging aid only.
    """
    n = 100000
    data = {'a': b'a' * n, 'b': b'a' * n + b'b'}
    try:
        nr = repeats(data, False)
    except RecursionError:
        print(f'DEEP INPUT ({n} bytes): non-recursive hit RecursionError -- the fork is broken')
        return False
    if sum(nr.values()) != n:
        print(f'DEEP INPUT ({n} bytes): expected {n} results, got {sum(nr.values())}')
        return False
    print(f'DEEP INPUT ({n} bytes): non-recursive returned {sum(nr.values())} results, no crash')
    return True


if __name__ == '__main__':
    sys.exit(main())

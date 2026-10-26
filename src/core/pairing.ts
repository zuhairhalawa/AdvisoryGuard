/**
 * Deterministic matching of "before" items to "after" items. Used wherever the
 * identity of an item is not a simple unique key (affected packages, ranges,
 * severity entries, list objects).
 */

/** Upper bound on candidate (before, after) combinations scored by the heuristic phase. */
export const MAX_PAIR_CANDIDATES = 250_000;

export interface PairResult {
  /** Matched index pairs, sorted by before-index. `exact` means canonically equal. */
  pairs: { bi: number; ai: number; exact: boolean }[];
  restB: number[];
  restA: number[];
  /**
   * True when the heuristic (non-exact) matching phase was skipped because it would have
   * needed more than MAX_PAIR_CANDIDATES comparisons. Unmatched items are then simply
   * reported as removed/added, which is conservative (they still require review).
   */
  skipped: boolean;
}

export interface PairOptions<B, A> {
  /** Only items with equal bucket keys are ever compared by `score` (keeps big lists linear). */
  bucketB?: (b: B) => string;
  bucketA?: (a: A) => string;
  maxCandidates?: number;
}

/**
 * 1. Items with identical canonical keys are paired first (so reordering never
 *    produces a difference).
 * 2. Remaining items are paired greedily by descending `score` (>= 0 means
 *    "eligible"; negative means "never pair"), ties broken by position.
 */
export function pairItems<B, A>(
  bs: readonly B[],
  as: readonly A[],
  canonB: (b: B) => string,
  canonA: (a: A) => string,
  score: (b: B, a: A) => number,
  options: PairOptions<B, A> = {},
): PairResult {
  const usedB = new Set<number>();
  const usedA = new Set<number>();
  const pairs: PairResult["pairs"] = [];

  const byKey = new Map<string, number[]>();
  as.forEach((a, ai) => {
    const k = canonA(a);
    const list = byKey.get(k);
    if (list) list.push(ai);
    else byKey.set(k, [ai]);
  });
  bs.forEach((b, bi) => {
    const list = byKey.get(canonB(b));
    const ai = list?.shift();
    if (ai !== undefined) {
      pairs.push({ bi, ai, exact: true });
      usedB.add(bi);
      usedA.add(ai);
    }
  });

  const freeB = bs.map((_, i) => i).filter((i) => !usedB.has(i));
  const freeA = as.map((_, i) => i).filter((i) => !usedA.has(i));
  const limit = options.maxCandidates ?? MAX_PAIR_CANDIDATES;
  let skipped = false;

  // Which after-items may each before-item be compared with?
  let candidatesFor: (bi: number) => number[];
  let total = 0;
  if (options.bucketA && options.bucketB) {
    const buckets = new Map<string, number[]>();
    for (const ai of freeA) {
      const k = options.bucketA(as[ai] as A);
      const list = buckets.get(k);
      if (list) list.push(ai);
      else buckets.set(k, [ai]);
    }
    candidatesFor = (bi) => buckets.get((options.bucketB as (b: B) => string)(bs[bi] as B)) ?? [];
    for (const bi of freeB) total += candidatesFor(bi).length;
  } else {
    candidatesFor = () => freeA;
    total = freeB.length * freeA.length;
  }

  if (total > limit) {
    skipped = true;
  } else {
    const cands: { s: number; bi: number; ai: number }[] = [];
    for (const bi of freeB) {
      for (const ai of candidatesFor(bi)) {
        const s = score(bs[bi] as B, as[ai] as A);
        if (s >= 0) cands.push({ s, bi, ai });
      }
    }
    cands.sort((x, y) => y.s - x.s || x.bi - y.bi || x.ai - y.ai);
    for (const c of cands) {
      if (usedB.has(c.bi) || usedA.has(c.ai)) continue;
      usedB.add(c.bi);
      usedA.add(c.ai);
      pairs.push({ bi: c.bi, ai: c.ai, exact: false });
    }
  }

  pairs.sort((x, y) => x.bi - y.bi || x.ai - y.ai);
  return {
    pairs,
    restB: bs.map((_, i) => i).filter((i) => !usedB.has(i)),
    restA: as.map((_, i) => i).filter((i) => !usedA.has(i)),
    skipped,
  };
}

/** Size of the multiset-free intersection of two string collections. */
export function overlap(a: Iterable<string>, b: Iterable<string>): number {
  const sb = new Set(b);
  let n = 0;
  for (const x of new Set(a)) if (sb.has(x)) n++;
  return n;
}

/** Elements of `a` not present in `b`, preserving first-seen order, de-duplicated. */
export function setMinus(a: readonly string[], b: readonly string[]): string[] {
  const sb = new Set(b);
  const seen = new Set<string>();
  const out: string[] = [];
  for (const x of a) {
    if (!sb.has(x) && !seen.has(x)) {
      seen.add(x);
      out.push(x);
    }
  }
  return out;
}

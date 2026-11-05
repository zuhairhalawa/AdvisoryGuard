import { MAX_MATCHING_WORK, PAIRING_LIMIT_WHY, overlap, pairItems, setMinus } from "../pairing.js";
import type { WorkBudget } from "../pairing.js";
import type { Finding, JsonObject, JsonValue } from "../types.js";
import { asArray, asObjectArray, canonical, clone, getOwn, isObject, isString, shorten } from "../util.js";
import { diffGeneric, diffOtherKeys } from "./generic.js";
import { diffSeverity } from "./severity.js";

const EVENT_KINDS = ["introduced", "fixed", "last_affected", "limit"] as const;
type EventKind = (typeof EVENT_KINDS)[number];

interface Pkg {
  ecosystem: string;
  name: string;
  purl: string | undefined;
}

function pkgOf(entry: JsonObject): Pkg | null {
  const p = getOwn(entry, "package");
  if (!isObject(p)) return null;
  const eco = getOwn(p, "ecosystem");
  const name = getOwn(p, "name");
  const purl = getOwn(p, "purl");
  return {
    ecosystem: isString(eco) ? eco : "",
    name: isString(name) ? name : "",
    purl: isString(purl) ? purl : undefined,
  };
}

function labelOf(entry: JsonObject, index: number): string {
  const p = pkgOf(entry);
  if (p && (p.name || p.ecosystem)) return `${p.ecosystem}/${p.name}`;
  const gitRepo = asObjectArray(getOwn(entry, "ranges"))
    .map((r) => getOwn(r, "repo"))
    .find(isString);
  return gitRepo ? `git:${shorten(gitRepo, 60)}` : `#${index}`;
}

function keyOf(entry: JsonObject): string {
  const p = pkgOf(entry);
  return p ? `${p.ecosystem}\u0000${p.name}` : "";
}

function eventTokens(range: JsonObject): string[] {
  const out: string[] = [];
  for (const ev of asObjectArray(getOwn(range, "events"))) {
    for (const k of EVENT_KINDS) {
      const v = getOwn(ev, k);
      if (isString(v)) out.push(`${k}:${v}`);
    }
  }
  return out;
}

function versionList(entry: JsonObject): string[] {
  return asArray(getOwn(entry, "versions")).filter(isString);
}

function entryTokens(entry: JsonObject): string[] {
  return [
    ...asObjectArray(getOwn(entry, "ranges")).flatMap(eventTokens),
    ...versionList(entry).map((v) => `v:${v}`),
  ];
}

type TokenSets = (o: JsonObject) => Set<string>;

/** Matching compares the same objects many times, so derive each object's tokens only once. */
function memoized(f: (o: JsonObject) => string[]): TokenSets {
  const cache = new WeakMap<JsonObject, Set<string>>();
  return (o) => {
    let tokens = cache.get(o);
    if (!tokens) {
      tokens = new Set(f(o));
      cache.set(o, tokens);
    }
    return tokens;
  };
}

/**
 * State for one `diffAffected` call. The token caches live here rather than at module scope
 * because callers of the public `diffAdvisories` may change an object between two comparisons.
 */
interface MatchContext {
  budget: WorkBudget;
  eventSet: TokenSets;
  entrySet: TokenSets;
  /** Set when a limit stopped range pairing, so ranges were reported as removed and added. */
  rangesSkipped: boolean;
}

/** One unit for the comparison itself, plus the set look-ups `overlap` will make. */
function matchWeight(tokensOf: TokenSets): (b: JsonObject, a: JsonObject) => number {
  return (b, a) => 1 + Math.min(tokensOf(b).size, tokensOf(a).size);
}

function normalizeName(n: string): string {
  return n.toLowerCase().split("_").join("-").split(".").join("-");
}

/**
 * Text for a value that should be a string. Invalid data can hold objects that String() cannot convert,
 * and this runs for every scored pair, so it must stay cheap.
 */
function textOf(v: JsonValue | undefined, fallback: string): string {
  if (v === undefined || v === null) return fallback;
  return typeof v === "object" ? "(invalid)" : String(v);
}

function previewList(values: string[], max = 6): string {
  const shown = values.slice(0, max).map((v) => shorten(v, 40)).join(", ");
  return values.length > max ? `${shown}, and ${values.length - max} more` : shown;
}

const EVENT_WHY: Record<EventKind, { removed: string; added: string; changed: string }> = {
  introduced: {
    removed: "Removing an introduced event changes where the vulnerable range starts (a range needs at least one).",
    added: "A new introduced event starts an interval, so versions from it onward may be marked as vulnerable.",
    changed: "Changing where the vulnerability was introduced changes which versions are reported as affected.",
  },
  fixed: {
    removed: "Without a fixed event the range is open-ended: every later version is treated as vulnerable and no patched version is advertised.",
    added: "A new fixed event adds an exclusive end to the range, so versions from it onward may be treated as patched unless another interval covers them.",
    changed: "The fixed version decides which release is considered patched; versions between the old and new value may change status.",
  },
  last_affected: {
    removed: "Without last_affected (or fixed) the range is open-ended and later versions are treated as vulnerable.",
    added: "A last_affected event adds an inclusive end to the range, so later versions may be treated as unaffected unless another interval covers them.",
    changed: "Changing last_affected changes which versions are reported as affected.",
  },
  limit: {
    removed: "The limit event bounds git ranges; removing it may widen the range.",
    added: "A limit event may narrow a git range.",
    changed: "Changing the limit changes which commits are in scope.",
  },
};

/** Removing an end while another one stays: "open-ended" would be false, and which interval it closed is unknown. */
const END_REMOVED_WHY = "Another end remains in this range. Removing this one changes which versions the range covers, so check the range as a whole.";

/**
 * `last_affected` is an inclusive end and `fixed` an exclusive one, so replacing one with the
 * other is a single edit whose effect neither the removal nor the addition explains on its own.
 */
function boundConvertedWhy(git: boolean, valueKept: boolean): string {
  const unit = git ? "commit" : "version";
  const ends = `"last_affected" is an inclusive end (that ${unit} is affected) and "fixed" is an exclusive end (that ${unit} is not).`;
  if (valueKept) return `${ends} A value stayed the same, so this end now treats that ${unit} differently, though other data in the advisory may still cover it. Confirm which is correct.`;
  return git
    ? `${ends} Replacing one with the other may change which commits are affected, or may change nothing, depending on the repository's history. AdvisoryGuard does not walk commit history, so check the repository.`
    : `${ends} Replacing one with the other may change which releases are affected, or may change nothing, depending on what the package has released. AdvisoryGuard does not compare versions, so check the package's release history.`;
}

function reportBoundConversions(
  gone: Record<EventKind, string[]>,
  fresh: Record<EventKind, string[]>,
  where: string,
  path: string,
  git: boolean,
  afterNamesFixed: boolean,
  out: Finding[],
): void {
  const noPatched = afterNamesFixed ? "" : `this range no longer names a patched ${git ? "commit" : "version"}`;
  for (const [from, to] of [["last_affected", "fixed"], ["fixed", "last_affected"]] as const) {
    // A same-kind change on either side means this is not simply one kind replacing the other.
    if (fresh[from].length > 0 || gone[to].length > 0) continue;
    const olds = gone[from];
    const news = fresh[to];
    const [before] = olds;
    const [after] = news;
    if (before === undefined || after === undefined) continue;
    // A different number of ends means an interval gained or lost one, which is more than a change of kind.
    if (olds.length !== news.length) continue;
    const single = olds.length === 1;
    const sameValue = single && before === after;
    const newValues = new Set(news);
    const lostPatched = to === "last_affected" && noPatched ? `, and ${noPatched}` : "";
    let message: string;
    if (sameValue) {
      const [end, effect] = to === "fixed" ? ["exclusive", "no longer includes"] : ["inclusive", "now includes"];
      message = `"${from}" ${before} was replaced by "${to}" ${after} in ${where}: the same value is now an ${end} end, so this end ${effect} ${after}${lostPatched}.`;
    } else if (single && to === "fixed") {
      message = `"${from}" ${before} was replaced by "${to}" ${after} in ${where}: an inclusive end at ${before} became an exclusive end at ${after}.`;
    } else if (single) {
      message = `"${from}" ${before} was replaced by "${to}" ${after} in ${where}: an exclusive end at ${before} became an inclusive end at ${after}${lostPatched}.`;
    } else {
      // Without comparing versions there is no way to say which value replaced which.
      message = `"${from}" values (${previewList(olds)}) were replaced by "${to}" values (${previewList(news)}) in ${where}. The values are not paired, because AdvisoryGuard does not compare ${git ? "commits" : "versions"}.${to === "last_affected" && noPatched ? ` Also, ${noPatched}.` : ""}`;
    }
    out.push({
      code: "range-bound-converted",
      level: "review",
      path,
      message,
      why: boundConvertedWhy(git, olds.some((v) => newValues.has(v))),
      before: single ? before : olds,
      after: single ? after : news,
    });
    gone[from] = [];
    fresh[to] = [];
  }
}

function diffRanges(b: JsonObject, a: JsonObject, label: string, path: string, out: Finding[], ctx: MatchContext): void {
  const bs = asObjectArray(getOwn(b, "ranges"));
  const as = asObjectArray(getOwn(a, "ranges"));
  const rangeId = (r: JsonObject): string => `${textOf(getOwn(r, "type"), "?")}|${textOf(getOwn(r, "repo"), "")}`;
  const { pairs, restB, restA, skipped } = pairItems(
    bs,
    as,
    (r) => canonical(r),
    (r) => canonical(r),
    (rb, ra) => (rangeId(rb) === rangeId(ra) ? 100 + overlap(ctx.eventSet(rb), ctx.eventSet(ra)) : -1),
    { budget: ctx.budget, weight: matchWeight(ctx.eventSet) },
  );
  // Only ranges of the same type and repo can pair, so anything else did not lose out to the limit.
  if (skipped) {
    const idsA = new Set(restA.map((ai) => rangeId(as[ai] as JsonObject)));
    if (restB.some((bi) => idsA.has(rangeId(bs[bi] as JsonObject)))) ctx.rangesSkipped = true;
  }

  for (const { bi, ai, exact } of pairs) {
    if (exact) continue;
    const rb = bs[bi];
    const ra = as[ai];
    if (!rb || !ra) continue;
    const rtype = textOf(getOwn(rb, "type"), "range");
    const where = `${rtype} range of ${label}`;
    const valuesOf = (r: JsonObject, kind: EventKind): string[] =>
      asObjectArray(getOwn(r, "events")).map((e) => getOwn(e, kind)).filter(isString);
    const eventDelta = (x: JsonObject, y: JsonObject): Record<EventKind, string[]> => ({
      introduced: setMinus(valuesOf(x, "introduced"), valuesOf(y, "introduced")).sort(),
      fixed: setMinus(valuesOf(x, "fixed"), valuesOf(y, "fixed")).sort(),
      last_affected: setMinus(valuesOf(x, "last_affected"), valuesOf(y, "last_affected")).sort(),
      limit: setMinus(valuesOf(x, "limit"), valuesOf(y, "limit")).sort(),
    });
    const goneByKind = eventDelta(rb, ra);
    const freshByKind = eventDelta(ra, rb);
    const afterNamesFixed = valuesOf(ra, "fixed").length > 0;
    const afterHasEnd = afterNamesFixed || valuesOf(ra, "last_affected").length > 0;
    reportBoundConversions(goneByKind, freshByKind, where, path, rtype === "GIT", afterNamesFixed, out);
    for (const kind of EVENT_KINDS) {
      const gone = goneByKind[kind];
      const fresh = freshByKind[kind];
      // Which of several values replaced which cannot be known without comparing versions.
      const n = gone.length === 1 && fresh.length === 1 ? 1 : 0;
      for (let k = 0; k < n; k++) {
        out.push({
          code: "range-event-changed",
          level: "review",
          path,
          message: `"${kind}" event changed in ${where}: ${gone[k]} -> ${fresh[k]}.`,
          why: EVENT_WHY[kind].changed,
          before: gone[k] as string,
          after: fresh[k] as string,
        });
      }
      for (const v of gone.slice(n)) {
        out.push({
          code: "range-event-removed",
          level: "review",
          path,
          message: `"${kind}" event removed from ${where}: ${v}.`,
          why: (kind === "fixed" || kind === "last_affected") && afterHasEnd ? END_REMOVED_WHY : EVENT_WHY[kind].removed,
          before: v,
        });
      }
      for (const v of fresh.slice(n)) {
        out.push({
          code: "range-event-added",
          level: "review",
          path,
          message: `"${kind}" event added to ${where}: ${v}.`,
          why: EVENT_WHY[kind].added,
          after: v,
        });
      }
    }
    // Remaining differences inside the range object (e.g. database_specific) are covered generically.
    const rest = (r: JsonObject): JsonValue => {
      const c = clone(r);
      delete c["events"];
      return c;
    };
    diffGeneric(rest(rb), rest(ra), `${path}.ranges`, out);
    const eventId = (e: JsonObject): string | undefined =>
      EVENT_KINDS.flatMap((k) => {
        const v = getOwn(e, k);
        return isString(v) ? [`${k}:${v}`] : [];
      }).join(",") || undefined;
    diffOtherKeys(getOwn(rb, "events"), getOwn(ra, "events"), EVENT_KINDS, eventId, `${path}.ranges.events`, out);
  }

  for (const bi of restB) {
    const r = bs[bi];
    if (!r) continue;
    out.push({
      code: "range-removed",
      level: "review",
      path,
      message: `${textOf(getOwn(r, "type"), "A")} range removed from ${label}: ${previewList(eventTokens(r))}.`,
      why: "Removing a whole range stops flagging every version it covered.",
      before: canonical(r),
    });
  }
  for (const ai of restA) {
    const r = as[ai];
    if (!r) continue;
    out.push({
      code: "range-added",
      level: "review",
      path,
      message: `${textOf(getOwn(r, "type"), "A")} range added to ${label}: ${previewList(eventTokens(r))}.`,
      why: "A new range marks additional versions as vulnerable.",
      after: canonical(r),
    });
  }
}

function diffVersions(b: JsonObject, a: JsonObject, label: string, path: string, out: Finding[]): void {
  const bv = versionList(b);
  const av = versionList(a);
  const gone = setMinus(bv, av);
  const fresh = setMinus(av, bv);
  if (gone.length > 0) {
    out.push({
      code: "versions-removed",
      level: "review",
      path: `${path}.versions`,
      message: `${gone.length} explicitly listed affected version(s) removed from ${label}: ${previewList(gone)}.`,
      why: "Versions that are no longer listed will no longer be flagged as vulnerable (unless a range covers them).",
      before: gone,
    });
  }
  if (fresh.length > 0) {
    out.push({
      code: "versions-added",
      level: "review",
      path: `${path}.versions`,
      message: `${fresh.length} affected version(s) added to ${label}: ${previewList(fresh)}.`,
      why: "Newly listed versions will be flagged as vulnerable.",
      after: fresh,
    });
  }
}

/** Everything in an affected entry that has no dedicated comparer. */
function remainder(entry: JsonObject): JsonValue {
  const c = clone(entry);
  delete c["ranges"];
  delete c["versions"];
  delete c["severity"];
  const p = getOwn(c, "package");
  if (isObject(p)) {
    delete p["name"];
    delete p["ecosystem"];
    delete p["purl"];
    if (Object.keys(p).length === 0) delete c["package"];
  }
  return c;
}

function diffPair(b: JsonObject, a: JsonObject, ai: number, out: Finding[], ctx: MatchContext): void {
  const label = labelOf(a, ai);
  const path = `affected[${label}]`;
  const pb = pkgOf(b);
  const pa = pkgOf(a);

  if (pb && pa) {
    if (pb.ecosystem !== pa.ecosystem) {
      out.push({
        code: "package-ecosystem-changed",
        level: "review",
        path: `${path}.package.ecosystem`,
        message: `Package ecosystem changed from "${pb.ecosystem}" to "${pa.ecosystem}" (package ${pa.name}).`,
        why: "The advisory now targets a different package registry. Confirm this is a correction and not an accidental edit.",
        before: pb.ecosystem,
        after: pa.ecosystem,
      });
    }
    if (pb.name !== pa.name) {
      const sameish = normalizeName(pb.name) === normalizeName(pa.name);
      out.push({
        code: "package-renamed",
        level: "review",
        path: `${path}.package.name`,
        message: `Package name changed from "${pb.name}" to "${pa.name}" (${pa.ecosystem || pb.ecosystem}).${
          sameish ? " The names differ only in case or separators, which some registries treat as the same package." : ""
        }`,
        why: "The advisory now flags a different package. Correcting a typo is normal, but verify the new name exists in the registry, and that the severity, version ranges and references were left untouched by the edit.",
        before: pb.name,
        after: pa.name,
      });
    }
    if (pb.purl !== pa.purl) {
      out.push({
        code: "package-purl-changed",
        level: "review",
        path: `${path}.package.purl`,
        message: `Package purl ${pa.purl === undefined ? "was removed" : pb.purl === undefined ? "was added" : "changed"}: ${pb.purl ?? "(unset)"} -> ${pa.purl ?? "(unset)"}.`,
        why: "The purl is an alternative identifier of the affected package; it should stay consistent with its name.",
        ...(pb.purl !== undefined ? { before: pb.purl } : {}),
        ...(pa.purl !== undefined ? { after: pa.purl } : {}),
      });
    }
  } else if (pb && !pa) {
    out.push({
      code: "package-removed",
      level: "review",
      path: `${path}.package`,
      message: `The package identification (${pb.ecosystem}/${pb.name}) was removed from an affected entry.`,
      why: "An affected entry without a package no longer says which software is vulnerable.",
    });
  } else if (!pb && pa) {
    out.push({
      code: "package-added",
      level: "review",
      path: `${path}.package`,
      message: `Package ${pa.ecosystem}/${pa.name} was added to an affected entry that had none.`,
      why: "This changes which software the entry applies to.",
    });
  }

  diffSeverity(getOwn(b, "severity"), getOwn(a, "severity"), `${path}.severity`, ` (affected ${label})`, out);
  diffRanges(b, a, label, path, out, ctx);
  diffVersions(b, a, label, path, out);
  diffGeneric(remainder(b), remainder(a), path, out);
}

/**
 * Compare `affected[]`. Entries are matched by (ecosystem, name) so that reordering is
 * ignored and several entries/packages/ranges stay distinct. Unmatched leftovers in the
 * same ecosystem are paired as a rename (the "fix a typo in the package name" case) so
 * that the REST of the entry (severity, ranges, ...) is still compared.
 */
export function diffAffected(
  before: JsonValue | undefined,
  after: JsonValue | undefined,
  out: Finding[],
  maxMatchingWork: number = MAX_MATCHING_WORK,
): void {
  const bs = asObjectArray(before);
  const as = asObjectArray(after);
  const ctx: MatchContext = {
    budget: { remaining: maxMatchingWork },
    eventSet: memoized(eventTokens),
    entrySet: memoized(entryTokens),
    rangesSkipped: false,
  };
  const { budget, entrySet } = ctx;
  const entryWeight = matchWeight(entrySet);

  const step1 = pairItems(
    bs,
    as,
    (e) => canonical(e),
    (e) => canonical(e),
    (b, a) => (keyOf(b) === keyOf(a) && keyOf(b) !== "" ? 1000 + overlap(entrySet(b), entrySet(a)) : -1),
    { bucketB: keyOf, bucketA: keyOf, budget, weight: entryWeight },
  );

  let pairingSkipped = step1.skipped;
  const matched = [...step1.pairs];
  let restB = step1.restB;
  let restA = step1.restA;

  // Step 2: rename detection inside the same ecosystem.
  const ecoOf = (e: JsonObject): string => pkgOf(e)?.ecosystem ?? "";
  const groupByEco = (idx: number[], list: JsonObject[]): Map<string, number[]> => {
    const m = new Map<string, number[]>();
    for (const i of idx) {
      const k = ecoOf(list[i] as JsonObject);
      const g = m.get(k);
      if (g) g.push(i);
      else m.set(k, [i]);
    }
    return m;
  };
  const ecoB = groupByEco(restB, bs);
  const ecoA = groupByEco(restA, as);
  const ecosystems = [...ecoB.keys()].filter((k) => ecoA.has(k)).sort();
  const pairedB = new Set<number>();
  const pairedA = new Set<number>();
  for (const eco of ecosystems) {
    const gb = ecoB.get(eco) ?? [];
    const ga = ecoA.get(eco) ?? [];
    if (gb.length === 0 || ga.length === 0) continue;
    const sole = gb.length === 1 && ga.length === 1;
    const r = pairItems(
      gb.map((i) => bs[i] as JsonObject),
      ga.map((i) => as[i] as JsonObject),
      () => "\u0001b",
      () => "\u0001a",
      (b, a) => {
        const o = overlap(entrySet(b), entrySet(a));
        return o > 0 || sole ? o : -1;
      },
      { budget, weight: entryWeight, tieKeyB: canonical, tieKeyA: canonical },
    );
    pairingSkipped = pairingSkipped || r.skipped;
    for (const p of r.pairs) {
      matched.push({ bi: gb[p.bi] as number, ai: ga[p.ai] as number, exact: false });
    }
    for (const p of r.pairs) {
      pairedB.add(gb[p.bi] as number);
      pairedA.add(ga[p.ai] as number);
    }
  }
  restB = restB.filter((i) => !pairedB.has(i));
  restA = restA.filter((i) => !pairedA.has(i));

  // Step 3: a single unmatched entry on each side is treated as the same entry.
  if (restB.length === 1 && restA.length === 1) {
    matched.push({ bi: restB[0] as number, ai: restA[0] as number, exact: false });
    restB = [];
    restA = [];
  }

  // After step 3, so that the counts below match the entries that really are reported separately.
  if (pairingSkipped && (restB.length > 0 || restA.length > 0)) {
    out.push({
      code: "pairing-limit",
      level: "review",
      path: "affected",
      message: `Too many unmatched affected entries to search for renamed packages; the ${restB.length} removed and ${restA.length} added entries are reported separately.`,
      why: PAIRING_LIMIT_WHY,
    });
  }

  matched.sort((x, y) => x.bi - y.bi || x.ai - y.ai);
  const changed = matched.filter((m) => !m.exact);
  // All pairs share one budget, so spend it in content order: the order of the arrays must not decide
  // which entries fall back. Findings are still reported in array order.
  const spendOrder = changed
    .map((m) => ({ ...m, key: `${canonical(bs[m.bi])}\u0000${canonical(as[m.ai])}` }))
    .sort((x, y) => (x.key < y.key ? -1 : x.key > y.key ? 1 : 0));
  const reports = new Map<number, Finding[]>();
  for (const { bi, ai } of spendOrder) {
    const b = bs[bi];
    const a = as[ai];
    const report: Finding[] = [];
    if (b && a) diffPair(b, a, ai, report, ctx);
    reports.set(bi, report);
  }
  for (const { bi } of changed) {
    for (const f of reports.get(bi) ?? []) out.push(f);
  }

  if (ctx.rangesSkipped) {
    out.push({
      code: "pairing-limit",
      level: "review",
      path: "affected",
      message: "A matching limit was reached while pairing version ranges; some ranges are reported as removed and added instead of changed.",
      why: PAIRING_LIMIT_WHY,
    });
  }

  for (const bi of restB) {
    const e = bs[bi];
    if (!e) continue;
    const label = labelOf(e, bi);
    out.push({
      code: "package-removed",
      level: "review",
      path: `affected[${label}]`,
      message: `Affected entry for ${label} was removed (${previewList(entryTokens(e)) || "no versions listed"}).`,
      why: "Users of this package will stop being warned. Confirm the entry was removed on purpose and was not replaced by a mis-typed one.",
      before: canonical(e),
    });
  }
  for (const ai of restA) {
    const e = as[ai];
    if (!e) continue;
    const label = labelOf(e, ai);
    out.push({
      code: "package-added",
      level: "review",
      path: `affected[${label}]`,
      message: `Affected entry for ${label} was added (${previewList(entryTokens(e)) || "no versions listed"}).`,
      why: "This widens the set of packages the advisory applies to. Verify the package name and ecosystem exist.",
      after: canonical(e),
    });
  }
}

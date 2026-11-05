/**
 * Leading zeros in a version's numeric parts. This only reads spelling: AdvisoryGuard still does not
 * compare versions. A `v` prefix, pre-release and build are kept as written.
 */
const VERSION = /^(v?)([0-9]+(?:[.][0-9]+)*)([-+].*)?$/s;

export function withoutLeadingZeros(value: string): string {
  const m = VERSION.exec(value);
  if (!m) return value;
  const core = (m[2] as string)
    .split(".")
    .map((part) => part.replace(/^0+(?=[0-9])/, ""))
    .join(".");
  return `${m[1] ?? ""}${core}${m[3] ?? ""}`;
}

export function hasLeadingZero(value: string): boolean {
  return withoutLeadingZeros(value) !== value;
}

export function differsOnlyInLeadingZeros(a: string, b: string): boolean {
  return a !== b && withoutLeadingZeros(a) === withoutLeadingZeros(b);
}

/** npm versions are semantic versions, and a SEMVER range declares that it holds them. */
export function rejectsLeadingZeros(ecosystem: unknown, rangeType: unknown): boolean {
  if (rangeType === "GIT") return false;
  return rangeType === "SEMVER" || ecosystem === "npm";
}

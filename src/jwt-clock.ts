/** Read application time without allowing NaN or infinity to bypass claim comparisons. */
export function readJwtClock(clock?: () => number): number {
  const current = clock ? clock() : Math.floor(Date.now() / 1000);
  if (!Number.isFinite(current))
    throw new TypeError("JWT clock must return finite Unix time in seconds.");
  return current;
}

/** Drizzle wraps driver errors in DrizzleQueryError (original on `.cause`), so check both. */
export function pgErrorCode(err: unknown): string | undefined {
  const e = err as { code?: string; cause?: { code?: string } } | null;
  return e?.code ?? e?.cause?.code;
}

export const isUniqueViolation = (err: unknown) => pgErrorCode(err) === "23505";

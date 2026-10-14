import argon2 from "argon2";

// OWASP-recommended Argon2id parameters (19 MiB, t=2, p=1).
const options = { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 } as const;

export const hashPassword = (password: string) => argon2.hash(password, options);

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

let dummyHash: Promise<string> | undefined;
/**
 * Verify against a throwaway hash so "unknown email" costs the same time as "wrong password".
 * Prevents user enumeration through response timing.
 */
export async function burnPasswordCheck(password: string): Promise<void> {
  dummyHash ??= hashPassword("timing-equalizer-not-a-real-password");
  await verifyPassword(await dummyHash, password);
}

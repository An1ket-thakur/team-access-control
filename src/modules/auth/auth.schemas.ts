import { z } from "zod";

export const emailSchema = z.string().trim().toLowerCase().pipe(z.email().max(254));

// Length-based policy (NIST 800-63B): long enough to resist guessing, no arbitrary composition rules.
export const passwordSchema = z.string().min(10, "Password must be at least 10 characters").max(128);

export const signupBody = z.object({
  email: emailSchema,
  password: passwordSchema,
  name: z.string().trim().min(1).max(100),
});

export const loginBody = z.object({
  email: emailSchema,
  // Do not enforce the password policy at login: only verify.
  password: z.string().min(1).max(128),
});

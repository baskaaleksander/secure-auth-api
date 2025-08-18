import { z } from 'zod';

export const requestPasswordResetSchema = z.object({
  email: z.email().min(1, 'E-mail is required'),
});

export const resetPasswordSchema = z.object({
  newPassword: z
    .string()
    .min(8, 'Password must be at least 8 characters long')
    .refine((password) => /[a-z]/.test(password), {
      message: 'Password must contain at least one lowercase letter',
    })
    .refine((password) => /[A-Z]/.test(password), {
      message: 'Password must contain at least one uppercase letter',
    })
    .refine((password) => /\d/.test(password), {
      message: 'Password must contain at least one number',
    })
    .refine(
      (password) => /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password),
      {
        message: 'Password must contain at least one special character',
      },
    ),
});

export type RequestPasswordResetSchema = z.infer<
  typeof requestPasswordResetSchema
>;

export type ResetPasswordSchema = z.infer<typeof resetPasswordSchema>;

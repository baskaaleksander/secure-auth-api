import { z } from 'zod';

export const userAuthenticationSchema = z.object({
  email: z.email().min(1, 'E-mail is required'),
  password: z
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

export type UserAuthenticationSchema = z.infer<typeof userAuthenticationSchema>;

import config from '../../config/env';
import prismaClient from '../../config/prisma-client';
import { sendEmail } from '../../utils/send-email';
import { AppError } from '../../utils/types';
import { RequestPasswordResetSchema } from '../../validators/password-reset.validator';
import * as crypto from 'crypto';

export const requestPasswordReset = async (
  data: RequestPasswordResetSchema,
) => {
  const user = await prismaClient.user.findUnique({
    where: { email: data.email },
  });

  if (user) {
    const token = crypto.randomBytes(32).toString('hex');

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    try {
      await prismaClient.passwordReset.create({
        data: {
          userId: user.id,
          resetTokenHash: tokenHash,
          expiresAt: new Date(Date.now() + 60 * 60 * 1000),
        },
      });
    } catch {
      const err = new Error('Failed to create token') as AppError;
      err.statusCode = 500;

      throw err;
    }
    console.log(
      `${config.frontendUrl}/reset-password?token=${token}&id=${user.id}`,
    );

    sendEmail(
      user.email,
      'Password reset',
      'password-reset',
      `${config.frontendUrl}reset-password?token=${token}&id=${user.id}`,
    );
  }

  return { message: "If account exists, we'll send the email" };
};

export const resetPassword = async () => {};

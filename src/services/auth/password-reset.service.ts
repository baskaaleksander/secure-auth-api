import config from '../../config/env';
import prismaClient from '../../config/prisma-client';
import { sendEmail } from '../../utils/send-email';
import { AppError } from '../../utils/types';
import {
  RequestPasswordResetSchema,
  ResetPasswordSchema,
} from '../../validators/password-reset.validator';
import * as crypto from 'crypto';
import bcrypt from 'bcryptjs';

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

export const resetPassword = async (
  data: ResetPasswordSchema,
  query: { token: string; userId: string },
) => {
  const incomingTokenHash = crypto
    .createHash('sha256')
    .update(query.token)
    .digest('hex');

  const token = await prismaClient.passwordReset.findFirst({
    where: { resetTokenHash: incomingTokenHash, userId: query.userId },
  });

  if (!token) {
    const err = new Error('Reset token is not valid') as AppError;
    err.statusCode = 401;
    throw err;
  }

  if (token.userId !== query.userId) {
    const err = new Error('Reset token is not valid for that user') as AppError;
    err.statusCode = 401;
    throw err;
  }

  if (token.expiresAt < new Date()) {
    const err = new Error('Reset token expired') as AppError;
    err.statusCode = 401;
    throw err;
  }

  const updated = await prismaClient.passwordReset.updateMany({
    where: { id: token.id, usedAt: null },
    data: { usedAt: new Date() },
  });

  if (updated.count === 0) {
    const err = new Error('Reset token already used') as AppError;
    err.statusCode = 401;
    throw err;
  }

  const hashedPassword = bcrypt.hashSync(data.newPassword, 12);

  try {
    await prismaClient.user.update({
      where: { id: query.userId },
      data: { passwordHash: hashedPassword },
    });
  } catch {
    const err = new Error('Failed to updated password') as AppError;
    err.statusCode = 500;

    throw err;
  }

  return { message: 'Successfully updated password' };
};

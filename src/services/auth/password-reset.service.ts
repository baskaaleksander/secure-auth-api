import config from '../../config/env';
import prismaClient from '../../config/prisma-client';
import { sendEmail } from '../../utils/send-email';
import {
  AppError,
  ClientInformation,
  EventTypes,
  ResetPasswordQuery,
} from '../../utils/types';
import {
  RequestPasswordResetSchema,
  ResetPasswordSchema,
} from '../../validators/password-reset.validator';
import * as crypto from 'crypto';
import bcrypt from 'bcryptjs';
import logger from '../../utils/logger';

export const requestPasswordReset = async (
  data: RequestPasswordResetSchema,
  clientInformation: ClientInformation,
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

      await logger({
        userId: user.id,
        userAgent: clientInformation.userAgent,
        ipAddress: clientInformation.ip,
        eventType: EventTypes.PASSWORD_RESET_REQUEST,
        metadata: JSON.stringify({ message: 'Password reset requested' }),
      });
    } catch {
      const errorMessage = 'Failed to create token';
      const err = new Error(errorMessage) as AppError;
      err.statusCode = 500;

      await logger({
        userId: user.id,
        userAgent: clientInformation.userAgent,
        ipAddress: clientInformation.ip,
        eventType: EventTypes.PASSWORD_RESET_FAIL,
        metadata: JSON.stringify({
          message: errorMessage,
        }),
      });
      throw err;
    }

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
  query: ResetPasswordQuery,
  clientInformation: ClientInformation,
) => {
  const incomingTokenHash = crypto
    .createHash('sha256')
    .update(query.token)
    .digest('hex');

  const token = await prismaClient.passwordReset.findFirst({
    where: { resetTokenHash: incomingTokenHash, userId: query.userId },
  });

  if (!token) {
    const errorMessage = 'Reset token is not valid';
    const err = new Error(errorMessage) as AppError;
    err.statusCode = 401;

    await logger({
      userAgent: clientInformation.userAgent,
      ipAddress: clientInformation.ip,
      eventType: EventTypes.PASSWORD_RESET_FAIL,
      metadata: JSON.stringify({
        message: errorMessage,
      }),
    });

    throw err;
  }

  if (token.expiresAt < new Date()) {
    const errorMessage = 'Reset token expired';
    const err = new Error(errorMessage) as AppError;
    err.statusCode = 401;

    await logger({
      userId: query.userId,
      userAgent: clientInformation.userAgent,
      ipAddress: clientInformation.ip,
      eventType: EventTypes.PASSWORD_RESET_FAIL,
      metadata: JSON.stringify({
        message: errorMessage,
      }),
    });

    throw err;
  }

  const updated = await prismaClient.passwordReset.updateMany({
    where: { id: token.id, usedAt: null },
    data: { usedAt: new Date() },
  });

  if (updated.count === 0) {
    const errorMessage = 'Reset token already used';
    const err = new Error(errorMessage) as AppError;
    err.statusCode = 401;

    await logger({
      userId: query.userId,
      userAgent: clientInformation.userAgent,
      ipAddress: clientInformation.ip,
      eventType: EventTypes.PASSWORD_RESET_FAIL,
      metadata: JSON.stringify({
        message: errorMessage,
      }),
    });

    throw err;
  }

  const hashedPassword = bcrypt.hashSync(data.newPassword, 12);

  try {
    await prismaClient.user.update({
      where: { id: query.userId },
      data: { passwordHash: hashedPassword },
    });
  } catch {
    const errorMessage = 'Failed to updated password';
    const err = new Error(errorMessage) as AppError;
    err.statusCode = 500;

    await logger({
      userId: query.userId,
      userAgent: clientInformation.userAgent,
      ipAddress: clientInformation.ip,
      eventType: EventTypes.PASSWORD_RESET_FAIL,
      metadata: JSON.stringify({
        message: errorMessage,
      }),
    });

    throw err;
  }

  const message = 'Successfully updated password';
  await logger({
    userId: query.userId,
    userAgent: clientInformation.userAgent,
    ipAddress: clientInformation.ip,
    eventType: EventTypes.PASSWORD_RESET_SUCCESS,
    metadata: JSON.stringify({
      message,
    }),
  });
  return { message };
};

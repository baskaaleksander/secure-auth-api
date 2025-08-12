import prismaClient from '../config/prisma-client';
import { AppError, ClientInformation, EventTypes } from '../utils/types';
import jwt from 'jsonwebtoken';
import config from '../config/env';
import crypto from 'crypto';
import logger from '../utils/logger';

export const logout = async (
  refreshToken: string,
  clientInformation: ClientInformation,
) => {
  let payload: string | jwt.JwtPayload;

  try {
    payload = jwt.verify(refreshToken, config.jwtRefreshSecret);
  } catch {
    const errorMessage = 'Failed to verify your JWT token';
    await logger({
      userAgent: clientInformation.userAgent,
      ipAddress: clientInformation.ip,
      eventType: EventTypes.LOGOUT,
      metadata: JSON.stringify({ message: errorMessage }),
    });
    const err = new Error(errorMessage) as AppError;
    err.statusCode = 401;
    throw err;
  }

  const incomingHash = crypto
    .createHash('sha256')
    .update(refreshToken)
    .digest('hex');

  const tokenRecord = await prismaClient.refreshToken.findFirst({
    where: { tokenHash: incomingHash },
  });

  if (!tokenRecord || tokenRecord.revoked) {
    await logger({
      userId: payload.sub as string,
      userAgent: clientInformation.userAgent,
      ipAddress: clientInformation.ip,
      eventType: EventTypes.LOGOUT,
      metadata: JSON.stringify({ message: 'Token record not found' }),
    });

    return true;
  }

  try {
    const refreshToken = await prismaClient.refreshToken.update({
      where: { id: tokenRecord.id },
      data: {
        revoked: true,
        revokedAt: new Date(),
      },
    });
    await logger({
      userId: refreshToken.userId,
      userAgent: clientInformation.userAgent,
      ipAddress: clientInformation.ip,
      eventType: EventTypes.REFRESH_TOKEN_SUCCESS,
      metadata: JSON.stringify({
        message: 'Successfully revoked refresh token',
      }),
    });
  } catch {
    const errorMessage = 'Failed to update refresh token in DB';
    await logger({
      userId: payload.sub as string,
      userAgent: clientInformation.userAgent,
      ipAddress: clientInformation.ip,
      eventType: EventTypes.DB_ERROR,
      metadata: JSON.stringify({ message: errorMessage }),
    });
    const err = new Error(errorMessage) as AppError;
    err.statusCode = 500;

    throw err;
  }

  await logger({
    userId: payload.sub as string,
    userAgent: clientInformation.userAgent,
    ipAddress: clientInformation.ip,
    eventType: EventTypes.LOGOUT,
    metadata: JSON.stringify({ message: 'Successfully logged out user' }),
  });

  return true;
};

export const logoutAll = async (
  userId: string,
  clientInformation: ClientInformation,
) => {
  const allUserValidRefreshTokens = await prismaClient.refreshToken.findMany({
    where: { userId, revoked: false },
  });

  if (allUserValidRefreshTokens.length === 0) {
    const message = 'Logout completed. None of the tokens were valid';
    await logger({
      userId,
      userAgent: clientInformation.userAgent,
      ipAddress: clientInformation.ip,
      eventType: EventTypes.LOGOUT_ALL,
      metadata: JSON.stringify({ message }),
    });
    return { message };
  }

  let revokeTokensCount;

  try {
    const revokeTokens = await prismaClient.refreshToken.updateMany({
      where: { userId, revoked: false },
      data: { revoked: true, revokedAt: new Date() },
    });

    revokeTokensCount = revokeTokens.count;

    await logger({
      userId,
      userAgent: clientInformation.userAgent,
      ipAddress: clientInformation.ip,
      eventType: EventTypes.REFRESH_TOKEN_SUCCESS,
      metadata: JSON.stringify({
        message: 'Refresh tokens successfuly updated',
      }),
    });
  } catch {
    const errorMessage = 'Failed to update refresh tokens in DB';
    await logger({
      userId,
      userAgent: clientInformation.userAgent,
      ipAddress: clientInformation.ip,
      eventType: EventTypes.REFRESH_TOKEN_FAIL,
      metadata: JSON.stringify({
        message: errorMessage,
      }),
    });

    const err = new Error(errorMessage) as AppError;
    err.statusCode = 500;

    throw err;
  }

  return { message: `Logout completed. Revoked ${revokeTokensCount} tokens` };
};

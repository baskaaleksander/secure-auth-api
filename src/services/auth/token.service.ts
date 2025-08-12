import prismaClient from '../../config/prisma-client';
import { AppError, ClientInformation, EventTypes } from '../../utils/types';
import { v4 as uuidv4 } from 'uuid';
import jwt from 'jsonwebtoken';
import config from '../../config/env';
import crypto from 'crypto';
import logger from '../../utils/logger';

export const refreshToken = async (
  refreshToken: string,
  clientInformation: ClientInformation,
) => {
  const incomingHash = crypto
    .createHash('sha256')
    .update(refreshToken)
    .digest('hex');

  const refreshTokenInDB = await prismaClient.refreshToken.findFirst({
    where: {
      tokenHash: incomingHash,
      ipAddress: clientInformation.ip,
      userAgent: clientInformation.userAgent,
      revoked: false,
    },
  });

  if (!refreshTokenInDB) {
    const errorMessage = 'Invalid refresh token';
    await logger({
      userAgent: clientInformation.userAgent,
      ipAddress: clientInformation.ip,
      eventType: EventTypes.REFRESH_TOKEN_FAIL,
      metadata: JSON.stringify({ message: errorMessage }),
    });
    const err = new Error(errorMessage) as AppError;
    err.statusCode = 401;
    throw err;
  }

  let payload;

  try {
    payload = jwt.verify(refreshToken, config.jwtRefreshSecret);
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : 'Invalid refresh token';
    await logger({
      userAgent: clientInformation.userAgent,
      ipAddress: clientInformation.ip,
      eventType: EventTypes.REFRESH_TOKEN_FAIL,
      metadata: JSON.stringify({ message: errorMessage }),
    });
    const err = new Error(errorMessage) as AppError;
    err.statusCode = 401;
    throw err;
  }

  const userId = payload.sub as string;

  const user = await prismaClient.user.findUnique({ where: { id: userId } });

  if (!user) {
    const errorMessage = 'User not found';
    await logger({
      userAgent: clientInformation.userAgent,
      ipAddress: clientInformation.ip,
      eventType: EventTypes.REFRESH_TOKEN_FAIL,
      metadata: JSON.stringify({ message: errorMessage }),
    });

    const err = new Error(errorMessage) as AppError;
    err.statusCode = 404;
    throw err;
  }

  const jti = uuidv4();

  const generatedRefreshToken = jwt.sign(
    { sub: user.id, jti, type: 'refresh' },
    config.jwtRefreshSecret,
    { expiresIn: '7d' },
  );

  const accessToken = jwt.sign(
    { sub: user.id, type: 'access' },
    config.jwtSecret,
    {
      expiresIn: '15m',
    },
  );

  const tokenHash = crypto
    .createHash('sha256')
    .update(generatedRefreshToken)
    .digest('hex');

  let newRefreshToken;

  try {
    newRefreshToken = await prismaClient.refreshToken.create({
      data: {
        id: jti,
        userId: user.id,
        ipAddress: clientInformation.ip,
        userAgent: clientInformation.userAgent,
        tokenHash,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });
    await logger({
      userId: user.id,
      userAgent: clientInformation.userAgent,
      ipAddress: clientInformation.ip,
      eventType: EventTypes.REFRESH_TOKEN_SUCCESS,
      metadata: JSON.stringify({
        message: 'Refresh token successfully inserted to DB',
      }),
    });
  } catch {
    const errorMessage = 'Failed to insert refresh token to DB';
    await logger({
      userAgent: clientInformation.userAgent,
      ipAddress: clientInformation.ip,
      eventType: EventTypes.DB_ERROR,
      metadata: JSON.stringify({ message: errorMessage }),
    });

    const err = new Error(errorMessage) as AppError;
    err.statusCode = 500;
    throw err;
  }

  try {
    await prismaClient.refreshToken.update({
      where: { id: refreshTokenInDB.id },
      data: {
        revoked: true,
        revokedAt: new Date(),
        replacedById: newRefreshToken.id,
      },
    });
    await logger({
      userId: user.id,
      userAgent: clientInformation.userAgent,
      ipAddress: clientInformation.ip,
      eventType: EventTypes.REFRESH_TOKEN_SUCCESS,
      metadata: JSON.stringify({
        message: 'Refresh token successfully updated in DB',
      }),
    });
  } catch {
    const errorMessage = 'Failed to update refresh token in DB';
    await logger({
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
    userId,
    userAgent: clientInformation.userAgent,
    ipAddress: clientInformation.ip,
    eventType: EventTypes.REFRESH_TOKEN_SUCCESS,
    metadata: JSON.stringify({ message: 'Successfully refreshed token' }),
  });

  return { accessToken, refreshToken: generatedRefreshToken };
};

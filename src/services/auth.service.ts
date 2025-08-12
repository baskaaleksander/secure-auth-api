/* eslint-disable @typescript-eslint/no-unused-vars */
import { UserAuthenticationSchema } from '../validators/auth.validator';
import bcrypt from 'bcryptjs';
import prismaClient from '../config/prisma-client';
import { AppError, ClientInformation, EventTypes } from '../utils/types';
import { v4 as uuidv4 } from 'uuid';
import jwt from 'jsonwebtoken';
import config from '../config/env';
import crypto from 'crypto';
import logger from '../utils/logger';

export const registerUser = async (
  data: UserAuthenticationSchema,
  clientInformation: ClientInformation,
) => {
  const isUser = await prismaClient.user.findUnique({
    where: { email: data.email },
  });

  if (isUser) {
    const err = new Error('User with that email already exists') as AppError;
    err.statusCode = 409;
    throw err;
  }

  const hashedPassword = bcrypt.hashSync(data.password, 12);

  const createdUser = await prismaClient.user.create({
    data: {
      email: data.email,
      passwordHash: hashedPassword,
    },
  });

  const { passwordHash: _, ...userWithoutPassword } = createdUser;

  return userWithoutPassword;
};

export const loginUser = async (
  data: UserAuthenticationSchema,
  clientInformation: ClientInformation,
) => {
  const user = await prismaClient.user.findUnique({
    where: { email: data.email },
  });

  if (!user) {
    const errorMessage = 'User with that email does not exist';
    await logger({
      eventType: EventTypes.AUTH_FAILED,
      userAgent: clientInformation.userAgent,
      ipAddress: clientInformation.ip,
      metadata: JSON.stringify({ message: errorMessage }),
    });
    const err = new Error(errorMessage) as AppError;
    err.statusCode = 404;
    throw err;
  }

  const isValidPassword = bcrypt.compareSync(data.password, user.passwordHash);

  if (!isValidPassword) {
    const errorMessage = 'Incorrect password';
    await logger({
      userId: user.id,
      eventType: EventTypes.AUTH_FAILED,
      userAgent: clientInformation.userAgent,
      ipAddress: clientInformation.ip,
      metadata: JSON.stringify({ message: errorMessage }),
    });

    const err = new Error(errorMessage) as AppError;
    err.statusCode = 401;
    throw err;
  }

  const jti = uuidv4();

  const generatedRefreshToken = jwt.sign(
    { sub: user.id, jti, type: 'refresh' },
    config.jwtRefreshSecret,
    { expiresIn: '7d' },
  );

  const generatedAccessToken = jwt.sign(
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

  try {
    await prismaClient.refreshToken.create({
      data: {
        id: jti,
        userId: user.id,
        ipAddress: clientInformation.ip,
        userAgent: clientInformation.userAgent,
        tokenHash,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });
  } catch (error) {
    const errorMessage = 'Failed to create refresh token in DB';
    await logger({
      userId: user.id,
      eventType: EventTypes.DB_ERROR,
      userAgent: clientInformation.userAgent,
      ipAddress: clientInformation.ip,
      metadata: JSON.stringify({ message: errorMessage }),
    });

    const err = new Error(errorMessage) as AppError;
    err.statusCode = 500;
    throw err;
  }

  const { passwordHash: _, ...userWithoutPassword } = user;

  await logger({
    userId: user.id,
    eventType: EventTypes.AUTH_SUCCESS,
    userAgent: clientInformation.userAgent,
    ipAddress: clientInformation.ip,
    metadata: JSON.stringify({ message: 'Successfully logged in user' }),
  });

  return {
    accessToken: generatedAccessToken,
    refreshToken: generatedRefreshToken,
    user: userWithoutPassword,
  };
};

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
  } catch (error) {
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
  } catch (error) {
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

export const logout = async (
  refreshToken: string,
  clientInformation: ClientInformation,
) => {
  let payload: string | jwt.JwtPayload;

  try {
    payload = jwt.verify(refreshToken, config.jwtRefreshSecret);
  } catch (error) {
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
    await prismaClient.refreshToken.update({
      where: { id: tokenRecord.id },
      data: {
        revoked: true,
        revokedAt: new Date(),
      },
    });
  } catch (error) {
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

export const logoutAll = async (userId: string) => {
  const allUserValidRefreshTokens = await prismaClient.refreshToken.findMany({
    where: { userId, revoked: false },
  });

  if (allUserValidRefreshTokens.length === 0) {
    return { message: 'Logout completed. None of the tokens were valid' };
  }
  const revokeTokens = await prismaClient.refreshToken.updateMany({
    where: { userId, revoked: false },
    data: { revoked: true, revokedAt: new Date() },
  });

  return { message: `Logout completed. Revoked ${revokeTokens.count} tokens` };
};

/* eslint-disable @typescript-eslint/no-unused-vars */
import { UserAuthenticationSchema } from '../validators/auth.validator';
import bcrypt from 'bcryptjs';
import prismaClient from '../config/prisma-client';
import { AppError, ClientInformation } from '../utils/types';
import { v4 as uuidv4 } from 'uuid';
import jwt from 'jsonwebtoken';
import config from '../config/env';
import crypto from 'crypto';

export const registerUser = async (data: UserAuthenticationSchema) => {
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
    const err = new Error('User with that email does not exist') as AppError;
    err.statusCode = 404;
    throw err;
  }

  const isValidPassword = bcrypt.compareSync(data.password, user.passwordHash);

  if (!isValidPassword) {
    const err = new Error('Incorrect password') as AppError;
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

  const { passwordHash: _, ...userWithoutPassword } = user;

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
    const err = new Error('Invalid refresh token') as AppError;
    err.statusCode = 401;
    throw err;
  }

  let payload;

  try {
    payload = jwt.verify(refreshToken, config.jwtRefreshSecret);
  } catch (error) {
    const err = new Error(error.message || 'Invalid refresh token') as AppError;
    err.statusCode = 401;
    throw err;
  }

  const userId = payload.sub as string;

  const user = await prismaClient.user.findUnique({ where: { id: userId } });

  if (!user) {
    const err = new Error('User not found') as AppError;
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

  const newRefreshToken = await prismaClient.refreshToken.create({
    data: {
      id: jti,
      userId: user.id,
      ipAddress: clientInformation.ip,
      userAgent: clientInformation.userAgent,
      tokenHash,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    },
  });

  await prismaClient.refreshToken.update({
    where: { id: refreshTokenInDB.id },
    data: {
      revoked: true,
      revokedAt: new Date(),
      replacedById: newRefreshToken.id,
    },
  });

  return { accessToken, refreshToken: generatedRefreshToken };
};

export const logout = async (refreshToken: string) => {
  let payload: string | jwt.JwtPayload;

  try {
    payload = jwt.verify(refreshToken, config.jwtRefreshSecret);
  } catch {
    return true;
  }

  const incomingHash = crypto
    .createHash('sha256')
    .update(refreshToken)
    .digest('hex');

  const tokenRecord = await prismaClient.refreshToken.findFirst({
    where: { tokenHash: incomingHash },
  });

  if (!tokenRecord || tokenRecord.revoked) {
    return true;
  }

  await prismaClient.refreshToken.update({
    where: { id: tokenRecord.id },
    data: {
      revoked: true,
      revokedAt: new Date(),
    },
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

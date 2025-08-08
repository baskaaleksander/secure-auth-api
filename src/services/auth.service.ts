import { UserAuthenticationSchema } from '../validators/auth.validator';
import bcrypt from 'bcryptjs';
import prismaClient from '../config/prisma-client';
import { AppError } from '../utils/types';
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

  const { passwordHash, ...userWithoutPassword } = createdUser;

  return userWithoutPassword;
};

export const loginUser = async (
  data: UserAuthenticationSchema,
  userAgent: string,
  ip: string,
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
      ipAddress: ip,
      userAgent,
      tokenHash,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    },
  });

  const { passwordHash, ...userWithoutPassword } = user;

  return {
    accessToken: generatedAccessToken,
    refreshToken: generatedRefreshToken,
    user: userWithoutPassword,
  };
};

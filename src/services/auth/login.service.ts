import { UserAuthenticationSchema } from '../../validators/auth.validator';
import bcrypt from 'bcryptjs';
import prismaClient from '../../config/prisma-client';
import { AppError, ClientInformation, EventTypes } from '../../utils/types';
import { v4 as uuidv4 } from 'uuid';
import jwt from 'jsonwebtoken';
import config from '../../config/env';
import crypto from 'crypto';
import logger from '../../utils/logger';

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

  /* eslint-disable @typescript-eslint/no-unused-vars */
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

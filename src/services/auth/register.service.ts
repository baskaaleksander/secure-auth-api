import prismaClient from '../../config/prisma-client';
import logger from '../../utils/logger';
import { AppError, ClientInformation, EventTypes } from '../../utils/types';
import { UserAuthenticationSchema } from '../../validators/auth.validator';
import bcrypt from 'bcryptjs';

export const registerUser = async (
  data: UserAuthenticationSchema,
  clientInformation: ClientInformation,
) => {
  const isUser = await prismaClient.user.findUnique({
    where: { email: data.email },
  });

  if (isUser) {
    const errorMessage = 'User with that email already exists';
    await logger({
      userAgent: clientInformation.userAgent,
      ipAddress: clientInformation.ip,
      eventType: EventTypes.AUTH_FAILED,
      metadata: JSON.stringify({ message: errorMessage }),
    });
    const err = new Error(errorMessage) as AppError;
    err.statusCode = 409;
    throw err;
  }

  const hashedPassword = bcrypt.hashSync(data.password, 12);

  let createdUser;
  try {
    createdUser = await prismaClient.user.create({
      data: {
        email: data.email,
        passwordHash: hashedPassword,
      },
    });
  } catch {
    const errorMessage = 'Failed to create user';
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

  /* eslint-disable @typescript-eslint/no-unused-vars */
  const { passwordHash: _, ...userWithoutPassword } = createdUser;

  await logger({
    userId: createdUser.id,
    userAgent: clientInformation.userAgent,
    ipAddress: clientInformation.ip,
    eventType: EventTypes.AUTH_SUCCESS,
    metadata: JSON.stringify({ message: 'User created successfully' }),
  });

  return userWithoutPassword;
};

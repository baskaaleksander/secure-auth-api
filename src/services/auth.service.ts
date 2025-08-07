import { UserAuthenticationSchema } from '../validators/auth.validator';
import bcrypt from 'bcryptjs';
import prismaClient from '../config/prisma-client';
import { AppError } from '../utils/types';

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

export const loginUser = async (data: UserAuthenticationSchema) => {
  const user = await prismaClient.user.findUnique({
    where: { email: data.email },
  });

  if (!user) {
    const err = new Error('User with that email does not exist') as AppError;
    err.statusCode = 404;
    throw err;
  }

  const isValidPassword = bcrypt.compareSync(data.password, user.passwordHash);

  console.log(isValidPassword);

  if (!isValidPassword) {
    const err = new Error('Incorrect password') as AppError;
    err.statusCode = 409;
    throw err;
  }

  const { passwordHash, ...userWithoutPassword } = user;

  return userWithoutPassword;
};

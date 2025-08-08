import { NextFunction, Request, Response } from 'express';
import * as authService from '../services/auth.service';
import { AppError, ClientInformation } from '../utils/types';

export const registerUser = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const data = req.body;

    const registerResponse = await authService.registerUser(data);

    res.status(201).json(registerResponse);
  } catch (error) {
    next(error);
  }
};

export const loginUser = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const data = req.body;
    const userAgent = req.headers['user-agent'];
    const ip = req.ip;

    if (!userAgent || !ip) {
      const err = new Error('None of client information found') as AppError;
      err.statusCode = 404;
      throw err;
    }

    const clientInformation: ClientInformation = {
      userAgent,
      ip,
    };

    const loginResponse = await authService.loginUser(data, clientInformation);

    const { refreshToken, ...loginResponseWithoutRefresh } = loginResponse;

    res.cookie('refresh', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json(loginResponseWithoutRefresh);
  } catch (error) {
    next(error);
  }
};

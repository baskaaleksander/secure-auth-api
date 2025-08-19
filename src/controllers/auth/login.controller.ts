import { NextFunction, Request, Response } from 'express';
import { ClientInformation } from '../../utils/types';
import * as loginService from '../../services/auth/login.service';

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
      return res.status(400).json({ message: 'Invalid request' });
    }

    const clientInformation: ClientInformation = {
      userAgent,
      ip,
    };

    const loginResponse = await loginService.loginUser(data, clientInformation);

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

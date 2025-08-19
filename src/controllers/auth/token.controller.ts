import { NextFunction, Request, Response } from 'express';
import { ClientInformation } from '../../utils/types';
import * as tokenService from '../../services/auth/token.service';

export const refreshToken = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const refreshToken = req.cookies.refresh;

    if (!refreshToken) {
      return res.status(401).json({ message: 'Missing refresh token' });
    }

    const userAgent = req.headers['user-agent'];
    const ip = req.ip;

    if (!userAgent || !ip) {
      return res.status(400).json({ message: 'Invalid request' });
    }

    const clientInformation: ClientInformation = {
      userAgent,
      ip,
    };

    const newTokens = await tokenService.refreshToken(
      refreshToken,
      clientInformation,
    );

    res.clearCookie('refresh', {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
    });

    res.cookie('refresh', newTokens.refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({ accessToken: newTokens.accessToken });
  } catch (error) {
    next(error);
  }
};

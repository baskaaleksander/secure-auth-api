import { NextFunction, Request, Response } from 'express';
import { ClientInformation } from '../../utils/types';
import * as logoutService from '../../services/auth/logout.service';
import jwt from 'jsonwebtoken';

export const logout = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const refreshToken = req.cookies.refresh;
    const userAgent = req.headers['user-agent'];
    const ip = req.ip;

    if (!userAgent || !ip) {
      return res.status(400).json({ message: 'Invalid request' });
    }

    const clientInformation: ClientInformation = {
      userAgent,
      ip,
    };

    if (!refreshToken) {
      return res.status(400).json({ message: 'No refresh token provided' });
    }

    await logoutService.logout(refreshToken, clientInformation);

    res.clearCookie('refresh', {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
    });

    return res.status(200).json({ message: 'Logged out successfully' });
  } catch (error) {
    next(error);
  }
};

export const logoutAll = async (
  req: Request & { user?: string | jwt.JwtPayload },
  res: Response,
  next: NextFunction,
) => {
  try {
    const refreshToken = req.cookies.refresh;
    const userId = req.user?.sub;
    const userAgent = req.headers['user-agent'];
    const ip = req.ip;

    if (!userAgent || !ip) {
      return res.status(400).json({ message: 'Invalid request' });
    }

    const clientInformation: ClientInformation = {
      userAgent,
      ip,
    };

    if (!refreshToken) {
      return res.status(400).json({ message: 'No refresh token provided' });
    }

    if (!userId || typeof userId !== 'string') {
      return res.status(400).json({ message: 'Invalid user ID' });
    }
    const logoutResponse = await logoutService.logoutAll(
      userId,
      clientInformation,
    );

    res.clearCookie('refresh', {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
    });

    return res.status(200).json(logoutResponse);
  } catch (error) {
    next(error);
  }
};

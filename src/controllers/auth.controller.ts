import { NextFunction, Request, Response } from 'express';
import * as authService from '../services/auth.service';
import { ClientInformation } from '../utils/types';
import jwt from 'jsonwebtoken';

export const registerUser = async (
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

    const registerResponse = await authService.registerUser(
      data,
      clientInformation,
    );

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
      return res.status(400).json({ message: 'Invalid request' });
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

    const newTokens = await authService.refreshToken(
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

    await authService.logout(refreshToken, clientInformation);

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
    const logoutResponse = await authService.logoutAll(
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

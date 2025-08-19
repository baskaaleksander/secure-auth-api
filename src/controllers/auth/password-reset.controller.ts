import { NextFunction, Request, Response } from 'express';
import { ClientInformation } from '../../utils/types';
import * as passwordResetService from '../../services/auth/password-reset.service';

export const requestPasswordReset = async (
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

    const requestPasswordReset =
      await passwordResetService.requestPasswordReset(data, clientInformation);

    return res.status(200).json(requestPasswordReset);
  } catch (error) {
    next(error);
  }
};

export const resetPassword = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const query = req.query as { token: string; userId: string };
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

    if (!query.token || !query.userId) {
      return res
        .status(401)
        .json({ message: 'Enter valid token and userId values into URL' });
    }

    const resetPasswordResponse = await passwordResetService.resetPassword(
      data,
      query,
      clientInformation,
    );

    return res.status(200).json(resetPasswordResponse);
  } catch (error) {
    next(error);
  }
};

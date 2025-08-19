import { NextFunction, Request, Response } from 'express';
import { ClientInformation } from '../../utils/types';
import * as registerService from '../../services/auth/register.service';

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

    const registerResponse = await registerService.registerUser(
      data,
      clientInformation,
    );

    res.status(201).json(registerResponse);
  } catch (error) {
    next(error);
  }
};

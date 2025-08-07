import { NextFunction, Request, Response } from 'express';
import * as authService from '../services/auth.service';

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

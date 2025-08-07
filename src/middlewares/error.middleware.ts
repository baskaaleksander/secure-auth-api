import { AppError } from '../utils/types';
import { Request, Response } from 'express';

export const errorMiddleware = (err: AppError, req: Request, res: Response) => {
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Internal Server Error';

  res.status(statusCode).json({
    status: 'error',
    statusCode,
    message,
  });
};

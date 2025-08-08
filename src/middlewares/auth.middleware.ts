import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import config from '../config/env';

export const authMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const headers = req.headers;
  const token = headers['authorization']?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Missing JWT Token' });
  }

  jwt.verify(token, config.jwtSecret, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid JWT Token' });
    }

    (req as Request & { user?: string | jwt.JwtPayload }).user = user;
    next();
  });
};

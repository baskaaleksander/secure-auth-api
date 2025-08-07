import { NextFunction, Request, Response } from 'express';
import { z } from 'zod';

export const validate =
  (schema: z.Schema) => (req: Request, res: Response, next: NextFunction) => {
    const result = schema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json(z.treeifyError(result.error));
    }
    req.body = result.data;
    next();
  };

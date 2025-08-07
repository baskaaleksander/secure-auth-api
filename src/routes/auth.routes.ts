import express from 'express';
import * as authController from '../controllers/auth.controller';
import { validate } from '../middlewares/validate.middleware';
import { userAuthenticationSchema } from '../validators/auth.validator';
const router = express.Router();

router.post(
  '/register',
  validate(userAuthenticationSchema),
  authController.registerUser,
);
router.post(
  '/login',
  validate(userAuthenticationSchema),
  authController.loginUser,
);

export default router;

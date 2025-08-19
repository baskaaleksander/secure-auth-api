import express from 'express';
import * as loginController from '../controllers/auth/login.controller';
import * as logoutController from '../controllers/auth/logout.controller';
import * as passwordResetController from '../controllers/auth/password-reset.controller';
import * as registerController from '../controllers/auth/register.controller';
import * as tokenController from '../controllers/auth/token.controller';
import { validate } from '../middlewares/validate.middleware';
import { userAuthenticationSchema } from '../validators/auth.validator';
import { authMiddleware } from '../middlewares/auth.middleware';
import {
  authLimiter,
  passwordResetLimiter,
  refreshTokenLimiter,
} from '../utils/limiters';
import {
  requestPasswordResetSchema,
  resetPasswordSchema,
} from '../validators/password-reset.validator';
const router = express.Router();

router.post(
  '/register',
  authLimiter,
  validate(userAuthenticationSchema),
  registerController.registerUser,
);
router.post(
  '/login',
  authLimiter,
  validate(userAuthenticationSchema),
  loginController.loginUser,
);

router.post('/refresh', refreshTokenLimiter, tokenController.refreshToken);

router.post('/logout', authLimiter, authMiddleware, logoutController.logout);

router.post(
  '/logout-all',
  authLimiter,
  authMiddleware,
  logoutController.logoutAll,
);

router.post(
  '/request-password-reset',
  passwordResetLimiter,
  validate(requestPasswordResetSchema),
  passwordResetController.requestPasswordReset,
);

router.post(
  '/reset-password',
  validate(resetPasswordSchema),
  passwordResetController.resetPassword,
);
export default router;

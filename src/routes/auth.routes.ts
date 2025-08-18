import express from 'express';
import * as authController from '../controllers/auth.controller';
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
  authController.registerUser,
);
router.post(
  '/login',
  authLimiter,
  validate(userAuthenticationSchema),
  authController.loginUser,
);

router.post('/refresh', refreshTokenLimiter, authController.refreshToken);

router.post('/logout', authLimiter, authMiddleware, authController.logout);

router.post(
  '/logout-all',
  authLimiter,
  authMiddleware,
  authController.logoutAll,
);

router.post(
  '/request-password-reset',
  passwordResetLimiter,
  validate(requestPasswordResetSchema),
  authController.requestPasswordReset,
);

router.post(
  '/reset-password',
  validate(resetPasswordSchema),
  authController.resetPassword,
);
export default router;

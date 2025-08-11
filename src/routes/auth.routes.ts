import express from 'express';
import * as authController from '../controllers/auth.controller';
import { validate } from '../middlewares/validate.middleware';
import { userAuthenticationSchema } from '../validators/auth.validator';
import { authMiddleware } from '../middlewares/auth.middleware';
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

router.post('/refresh', authController.refreshToken);

router.post('/logout', authMiddleware, authController.logout);

router.post('/logout-all', authMiddleware, authController.logoutAll);
export default router;

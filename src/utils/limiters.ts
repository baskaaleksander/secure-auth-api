import rateLimit from 'express-rate-limit';
import RedisStore, { RedisReply } from 'rate-limit-redis';
import { redisClient } from '../config/redis';

export const authLimiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args: string[]) =>
      redisClient.call(...args) as Promise<RedisReply>,
  }),
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many authentication attempts. Please wait a bit.',
});

export const passwordResetLimiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args: string[]) =>
      redisClient.call(...args) as Promise<RedisReply>,
  }),
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: 'Too many password reset attempts. Please wait a bit',
});

export const refreshTokenLimiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args: string[]) =>
      redisClient.call(...args) as Promise<RedisReply>,
  }),
  windowMs: 60 * 60 * 1000,
  max: 20,
  message: 'Too many token refresh requests. Please wait a bit',
});

export const globalLimiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args: string[]) =>
      redisClient.call(...args) as Promise<RedisReply>,
  }),
  windowMs: 60 * 60 * 1000,
  max: 500,
  message: 'Too many password reset attempts. Please wait a bit',
});

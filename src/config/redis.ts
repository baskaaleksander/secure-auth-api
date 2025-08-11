import Redis from 'ioredis';
import config from './env';

export const redisClient = new Redis(config.redisUrl);

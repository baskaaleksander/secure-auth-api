import dotenv from 'dotenv';

dotenv.config();

interface Config {
  jwtSecret: string;
  jwtRefreshSecret: string;
  port: number;
  nodeEnv: string;
  redisUrl: string;
  frontendUrl: string;
}

if (!process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET is required! Define it in .env file');
}
if (!process.env.JWT_REFRESH_SECRET) {
  throw new Error('JWT_REFRESH_SECRET is required! Define it in .env file');
}

if (!process.env.REDIS_URL) {
  throw new Error('REDIS_URL is required! Define it in .env file');
}

if (!process.env.FRONTEND_URL) {
  throw new Error('FRONTEND_URL is required! Define it in .env file');
}

const config: Config = {
  jwtSecret: process.env.JWT_SECRET,
  jwtRefreshSecret: process.env.JWT_REFRESH_SECRET,
  port: Number(process.env.PORT) || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  redisUrl: process.env.REDIS_URL,
  frontendUrl: process.env.FRONTEND_URL,
};

export default config;

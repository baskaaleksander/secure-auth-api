import dotenv from 'dotenv';

dotenv.config();

interface Config {
  jwtSecret: string;
  jwtRefreshSecret: string;
  port: number;
  nodeEnv: string;
}

const config: Config = {
  jwtSecret: process.env.JWT_SECRET || 'yoursecuretoken',
  jwtRefreshSecret: process.env.JWT_SECRET || 'yoursecuretoken',
  port: Number(process.env.PORT) || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
};

export default config;

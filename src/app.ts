import express, { Request, Response } from 'express';
import cookieParser from 'cookie-parser';
import routes from './routes/index';
import { errorMiddleware } from './middlewares/error.middleware';
import helmet from 'helmet';
import config from './config/env';

const app = express();

app.use(
  helmet({
    contentSecurityPolicy: false,
    hsts:
      config.nodeEnv === 'production'
        ? {
            maxAge: 31536000,
            includeSubDomains: true,
            preload: true,
          }
        : false,
    frameguard: { action: 'deny' },
    referrerPolicy: { policy: 'no-referrer' },
    noSniff: true,
    dnsPrefetchControl: true,
    ieNoOpen: true,
    originAgentCluster: true,
    permittedCrossDomainPolicies: false,
  }),
);

app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

app.use('/api', routes);

app.use('/', (req: Request, res: Response) => {
  res.json({ message: 'Secure Auth API is running!' });
});

app.use(errorMiddleware);

export default app;

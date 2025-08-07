import express, { Request, Response } from 'express';
import cookieParser from 'cookie-parser';
import routes from './routes/index';
import { errorMiddleware } from './middlewares/error.middleware';

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use('/api', routes);

app.use('/', (req: Request, res: Response) => {
  res.send('app is running!');
});

app.use(errorMiddleware);

export default app;

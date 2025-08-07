import express, { Request, Response } from 'express';
import cookieParser from 'cookie-parser';
import routes from './routes/index';

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use('/api', routes);

app.use('/', (req: Request, res: Response) => {
  res.send('app is running!');
});

export default app;

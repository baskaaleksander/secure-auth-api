import express from 'express';
import cookieParser from 'cookie-parser';
import prismaClient from './prisma-client';

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use('/', (req, res) => {
  res.send('app is running!');
});

export default app;

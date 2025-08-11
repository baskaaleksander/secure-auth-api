import prismaClient from '../config/prisma-client';
import { LogDataInterface } from './types';

async function logger(logData: LogDataInterface) {
  await prismaClient.auditLog.create({ data: logData });
}

export default logger;

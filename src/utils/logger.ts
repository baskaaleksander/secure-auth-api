import prismaClient from '../config/prisma-client';
import { LogDataInterface } from './types';
async function logger(logData: LogDataInterface) {
  try {
    await prismaClient.auditLog.create({
      data: { ...logData },
    });
  } catch (error) {
    console.error('Failed to write audit log:', error);
  }
}

export default logger;

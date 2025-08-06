import { PrismaClient } from '../src/generated/prisma';

declare global {
  // eslint-disable-next-line no-var
  var __prismaClient: PrismaClient | undefined;
}

const createPrismaClient = (): PrismaClient => {
  return new PrismaClient({
    log:
      process.env.NODE_ENV === 'development'
        ? ['query', 'error', 'warn']
        : ['error'],
    errorFormat: 'minimal',
  });
};

const prismaClient = globalThis.__prismaClient ?? createPrismaClient();

if (process.env.NODE_ENV === 'development') {
  globalThis.__prismaClient = prismaClient;
}

const gracefulShutdown = async () => {
  await prismaClient.$disconnect();
  process.exit(0);
};

process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);

export default prismaClient;

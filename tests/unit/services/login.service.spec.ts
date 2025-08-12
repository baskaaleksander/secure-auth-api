import { loginUser } from '../../../src/services/auth/login.service';
import { UserAuthenticationSchema } from '../../../src/validators/auth.validator';
import { ClientInformation, EventTypes } from '../../../src/utils/types';

jest.mock('../../../src/config/prisma-client', () => ({
  __esModule: true,
  default: {
    user: {
      findUnique: jest.fn(),
    },
    refreshToken: {
      create: jest.fn(),
    },
  },
}));

jest.mock('../../../src/utils/logger', () => jest.fn());

jest.mock('../../../src/config/env', () => ({
  jwtSecret: 'test-jwt-secret',
  jwtRefreshSecret: 'test-refresh-secret',
  port: 3000,
  nodeEnv: 'test',
  redisUrl: 'redis://localhost:6379',
  frontendUrl: 'http://localhost:3000',
}));

jest.mock('bcryptjs', () => ({
  compareSync: jest.fn(),
}));

jest.mock('jsonwebtoken', () => ({
  sign: jest.fn(),
}));

jest.mock('crypto', () => ({
  createHash: jest.fn(),
}));

jest.mock('uuid', () => ({
  v4: jest.fn(),
}));

import prismaClient from '../../../src/config/prisma-client';
import logger from '../../../src/utils/logger';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';

const mockFindUnique = prismaClient.user.findUnique as jest.MockedFunction<
  typeof prismaClient.user.findUnique
>;
const mockCreate = prismaClient.refreshToken.create as jest.MockedFunction<
  typeof prismaClient.refreshToken.create
>;
const mockLogger = logger as jest.MockedFunction<typeof logger>;
const mockCompareSync = bcrypt.compareSync as jest.MockedFunction<
  typeof bcrypt.compareSync
>;
const mockJwtSign = jwt.sign as jest.MockedFunction<typeof jwt.sign>;
const mockCreateHash = crypto.createHash as jest.MockedFunction<
  typeof crypto.createHash
>;
const mockUuidv4 = uuidv4 as jest.MockedFunction<typeof uuidv4>;

const mockUser = {
  id: 'user-123',
  email: 'test@example.com',
  passwordHash: '$2a$10$hashedpassword',
  isActive: true,
  createdAt: new Date('2024-01-01T00:00:00Z'),
  updatedAt: new Date('2024-01-01T00:00:00Z'),
  lastLoginAt: null,
};

const mockClientInfo: ClientInformation = {
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
  ip: '192.168.1.1',
};

const mockAuthData: UserAuthenticationSchema = {
  email: 'test@example.com',
  password: 'Password123!',
};

const mockRefreshToken = {
  id: 'mock-jti-123',
  userId: mockUser.id,
  tokenHash: 'mock-token-hash',
  ipAddress: mockClientInfo.ip,
  userAgent: mockClientInfo.userAgent,
  createdAt: new Date(),
  expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  revoked: false,
  revokedAt: null,
  replacedById: null,
};

describe('loginUser', () => {
  beforeEach(() => {
    jest.clearAllMocks();

    (mockUuidv4 as jest.Mock).mockReturnValue('mock-jti-123');
    (mockJwtSign as jest.Mock).mockImplementation(
      (payload: Record<string, unknown>) => {
        if (payload.type === 'refresh') return 'mock-refresh-token';
        return 'mock-access-token';
      },
    );

    const mockHashInstance = {
      update: jest.fn().mockReturnThis(),
      digest: jest.fn().mockReturnValue('mock-token-hash'),
    };
    (mockCreateHash as jest.Mock).mockReturnValue(
      mockHashInstance as unknown as crypto.Hash,
    );
  });

  describe('Successful login scenarios', () => {
    it('should successfully login user with valid credentials', async () => {
      mockFindUnique.mockResolvedValue(mockUser);
      mockCompareSync.mockReturnValue(true);
      mockCreate.mockResolvedValue(mockRefreshToken);

      const result = await loginUser(mockAuthData, mockClientInfo);

      expect(result).toEqual({
        accessToken: 'mock-access-token',
        refreshToken: 'mock-refresh-token',
        user: {
          id: mockUser.id,
          email: mockUser.email,
          isActive: mockUser.isActive,
          createdAt: mockUser.createdAt,
          updatedAt: mockUser.updatedAt,
          lastLoginAt: mockUser.lastLoginAt,
        },
      });

      expect(mockFindUnique).toHaveBeenCalledWith({
        where: { email: mockAuthData.email },
      });
      expect(mockCompareSync).toHaveBeenCalledWith(
        mockAuthData.password,
        mockUser.passwordHash,
      );
      expect(mockJwtSign).toHaveBeenCalledTimes(2);
      expect(mockCreate).toHaveBeenCalled();
    });

    it('should generate proper JWT tokens with correct payload and expiration', async () => {
      mockFindUnique.mockResolvedValue(mockUser);
      mockCompareSync.mockReturnValue(true);
      mockCreate.mockResolvedValue(mockRefreshToken);

      await loginUser(mockAuthData, mockClientInfo);

      expect(mockJwtSign).toHaveBeenCalledWith(
        { sub: mockUser.id, jti: 'mock-jti-123', type: 'refresh' },
        'test-refresh-secret',
        { expiresIn: '7d' },
      );
      expect(mockJwtSign).toHaveBeenCalledWith(
        { sub: mockUser.id, type: 'access' },
        'test-jwt-secret',
        { expiresIn: '15m' },
      );
    });

    it('should create refresh token with proper hash and expiration', async () => {
      mockFindUnique.mockResolvedValue(mockUser);
      mockCompareSync.mockReturnValue(true);
      mockCreate.mockResolvedValue(mockRefreshToken);

      await loginUser(mockAuthData, mockClientInfo);

      expect(mockCreateHash).toHaveBeenCalledWith('sha256');
      expect(mockCreate).toHaveBeenCalledWith({
        data: {
          id: 'mock-jti-123',
          userId: mockUser.id,
          ipAddress: mockClientInfo.ip,
          userAgent: mockClientInfo.userAgent,
          tokenHash: 'mock-token-hash',
          expiresAt: expect.any(Date),
        },
      });
    });

    it('should exclude password hash from returned user object', async () => {
      mockFindUnique.mockResolvedValue(mockUser);
      mockCompareSync.mockReturnValue(true);
      mockCreate.mockResolvedValue(mockRefreshToken);

      const result = await loginUser(mockAuthData, mockClientInfo);

      expect(result.user).not.toHaveProperty('passwordHash');
      expect(result.user).toEqual({
        id: mockUser.id,
        email: mockUser.email,
        isActive: mockUser.isActive,
        createdAt: mockUser.createdAt,
        updatedAt: mockUser.updatedAt,
        lastLoginAt: mockUser.lastLoginAt,
      });
    });
  });

  describe('Authentication failure scenarios', () => {
    it('should throw 404 error when user does not exist', async () => {
      mockFindUnique.mockResolvedValue(null);

      await expect(
        loginUser(mockAuthData, mockClientInfo),
      ).rejects.toMatchObject({
        message: 'User with that email does not exist',
        statusCode: 404,
      });

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: EventTypes.AUTH_FAILED,
          userAgent: mockClientInfo.userAgent,
          ipAddress: mockClientInfo.ip,
          metadata: JSON.stringify({
            message: 'User with that email does not exist',
          }),
        }),
      );
    });

    it('should throw 401 error when password is incorrect', async () => {
      mockFindUnique.mockResolvedValue(mockUser);
      mockCompareSync.mockReturnValue(false);

      await expect(
        loginUser(mockAuthData, mockClientInfo),
      ).rejects.toMatchObject({
        message: 'Incorrect password',
        statusCode: 401,
      });

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockUser.id,
          eventType: EventTypes.AUTH_FAILED,
          userAgent: mockClientInfo.userAgent,
          ipAddress: mockClientInfo.ip,
          metadata: JSON.stringify({ message: 'Incorrect password' }),
        }),
      );
    });

    it('should not call refresh token creation when password is wrong', async () => {
      mockFindUnique.mockResolvedValue(mockUser);
      mockCompareSync.mockReturnValue(false);

      await expect(loginUser(mockAuthData, mockClientInfo)).rejects.toThrow();
      expect(mockCreate).not.toHaveBeenCalled();
      expect(mockJwtSign).not.toHaveBeenCalled();
    });

    it('should not call refresh token creation when user does not exist', async () => {
      mockFindUnique.mockResolvedValue(null);

      await expect(loginUser(mockAuthData, mockClientInfo)).rejects.toThrow();
      expect(mockCreate).not.toHaveBeenCalled();
      expect(mockJwtSign).not.toHaveBeenCalled();
    });
  });

  describe('Database error scenarios', () => {
    it('should throw 500 error when refresh token creation fails', async () => {
      mockFindUnique.mockResolvedValue(mockUser);
      mockCompareSync.mockReturnValue(true);
      mockCreate.mockRejectedValue(new Error('Database error'));

      await expect(
        loginUser(mockAuthData, mockClientInfo),
      ).rejects.toMatchObject({
        message: 'Failed to create refresh token in DB',
        statusCode: 500,
      });

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockUser.id,
          eventType: EventTypes.DB_ERROR,
          userAgent: mockClientInfo.userAgent,
          ipAddress: mockClientInfo.ip,
          metadata: JSON.stringify({
            message: 'Failed to create refresh token in DB',
          }),
        }),
      );
    });

    it('should handle user lookup database errors', async () => {
      mockFindUnique.mockRejectedValue(new Error('Database connection error'));

      await expect(loginUser(mockAuthData, mockClientInfo)).rejects.toThrow(
        'Database connection error',
      );
    });

    it('should generate unique JTI for each login attempt', async () => {
      mockFindUnique.mockResolvedValue(mockUser);
      mockCompareSync.mockReturnValue(true);
      mockCreate.mockResolvedValue(mockRefreshToken);

      await loginUser(mockAuthData, mockClientInfo);

      expect(mockUuidv4).toHaveBeenCalledTimes(1);
    });
  });

  describe('Edge cases and security scenarios', () => {
    it('should handle empty or null client information gracefully', async () => {
      const emptyClientInfo: ClientInformation = {
        userAgent: '',
        ip: '',
      };
      mockFindUnique.mockResolvedValue(mockUser);
      mockCompareSync.mockReturnValue(true);
      mockCreate.mockResolvedValue(mockRefreshToken);

      const result = await loginUser(mockAuthData, emptyClientInfo);

      expect(result).toBeDefined();
      expect(mockCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          ipAddress: '',
          userAgent: '',
        }),
      });
    });

    it('should handle special characters in email and password', async () => {
      const specialAuthData: UserAuthenticationSchema = {
        email: 'test+special@example.com',
        password: 'P@ssw0rd!#$%',
      };
      const userWithSpecialEmail = {
        ...mockUser,
        email: 'test+special@example.com',
      };

      mockFindUnique.mockResolvedValue(userWithSpecialEmail);
      mockCompareSync.mockReturnValue(true);
      mockCreate.mockResolvedValue(mockRefreshToken);

      const result = await loginUser(specialAuthData, mockClientInfo);

      expect(result).toBeDefined();
      expect(mockFindUnique).toHaveBeenCalledWith({
        where: { email: specialAuthData.email },
      });
    });

    it('should properly hash the refresh token before storing', async () => {
      mockFindUnique.mockResolvedValue(mockUser);
      mockCompareSync.mockReturnValue(true);
      mockCreate.mockResolvedValue(mockRefreshToken);

      const mockHashInstance = {
        update: jest.fn().mockReturnThis(),
        digest: jest.fn().mockReturnValue('unique-hash-123'),
      };
      (mockCreateHash as jest.Mock).mockReturnValue(
        mockHashInstance as unknown as crypto.Hash,
      );

      await loginUser(mockAuthData, mockClientInfo);

      expect(mockCreateHash).toHaveBeenCalledWith('sha256');
      expect(mockHashInstance.update).toHaveBeenCalledWith(
        'mock-refresh-token',
      );
      expect(mockHashInstance.digest).toHaveBeenCalledWith('hex');
      expect(mockCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          tokenHash: 'unique-hash-123',
        }),
      });
    });

    it('should handle long user agent strings', async () => {
      const longUserAgent =
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 EdgeAgent/91.0.864.59 Very-Long-Browser-String-That-Exceeds-Normal-Limits';
      const clientInfoWithLongUA: ClientInformation = {
        userAgent: longUserAgent,
        ip: mockClientInfo.ip,
      };

      mockFindUnique.mockResolvedValue(mockUser);
      mockCompareSync.mockReturnValue(true);
      mockCreate.mockResolvedValue(mockRefreshToken);

      const result = await loginUser(mockAuthData, clientInfoWithLongUA);

      expect(result).toBeDefined();
      expect(mockCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({
          userAgent: longUserAgent,
        }),
      });
    });
  });

  describe('Logging scenarios', () => {
    it('should log successful authentication with correct event type', async () => {
      mockFindUnique.mockResolvedValue(mockUser);
      mockCompareSync.mockReturnValue(true);
      mockCreate.mockResolvedValue(mockRefreshToken);

      await loginUser(mockAuthData, mockClientInfo);

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockUser.id,
          eventType: EventTypes.AUTH_SUCCESS,
          userAgent: mockClientInfo.userAgent,
          ipAddress: mockClientInfo.ip,
          metadata: JSON.stringify({
            message: 'Successfully logged in user',
          }),
        }),
      );
    });

    it('should log refresh token creation success', async () => {
      mockFindUnique.mockResolvedValue(mockUser);
      mockCompareSync.mockReturnValue(true);
      mockCreate.mockResolvedValue(mockRefreshToken);

      await loginUser(mockAuthData, mockClientInfo);

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockUser.id,
          eventType: EventTypes.REFRESH_TOKEN_SUCCESS,
          userAgent: mockClientInfo.userAgent,
          ipAddress: mockClientInfo.ip,
          metadata: JSON.stringify({
            message: 'Refresh token successfully inserted to DB',
          }),
        }),
      );
    });

    it('should log all events in correct order', async () => {
      mockFindUnique.mockResolvedValue(mockUser);
      mockCompareSync.mockReturnValue(true);
      mockCreate.mockResolvedValue(mockRefreshToken);

      await loginUser(mockAuthData, mockClientInfo);

      expect(mockLogger).toHaveBeenCalledTimes(2);

      expect(mockLogger).toHaveBeenNthCalledWith(
        1,
        expect.objectContaining({
          eventType: EventTypes.REFRESH_TOKEN_SUCCESS,
        }),
      );

      expect(mockLogger).toHaveBeenNthCalledWith(
        2,
        expect.objectContaining({
          eventType: EventTypes.AUTH_SUCCESS,
        }),
      );
    });

    it('should include user ID in all logs after user is found', async () => {
      mockFindUnique.mockResolvedValue(mockUser);
      mockCompareSync.mockReturnValue(false);

      await expect(loginUser(mockAuthData, mockClientInfo)).rejects.toThrow();

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockUser.id,
          eventType: EventTypes.AUTH_FAILED,
        }),
      );
    });

    it('should not include user ID in logs when user is not found', async () => {
      mockFindUnique.mockResolvedValue(null);

      await expect(loginUser(mockAuthData, mockClientInfo)).rejects.toThrow();

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: EventTypes.AUTH_FAILED,
        }),
      );
      expect(mockLogger).toHaveBeenCalledWith(
        expect.not.objectContaining({
          userId: expect.anything(),
        }),
      );
    });
  });

  describe('Performance and timing scenarios', () => {
    it('should handle concurrent login attempts', async () => {
      mockFindUnique.mockResolvedValue(mockUser);
      mockCompareSync.mockReturnValue(true);
      mockCreate.mockResolvedValue(mockRefreshToken);

      (mockUuidv4 as jest.Mock)
        .mockReturnValueOnce('jti-1')
        .mockReturnValueOnce('jti-2')
        .mockReturnValueOnce('jti-3');

      const promises = [
        loginUser(mockAuthData, mockClientInfo),
        loginUser(mockAuthData, mockClientInfo),
        loginUser(mockAuthData, mockClientInfo),
      ];

      const results = await Promise.all(promises);

      expect(results).toHaveLength(3);
      results.forEach((result) => {
        expect(result).toHaveProperty('accessToken');
        expect(result).toHaveProperty('refreshToken');
        expect(result).toHaveProperty('user');
      });
    });

    it('should handle slow database responses', async () => {
      const slowPromise = new Promise((resolve) => {
        setTimeout(() => resolve(mockUser), 100);
      });
      (mockFindUnique as jest.Mock).mockReturnValue(slowPromise);
      mockCompareSync.mockReturnValue(true);
      mockCreate.mockResolvedValue(mockRefreshToken);

      const startTime = Date.now();
      const result = await loginUser(mockAuthData, mockClientInfo);
      const endTime = Date.now();

      expect(result).toBeDefined();
      expect(endTime - startTime).toBeGreaterThanOrEqual(100);
    });

    it('should handle very long passwords', async () => {
      const longPassword = 'P@ssw0rd!' + 'a'.repeat(1000);
      const longPasswordData: UserAuthenticationSchema = {
        email: mockAuthData.email,
        password: longPassword,
      };

      mockFindUnique.mockResolvedValue(mockUser);
      mockCompareSync.mockReturnValue(true);
      mockCreate.mockResolvedValue(mockRefreshToken);

      const result = await loginUser(longPasswordData, mockClientInfo);

      expect(result).toBeDefined();
      expect(mockCompareSync).toHaveBeenCalledWith(
        longPassword,
        mockUser.passwordHash,
      );
    });
  });

  describe('Token expiration scenarios', () => {
    it('should set correct expiration time for refresh token', async () => {
      mockFindUnique.mockResolvedValue(mockUser);
      mockCompareSync.mockReturnValue(true);
      mockCreate.mockResolvedValue(mockRefreshToken);

      await loginUser(mockAuthData, mockClientInfo);

      const createCall = (mockCreate as jest.Mock).mock.calls[0][0];
      const expiresAt = createCall.data.expiresAt as Date;
      const expectedExpiration = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

      expect(
        Math.abs(expiresAt.getTime() - expectedExpiration.getTime()),
      ).toBeLessThan(1000);
    });

    it('should use correct JWT expiration times', async () => {
      mockFindUnique.mockResolvedValue(mockUser);
      mockCompareSync.mockReturnValue(true);
      mockCreate.mockResolvedValue(mockRefreshToken);

      await loginUser(mockAuthData, mockClientInfo);

      const jwtCalls = (mockJwtSign as jest.Mock).mock.calls;
      const refreshTokenCall = jwtCalls.find(
        (call) => (call[0] as Record<string, unknown>).type === 'refresh',
      );
      const accessTokenCall = jwtCalls.find(
        (call) => (call[0] as Record<string, unknown>).type === 'access',
      );

      expect(refreshTokenCall?.[2]).toEqual({ expiresIn: '7d' });
      expect(accessTokenCall?.[2]).toEqual({ expiresIn: '15m' });
    });
  });
});

import { logout, logoutAll } from '../../../src/services/auth/logout.service';
import { ClientInformation, EventTypes } from '../../../src/utils/types';

jest.mock('../../../src/config/prisma-client', () => ({
  __esModule: true,
  default: {
    refreshToken: {
      findFirst: jest.fn(),
      update: jest.fn(),
      findMany: jest.fn(),
      updateMany: jest.fn(),
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

jest.mock('jsonwebtoken', () => ({
  verify: jest.fn(),
}));

jest.mock('crypto', () => ({
  createHash: jest.fn(),
}));

import prismaClient from '../../../src/config/prisma-client';
import logger from '../../../src/utils/logger';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const mockFindFirst = prismaClient.refreshToken
  .findFirst as jest.MockedFunction<typeof prismaClient.refreshToken.findFirst>;
const mockUpdate = prismaClient.refreshToken.update as jest.MockedFunction<
  typeof prismaClient.refreshToken.update
>;
const mockFindMany = prismaClient.refreshToken.findMany as jest.MockedFunction<
  typeof prismaClient.refreshToken.findMany
>;
const mockUpdateMany = prismaClient.refreshToken
  .updateMany as jest.MockedFunction<
  typeof prismaClient.refreshToken.updateMany
>;
const mockLogger = logger as jest.MockedFunction<typeof logger>;
const mockJwtVerify = jwt.verify as jest.MockedFunction<typeof jwt.verify>;
const mockCreateHash = crypto.createHash as jest.MockedFunction<
  typeof crypto.createHash
>;

const mockClientInfo: ClientInformation = {
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
  ip: '192.168.1.1',
};

const mockTokenRecord = {
  id: 'token-123',
  userId: 'user-123',
  tokenHash: 'mock-token-hash',
  ipAddress: mockClientInfo.ip,
  userAgent: mockClientInfo.userAgent,
  createdAt: new Date(),
  expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  revoked: false,
  revokedAt: null,
  replacedById: null,
};

const mockUpdatedTokenRecord = {
  ...mockTokenRecord,
  revoked: true,
  revokedAt: new Date(),
};

const mockPayload = {
  sub: 'user-123',
  jti: 'token-123',
  type: 'refresh',
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60,
};

describe('logout', () => {
  beforeEach(() => {
    jest.clearAllMocks();

    const mockHashInstance = {
      update: jest.fn().mockReturnThis(),
      digest: jest.fn().mockReturnValue('mock-token-hash'),
    };
    (mockCreateHash as jest.Mock).mockReturnValue(
      mockHashInstance as unknown as crypto.Hash,
    );
  });

  describe('Successful logout scenarios', () => {
    it('should successfully logout user with valid refresh token', async () => {
      (mockJwtVerify as jest.Mock).mockReturnValue(mockPayload);
      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockUpdate.mockResolvedValue(mockUpdatedTokenRecord);

      const result = await logout('valid-refresh-token', mockClientInfo);

      expect(result).toBe(true);
      expect(mockJwtVerify).toHaveBeenCalledWith(
        'valid-refresh-token',
        'test-refresh-secret',
      );
      expect(mockFindFirst).toHaveBeenCalledWith({
        where: { tokenHash: 'mock-token-hash' },
      });
      expect(mockUpdate).toHaveBeenCalledWith({
        where: { id: mockTokenRecord.id },
        data: {
          revoked: true,
          revokedAt: expect.any(Date),
        },
      });
    });

    it('should hash the refresh token correctly before lookup', async () => {
      (mockJwtVerify as jest.Mock).mockReturnValue(mockPayload);
      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockUpdate.mockResolvedValue(mockUpdatedTokenRecord);

      const mockHashInstance = {
        update: jest.fn().mockReturnThis(),
        digest: jest.fn().mockReturnValue('unique-hash-456'),
      };
      (mockCreateHash as jest.Mock).mockReturnValue(
        mockHashInstance as unknown as crypto.Hash,
      );

      await logout('test-token-123', mockClientInfo);

      expect(mockCreateHash).toHaveBeenCalledWith('sha256');
      expect(mockHashInstance.update).toHaveBeenCalledWith('test-token-123');
      expect(mockHashInstance.digest).toHaveBeenCalledWith('hex');
      expect(mockFindFirst).toHaveBeenCalledWith({
        where: { tokenHash: 'unique-hash-456' },
      });
    });

    it('should log successful logout events in correct order', async () => {
      (mockJwtVerify as jest.Mock).mockReturnValue(mockPayload);
      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockUpdate.mockResolvedValue(mockUpdatedTokenRecord);

      await logout('valid-refresh-token', mockClientInfo);

      expect(mockLogger).toHaveBeenCalledTimes(2);

      expect(mockLogger).toHaveBeenNthCalledWith(
        1,
        expect.objectContaining({
          userId: mockTokenRecord.userId,
          eventType: EventTypes.REFRESH_TOKEN_SUCCESS,
          userAgent: mockClientInfo.userAgent,
          ipAddress: mockClientInfo.ip,
          metadata: JSON.stringify({
            message: 'Successfully revoked refresh token',
          }),
        }),
      );

      expect(mockLogger).toHaveBeenNthCalledWith(
        2,
        expect.objectContaining({
          userId: mockPayload.sub,
          eventType: EventTypes.LOGOUT,
          userAgent: mockClientInfo.userAgent,
          ipAddress: mockClientInfo.ip,
          metadata: JSON.stringify({
            message: 'Successfully logged out user',
          }),
        }),
      );
    });
  });

  describe('JWT verification failure scenarios', () => {
    it('should throw 401 error when JWT verification fails', async () => {
      (mockJwtVerify as jest.Mock).mockImplementation(() => {
        throw new Error('Invalid token');
      });

      await expect(
        logout('invalid-token', mockClientInfo),
      ).rejects.toMatchObject({
        message: 'Failed to verify your JWT token',
        statusCode: 401,
      });

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: EventTypes.LOGOUT,
          userAgent: mockClientInfo.userAgent,
          ipAddress: mockClientInfo.ip,
          metadata: JSON.stringify({
            message: 'Failed to verify your JWT token',
          }),
        }),
      );
    });

    it('should not proceed with token lookup when JWT verification fails', async () => {
      (mockJwtVerify as jest.Mock).mockImplementation(() => {
        throw new Error('Invalid token');
      });

      await expect(logout('invalid-token', mockClientInfo)).rejects.toThrow();

      expect(mockFindFirst).not.toHaveBeenCalled();
      expect(mockUpdate).not.toHaveBeenCalled();
    });

    it('should handle expired JWT tokens', async () => {
      (mockJwtVerify as jest.Mock).mockImplementation(() => {
        throw new Error('jwt expired');
      });

      await expect(
        logout('expired-token', mockClientInfo),
      ).rejects.toMatchObject({
        message: 'Failed to verify your JWT token',
        statusCode: 401,
      });
    });

    it('should handle malformed JWT tokens', async () => {
      (mockJwtVerify as jest.Mock).mockImplementation(() => {
        throw new Error('jwt malformed');
      });

      await expect(
        logout('malformed-token', mockClientInfo),
      ).rejects.toMatchObject({
        message: 'Failed to verify your JWT token',
        statusCode: 401,
      });
    });
  });

  describe('Token record not found scenarios', () => {
    it('should return true when token record does not exist', async () => {
      (mockJwtVerify as jest.Mock).mockReturnValue(mockPayload);
      mockFindFirst.mockResolvedValue(null);

      const result = await logout(
        'valid-but-nonexistent-token',
        mockClientInfo,
      );

      expect(result).toBe(true);
      expect(mockUpdate).not.toHaveBeenCalled();
      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockPayload.sub,
          eventType: EventTypes.LOGOUT,
          userAgent: mockClientInfo.userAgent,
          ipAddress: mockClientInfo.ip,
          metadata: JSON.stringify({
            message: 'Token record not found',
          }),
        }),
      );
    });

    it('should return true when token is already revoked', async () => {
      (mockJwtVerify as jest.Mock).mockReturnValue(mockPayload);
      const revokedTokenRecord = { ...mockTokenRecord, revoked: true };
      mockFindFirst.mockResolvedValue(revokedTokenRecord);

      const result = await logout('already-revoked-token', mockClientInfo);

      expect(result).toBe(true);
      expect(mockUpdate).not.toHaveBeenCalled();
      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockPayload.sub,
          eventType: EventTypes.LOGOUT,
          userAgent: mockClientInfo.userAgent,
          ipAddress: mockClientInfo.ip,
          metadata: JSON.stringify({
            message: 'Token record not found',
          }),
        }),
      );
    });
  });

  describe('Database error scenarios', () => {
    it('should throw 500 error when token update fails', async () => {
      (mockJwtVerify as jest.Mock).mockReturnValue(mockPayload);
      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockUpdate.mockRejectedValue(new Error('Database error'));

      await expect(logout('valid-token', mockClientInfo)).rejects.toMatchObject(
        {
          message: 'Failed to update refresh token in DB',
          statusCode: 500,
        },
      );

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockPayload.sub,
          eventType: EventTypes.DB_ERROR,
          userAgent: mockClientInfo.userAgent,
          ipAddress: mockClientInfo.ip,
          metadata: JSON.stringify({
            message: 'Failed to update refresh token in DB',
          }),
        }),
      );
    });

    it('should handle database connection errors during token lookup', async () => {
      (mockJwtVerify as jest.Mock).mockReturnValue(mockPayload);
      mockFindFirst.mockRejectedValue(new Error('Database connection error'));

      await expect(logout('valid-token', mockClientInfo)).rejects.toThrow(
        'Database connection error',
      );
    });
  });

  describe('Edge cases and security scenarios', () => {
    it('should handle empty refresh token', async () => {
      (mockJwtVerify as jest.Mock).mockImplementation(() => {
        throw new Error('jwt must be provided');
      });

      await expect(logout('', mockClientInfo)).rejects.toMatchObject({
        message: 'Failed to verify your JWT token',
        statusCode: 401,
      });
    });

    it('should handle null client information gracefully', async () => {
      const emptyClientInfo: ClientInformation = {
        userAgent: '',
        ip: '',
      };

      (mockJwtVerify as jest.Mock).mockReturnValue(mockPayload);
      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockUpdate.mockResolvedValue(mockUpdatedTokenRecord);

      const result = await logout('valid-token', emptyClientInfo);

      expect(result).toBe(true);
      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userAgent: '',
          ipAddress: '',
        }),
      );
    });

    it('should handle tokens with different JWT payload structures', async () => {
      const customPayload = {
        sub: 'user-456',
        jti: 'custom-jti',
        type: 'refresh',
        customField: 'value',
      };

      (mockJwtVerify as jest.Mock).mockReturnValue(customPayload);
      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockUpdate.mockResolvedValue(mockUpdatedTokenRecord);

      const result = await logout('custom-token', mockClientInfo);

      expect(result).toBe(true);
      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: customPayload.sub,
        }),
      );
    });
  });
});

describe('logoutAll', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Successful logout all scenarios', () => {
    it('should successfully revoke all valid tokens for user', async () => {
      const validTokens = [
        { ...mockTokenRecord, id: 'token-1' },
        { ...mockTokenRecord, id: 'token-2' },
        { ...mockTokenRecord, id: 'token-3' },
      ];

      mockFindMany.mockResolvedValue(validTokens);
      mockUpdateMany.mockResolvedValue({ count: 3 });

      const result = await logoutAll('user-123', mockClientInfo);

      expect(result).toEqual({
        message: 'Logout completed. Revoked 3 tokens',
      });

      expect(mockFindMany).toHaveBeenCalledWith({
        where: { userId: 'user-123', revoked: false },
      });

      expect(mockUpdateMany).toHaveBeenCalledWith({
        where: { userId: 'user-123', revoked: false },
        data: { revoked: true, revokedAt: expect.any(Date) },
      });
    });

    it('should log successful token revocation', async () => {
      const validTokens = [mockTokenRecord];
      mockFindMany.mockResolvedValue(validTokens);
      mockUpdateMany.mockResolvedValue({ count: 1 });

      await logoutAll('user-123', mockClientInfo);

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-123',
          eventType: EventTypes.REFRESH_TOKEN_SUCCESS,
          userAgent: mockClientInfo.userAgent,
          ipAddress: mockClientInfo.ip,
          metadata: JSON.stringify({
            message: 'Refresh tokens successfuly updated',
          }),
        }),
      );
    });

    it('should handle user with no valid tokens', async () => {
      mockFindMany.mockResolvedValue([]);

      const result = await logoutAll('user-123', mockClientInfo);

      expect(result).toEqual({
        message: 'Logout completed. None of the tokens were valid',
      });

      expect(mockUpdateMany).not.toHaveBeenCalled();
      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-123',
          eventType: EventTypes.LOGOUT_ALL,
          userAgent: mockClientInfo.userAgent,
          ipAddress: mockClientInfo.ip,
          metadata: JSON.stringify({
            message: 'Logout completed. None of the tokens were valid',
          }),
        }),
      );
    });

    it('should handle large number of tokens', async () => {
      const manyTokens = Array.from({ length: 50 }, (_, i) => ({
        ...mockTokenRecord,
        id: `token-${i}`,
      }));

      mockFindMany.mockResolvedValue(manyTokens);
      mockUpdateMany.mockResolvedValue({ count: 50 });

      const result = await logoutAll('user-123', mockClientInfo);

      expect(result).toEqual({
        message: 'Logout completed. Revoked 50 tokens',
      });
    });
  });

  describe('Database error scenarios', () => {
    it('should throw 500 error when token update fails', async () => {
      const validTokens = [mockTokenRecord];
      mockFindMany.mockResolvedValue(validTokens);
      mockUpdateMany.mockRejectedValue(new Error('Database error'));

      await expect(logoutAll('user-123', mockClientInfo)).rejects.toMatchObject(
        {
          message: 'Failed to update refresh tokens in DB',
          statusCode: 500,
        },
      );

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-123',
          eventType: EventTypes.REFRESH_TOKEN_FAIL,
          userAgent: mockClientInfo.userAgent,
          ipAddress: mockClientInfo.ip,
          metadata: JSON.stringify({
            message: 'Failed to update refresh tokens in DB',
          }),
        }),
      );
    });

    it('should handle database connection errors during token lookup', async () => {
      mockFindMany.mockRejectedValue(new Error('Database connection error'));

      await expect(logoutAll('user-123', mockClientInfo)).rejects.toThrow(
        'Database connection error',
      );
    });

    it('should handle partial update failures', async () => {
      const validTokens = [mockTokenRecord, mockTokenRecord];
      mockFindMany.mockResolvedValue(validTokens);
      mockUpdateMany.mockResolvedValue({ count: 1 });

      const result = await logoutAll('user-123', mockClientInfo);

      expect(result).toEqual({
        message: 'Logout completed. Revoked 1 tokens',
      });
    });
  });

  describe('Edge cases and security scenarios', () => {
    it('should handle empty user ID', async () => {
      mockFindMany.mockResolvedValue([]);

      const result = await logoutAll('', mockClientInfo);

      expect(result).toEqual({
        message: 'Logout completed. None of the tokens were valid',
      });

      expect(mockFindMany).toHaveBeenCalledWith({
        where: { userId: '', revoked: false },
      });
    });

    it('should handle null client information gracefully', async () => {
      const emptyClientInfo: ClientInformation = {
        userAgent: '',
        ip: '',
      };

      mockFindMany.mockResolvedValue([]);

      const result = await logoutAll('user-123', emptyClientInfo);

      expect(result).toEqual({
        message: 'Logout completed. None of the tokens were valid',
      });

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userAgent: '',
          ipAddress: '',
        }),
      );
    });

    it('should handle very long user IDs', async () => {
      const longUserId = 'user-' + 'a'.repeat(1000);
      mockFindMany.mockResolvedValue([]);

      const result = await logoutAll(longUserId, mockClientInfo);

      expect(result).toEqual({
        message: 'Logout completed. None of the tokens were valid',
      });

      expect(mockFindMany).toHaveBeenCalledWith({
        where: { userId: longUserId, revoked: false },
      });
    });
  });

  describe('Performance and concurrency scenarios', () => {
    it('should handle concurrent logoutAll requests for same user', async () => {
      const validTokens = [mockTokenRecord];
      mockFindMany.mockResolvedValue(validTokens);
      mockUpdateMany.mockResolvedValue({ count: 1 });

      const promises = [
        logoutAll('user-123', mockClientInfo),
        logoutAll('user-123', mockClientInfo),
        logoutAll('user-123', mockClientInfo),
      ];

      const results = await Promise.all(promises);

      expect(results).toHaveLength(3);
      results.forEach((result) => {
        expect(result).toHaveProperty('message');
      });
    });

    it('should handle slow database responses', async () => {
      const slowPromise = new Promise((resolve) => {
        setTimeout(() => resolve([mockTokenRecord]), 100);
      });
      (mockFindMany as jest.Mock).mockReturnValue(slowPromise);
      mockUpdateMany.mockResolvedValue({ count: 1 });

      const startTime = Date.now();
      const result = await logoutAll('user-123', mockClientInfo);
      const endTime = Date.now();

      expect(result).toBeDefined();
      expect(endTime - startTime).toBeGreaterThanOrEqual(100);
    });
  });

  describe('Logging scenarios', () => {
    it('should not log refresh token success when no tokens to revoke', async () => {
      mockFindMany.mockResolvedValue([]);

      await logoutAll('user-123', mockClientInfo);

      expect(mockLogger).toHaveBeenCalledTimes(1);
      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: EventTypes.LOGOUT_ALL,
        }),
      );
    });

    it('should include correct user ID in all log entries', async () => {
      const validTokens = [mockTokenRecord];
      mockFindMany.mockResolvedValue(validTokens);
      mockUpdateMany.mockResolvedValue({ count: 1 });

      await logoutAll('specific-user-456', mockClientInfo);

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'specific-user-456',
          eventType: EventTypes.REFRESH_TOKEN_SUCCESS,
        }),
      );
    });

    it('should handle logging with special characters in user ID', async () => {
      const specialUserId = 'user-@#$%^&*()';
      mockFindMany.mockResolvedValue([]);

      await logoutAll(specialUserId, mockClientInfo);

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: specialUserId,
          eventType: EventTypes.LOGOUT_ALL,
        }),
      );
    });
  });
});

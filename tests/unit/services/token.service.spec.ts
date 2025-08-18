import { refreshToken } from '../../../src/services/auth/token.service';
import { ClientInformation, EventTypes } from '../../../src/utils/types';

jest.mock('../../../src/config/prisma-client', () => ({
  __esModule: true,
  default: {
    refreshToken: {
      findFirst: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
    },
    user: {
      findUnique: jest.fn(),
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
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';

const mockFindFirst = prismaClient.refreshToken
  .findFirst as jest.MockedFunction<typeof prismaClient.refreshToken.findFirst>;
const mockCreate = prismaClient.refreshToken.create as jest.MockedFunction<
  typeof prismaClient.refreshToken.create
>;
const mockUpdate = prismaClient.refreshToken.update as jest.MockedFunction<
  typeof prismaClient.refreshToken.update
>;
const mockFindUnique = prismaClient.user.findUnique as jest.MockedFunction<
  typeof prismaClient.user.findUnique
>;
const mockLogger = logger as jest.MockedFunction<typeof logger>;
const mockJwtVerify = jwt.verify as jest.MockedFunction<
  (token: string, secret: string) => object
>;
const mockJwtSign = jwt.sign as jest.MockedFunction<typeof jwt.sign>;
const mockCreateHash = crypto.createHash as jest.MockedFunction<
  typeof crypto.createHash
>;
const mockUuidv4 = uuidv4 as jest.MockedFunction<() => string>;

const mockClientInfo: ClientInformation = {
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
  ip: '192.168.1.1',
};

const mockUser = {
  id: 'user-123',
  email: 'test@example.com',
  passwordHash: '$2a$12$hashedpassword',
  isActive: true,
  createdAt: new Date('2024-01-01T00:00:00Z'),
  updatedAt: new Date('2024-01-01T00:00:00Z'),
  lastLoginAt: null,
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

const mockNewTokenRecord = {
  id: 'new-token-456',
  userId: 'user-123',
  tokenHash: 'new-token-hash',
  ipAddress: mockClientInfo.ip,
  userAgent: mockClientInfo.userAgent,
  createdAt: new Date(),
  expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  revoked: false,
  revokedAt: null,
  replacedById: null,
};

const mockPayload = {
  sub: 'user-123',
  jti: 'token-123',
  type: 'refresh',
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60,
};

describe('refreshToken', () => {
  beforeEach(() => {
    jest.clearAllMocks();

    mockUuidv4.mockReturnValue('new-token-456');

    const mockHashInstance = {
      update: jest.fn().mockReturnThis(),
      digest: jest.fn().mockReturnValue('mock-token-hash'),
    };
    mockCreateHash.mockReturnValue(mockHashInstance as unknown as crypto.Hash);

    mockJwtSign.mockImplementation((payload: any) => {
      if (payload.type === 'refresh') return 'new-refresh-token';
      if (payload.type === 'access') return 'new-access-token';
      return 'mock-token';
    });
  });

  describe('Successful token refresh scenarios', () => {
    it('should successfully refresh token with valid credentials', async () => {
      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockJwtVerify.mockReturnValue(mockPayload);
      mockFindUnique.mockResolvedValue(mockUser);
      mockCreate.mockResolvedValue(mockNewTokenRecord);
      mockUpdate.mockResolvedValue({
        ...mockTokenRecord,
        revoked: true,
        revokedAt: new Date(),
        replacedById: mockNewTokenRecord.id,
      });

      const result = await refreshToken('valid-refresh-token', mockClientInfo);

      expect(result).toEqual({
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
      });

      expect(mockFindFirst).toHaveBeenCalledWith({
        where: {
          tokenHash: 'mock-token-hash',
          ipAddress: mockClientInfo.ip,
          userAgent: mockClientInfo.userAgent,
          revoked: false,
        },
      });
      expect(mockJwtVerify).toHaveBeenCalledWith(
        'valid-refresh-token',
        'test-refresh-secret',
      );
      expect(mockFindUnique).toHaveBeenCalledWith({
        where: { id: mockPayload.sub },
      });
    });

    it('should hash the incoming refresh token correctly', async () => {
      const mockHashInstance = {
        update: jest.fn().mockReturnThis(),
        digest: jest.fn().mockReturnValue('unique-hash-123'),
      };
      mockCreateHash.mockReturnValue(
        mockHashInstance as unknown as crypto.Hash,
      );

      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockJwtVerify.mockReturnValue(mockPayload);
      mockFindUnique.mockResolvedValue(mockUser);
      mockCreate.mockResolvedValue(mockNewTokenRecord);
      mockUpdate.mockResolvedValue(mockTokenRecord);

      await refreshToken('test-token-456', mockClientInfo);

      expect(mockCreateHash).toHaveBeenCalledWith('sha256');
      expect(mockHashInstance.update).toHaveBeenCalledWith('test-token-456');
      expect(mockHashInstance.digest).toHaveBeenCalledWith('hex');
      expect(mockFindFirst).toHaveBeenCalledWith({
        where: {
          tokenHash: 'unique-hash-123',
          ipAddress: mockClientInfo.ip,
          userAgent: mockClientInfo.userAgent,
          revoked: false,
        },
      });
    });

    it('should generate new JWT tokens with correct payload and expiration', async () => {
      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockJwtVerify.mockReturnValue(mockPayload);
      mockFindUnique.mockResolvedValue(mockUser);
      mockCreate.mockResolvedValue(mockNewTokenRecord);
      mockUpdate.mockResolvedValue(mockTokenRecord);

      await refreshToken('valid-token', mockClientInfo);

      expect(mockJwtSign).toHaveBeenCalledWith(
        { sub: mockUser.id, jti: 'new-token-456', type: 'refresh' },
        'test-refresh-secret',
        { expiresIn: '7d' },
      );
      expect(mockJwtSign).toHaveBeenCalledWith(
        { sub: mockUser.id, type: 'access' },
        'test-jwt-secret',
        { expiresIn: '15m' },
      );
    });

    it('should create new refresh token record with proper data', async () => {
      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockJwtVerify.mockReturnValue(mockPayload);
      mockFindUnique.mockResolvedValue(mockUser);
      mockCreate.mockResolvedValue(mockNewTokenRecord);
      mockUpdate.mockResolvedValue(mockTokenRecord);

      await refreshToken('valid-token', mockClientInfo);

      expect(mockCreate).toHaveBeenCalledWith({
        data: {
          id: 'new-token-456',
          userId: mockUser.id,
          ipAddress: mockClientInfo.ip,
          userAgent: mockClientInfo.userAgent,
          tokenHash: 'mock-token-hash',
          expiresAt: expect.any(Date),
        },
      });
    });

    it('should revoke old refresh token and link to new one', async () => {
      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockJwtVerify.mockReturnValue(mockPayload);
      mockFindUnique.mockResolvedValue(mockUser);
      mockCreate.mockResolvedValue(mockNewTokenRecord);
      mockUpdate.mockResolvedValue(mockTokenRecord);

      await refreshToken('valid-token', mockClientInfo);

      expect(mockUpdate).toHaveBeenCalledWith({
        where: { id: mockTokenRecord.id },
        data: {
          revoked: true,
          revokedAt: expect.any(Date),
          replacedById: mockNewTokenRecord.id,
        },
      });
    });

    it('should log all successful operations', async () => {
      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockJwtVerify.mockReturnValue(mockPayload);
      mockFindUnique.mockResolvedValue(mockUser);
      mockCreate.mockResolvedValue(mockNewTokenRecord);
      mockUpdate.mockResolvedValue(mockTokenRecord);

      await refreshToken('valid-token', mockClientInfo);

      expect(mockLogger).toHaveBeenCalledTimes(3);

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockUser.id,
          eventType: EventTypes.REFRESH_TOKEN_SUCCESS,
          metadata: JSON.stringify({
            message: 'Refresh token successfully inserted to DB',
          }),
        }),
      );

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockUser.id,
          eventType: EventTypes.REFRESH_TOKEN_SUCCESS,
          metadata: JSON.stringify({
            message: 'Refresh token successfully updated in DB',
          }),
        }),
      );

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockPayload.sub,
          eventType: EventTypes.REFRESH_TOKEN_SUCCESS,
          metadata: JSON.stringify({
            message: 'Successfully refreshed token',
          }),
        }),
      );
    });
  });

  describe('Invalid token scenarios', () => {
    it('should throw 401 error when refresh token is not found in database', async () => {
      mockFindFirst.mockResolvedValue(null);

      await expect(
        refreshToken('invalid-token', mockClientInfo),
      ).rejects.toMatchObject({
        message: 'Invalid refresh token',
        statusCode: 401,
      });

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: EventTypes.REFRESH_TOKEN_FAIL,
          userAgent: mockClientInfo.userAgent,
          ipAddress: mockClientInfo.ip,
          metadata: JSON.stringify({
            message: 'Invalid refresh token',
          }),
        }),
      );
    });

    it('should not proceed with JWT verification when token not in database', async () => {
      mockFindFirst.mockResolvedValue(null);

      await expect(
        refreshToken('invalid-token', mockClientInfo),
      ).rejects.toThrow();

      expect(mockJwtVerify).not.toHaveBeenCalled();
      expect(mockFindUnique).not.toHaveBeenCalled();
    });

    it('should throw 401 error when JWT verification fails', async () => {
      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockJwtVerify.mockImplementation(() => {
        throw new Error('JWT verification failed');
      });

      await expect(
        refreshToken('invalid-jwt', mockClientInfo),
      ).rejects.toMatchObject({
        message: 'JWT verification failed',
        statusCode: 401,
      });

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: EventTypes.REFRESH_TOKEN_FAIL,
          metadata: JSON.stringify({
            message: 'JWT verification failed',
          }),
        }),
      );
    });

    it('should handle expired JWT tokens', async () => {
      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockJwtVerify.mockImplementation(() => {
        const error = new Error('jwt expired');
        error.name = 'TokenExpiredError';
        throw error;
      });

      await expect(
        refreshToken('expired-token', mockClientInfo),
      ).rejects.toMatchObject({
        message: 'jwt expired',
        statusCode: 401,
      });
    });

    it('should handle malformed JWT tokens', async () => {
      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockJwtVerify.mockImplementation(() => {
        const error = new Error('invalid token');
        error.name = 'JsonWebTokenError';
        throw error;
      });

      await expect(
        refreshToken('malformed-token', mockClientInfo),
      ).rejects.toMatchObject({
        message: 'invalid token',
        statusCode: 401,
      });
    });

    it('should handle non-Error JWT verification failures', async () => {
      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockJwtVerify.mockImplementation(() => {
        throw 'Unknown error';
      });

      await expect(
        refreshToken('unknown-error-token', mockClientInfo),
      ).rejects.toMatchObject({
        message: 'Invalid refresh token',
        statusCode: 401,
      });
    });
  });

  describe('User not found scenarios', () => {
    it('should throw 404 error when user does not exist', async () => {
      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockJwtVerify.mockReturnValue(mockPayload);
      mockFindUnique.mockResolvedValue(null);

      await expect(
        refreshToken('valid-token', mockClientInfo),
      ).rejects.toMatchObject({
        message: 'User not found',
        statusCode: 404,
      });

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: EventTypes.REFRESH_TOKEN_FAIL,
          metadata: JSON.stringify({
            message: 'User not found',
          }),
        }),
      );
    });

    it('should not proceed with token generation when user not found', async () => {
      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockJwtVerify.mockReturnValue(mockPayload);
      mockFindUnique.mockResolvedValue(null);

      await expect(
        refreshToken('valid-token', mockClientInfo),
      ).rejects.toThrow();

      expect(mockCreate).not.toHaveBeenCalled();
      expect(mockUpdate).not.toHaveBeenCalled();
    });
  });

  describe('Database error scenarios', () => {
    it('should throw 500 error when new token creation fails', async () => {
      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockJwtVerify.mockReturnValue(mockPayload);
      mockFindUnique.mockResolvedValue(mockUser);
      mockCreate.mockRejectedValue(new Error('Database error'));

      await expect(
        refreshToken('valid-token', mockClientInfo),
      ).rejects.toMatchObject({
        message: 'Failed to insert refresh token to DB',
        statusCode: 500,
      });

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: EventTypes.DB_ERROR,
          metadata: JSON.stringify({
            message: 'Failed to insert refresh token to DB',
          }),
        }),
      );
    });

    it('should throw 500 error when old token update fails', async () => {
      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockJwtVerify.mockReturnValue(mockPayload);
      mockFindUnique.mockResolvedValue(mockUser);
      mockCreate.mockResolvedValue(mockNewTokenRecord);
      mockUpdate.mockRejectedValue(new Error('Update failed'));

      await expect(
        refreshToken('valid-token', mockClientInfo),
      ).rejects.toMatchObject({
        message: 'Failed to update refresh token in DB',
        statusCode: 500,
      });

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: EventTypes.DB_ERROR,
          metadata: JSON.stringify({
            message: 'Failed to update refresh token in DB',
          }),
        }),
      );
    });

    it('should handle database connection errors during token lookup', async () => {
      mockFindFirst.mockRejectedValue(new Error('Database connection error'));

      await expect(refreshToken('valid-token', mockClientInfo)).rejects.toThrow(
        'Database connection error',
      );
    });

    it('should handle database connection errors during user lookup', async () => {
      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockJwtVerify.mockReturnValue(mockPayload);
      mockFindUnique.mockRejectedValue(new Error('User lookup failed'));

      await expect(refreshToken('valid-token', mockClientInfo)).rejects.toThrow(
        'User lookup failed',
      );
    });
  });

  describe('Edge cases and security scenarios', () => {
    it('should handle empty client information gracefully', async () => {
      const emptyClientInfo: ClientInformation = {
        userAgent: '',
        ip: '',
      };

      mockFindFirst.mockResolvedValue({
        ...mockTokenRecord,
        ipAddress: '',
        userAgent: '',
      });
      mockJwtVerify.mockReturnValue(mockPayload);
      mockFindUnique.mockResolvedValue(mockUser);
      mockCreate.mockResolvedValue(mockNewTokenRecord);
      mockUpdate.mockResolvedValue(mockTokenRecord);

      const result = await refreshToken('valid-token', emptyClientInfo);

      expect(result).toBeDefined();
      expect(mockFindFirst).toHaveBeenCalledWith({
        where: {
          tokenHash: 'mock-token-hash',
          ipAddress: '',
          userAgent: '',
          revoked: false,
        },
      });
    });

    it('should handle mismatched client information', async () => {
      const differentClientInfo: ClientInformation = {
        userAgent: 'Different-Agent/1.0',
        ip: '10.0.0.1',
      };

      mockFindFirst.mockResolvedValue(null);

      await expect(
        refreshToken('valid-token', differentClientInfo),
      ).rejects.toMatchObject({
        message: 'Invalid refresh token',
        statusCode: 401,
      });
    });

    it('should handle revoked refresh token in database', async () => {
      mockFindFirst.mockResolvedValue(null);

      await expect(
        refreshToken('revoked-token', mockClientInfo),
      ).rejects.toMatchObject({
        message: 'Invalid refresh token',
        statusCode: 401,
      });
    });

    it('should handle very long refresh tokens', async () => {
      const longToken = 'a'.repeat(10000);

      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockJwtVerify.mockReturnValue(mockPayload);
      mockFindUnique.mockResolvedValue(mockUser);
      mockCreate.mockResolvedValue(mockNewTokenRecord);
      mockUpdate.mockResolvedValue(mockTokenRecord);

      const result = await refreshToken(longToken, mockClientInfo);

      expect(result).toBeDefined();
    });

    it('should handle special characters in refresh token', async () => {
      const specialToken =
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImp0aSI6IjllNTQyNzAyLTI3MWItNDMyZi1hNjNkLTcwOTNmZDQ2YzdhZiIsImlhdCI6MTU0NzY3NzkzMCwiZXhwIjoxNTQ3NjgxNTMwfQ.wYHV8vEUaD7qqKnOEE8C6lWy6NhXNXUVRG_1Bx2l5dw';

      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockJwtVerify.mockReturnValue(mockPayload);
      mockFindUnique.mockResolvedValue(mockUser);
      mockCreate.mockResolvedValue(mockNewTokenRecord);
      mockUpdate.mockResolvedValue(mockTokenRecord);

      const result = await refreshToken(specialToken, mockClientInfo);

      expect(result).toBeDefined();
    });

    it('should generate unique JTI for each refresh', async () => {
      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockJwtVerify.mockReturnValue(mockPayload);
      mockFindUnique.mockResolvedValue(mockUser);
      mockCreate.mockResolvedValue(mockNewTokenRecord);
      mockUpdate.mockResolvedValue(mockTokenRecord);

      await refreshToken('valid-token', mockClientInfo);

      expect(mockUuidv4).toHaveBeenCalledTimes(1);
    });

    it('should handle long user agent strings', async () => {
      const longUserAgent =
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 EdgeAgent/91.0.864.59 Very-Long-Browser-String-That-Exceeds-Normal-Limits';
      const clientInfoWithLongUA: ClientInformation = {
        userAgent: longUserAgent,
        ip: mockClientInfo.ip,
      };

      mockFindFirst.mockResolvedValue({
        ...mockTokenRecord,
        userAgent: longUserAgent,
      });
      mockJwtVerify.mockReturnValue(mockPayload);
      mockFindUnique.mockResolvedValue(mockUser);
      mockCreate.mockResolvedValue(mockNewTokenRecord);
      mockUpdate.mockResolvedValue(mockTokenRecord);

      const result = await refreshToken('valid-token', clientInfoWithLongUA);

      expect(result).toBeDefined();
    });
  });

  describe('Token hashing scenarios', () => {
    it('should hash new refresh token before storing', async () => {
      const mockHashInstance1 = {
        update: jest.fn().mockReturnThis(),
        digest: jest.fn().mockReturnValue('incoming-hash'),
      };
      const mockHashInstance2 = {
        update: jest.fn().mockReturnThis(),
        digest: jest.fn().mockReturnValue('new-token-hash'),
      };

      mockCreateHash
        .mockReturnValueOnce(mockHashInstance1 as unknown as crypto.Hash)
        .mockReturnValueOnce(mockHashInstance2 as unknown as crypto.Hash);

      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockJwtVerify.mockReturnValue(mockPayload);
      mockFindUnique.mockResolvedValue(mockUser);
      mockCreate.mockResolvedValue(mockNewTokenRecord);
      mockUpdate.mockResolvedValue(mockTokenRecord);

      await refreshToken('incoming-token', mockClientInfo);

      expect(mockCreateHash).toHaveBeenCalledTimes(2);
      expect(mockHashInstance1.update).toHaveBeenCalledWith('incoming-token');
      expect(mockHashInstance2.update).toHaveBeenCalledWith(
        'new-refresh-token',
      );
    });

    it('should use SHA256 for token hashing', async () => {
      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockJwtVerify.mockReturnValue(mockPayload);
      mockFindUnique.mockResolvedValue(mockUser);
      mockCreate.mockResolvedValue(mockNewTokenRecord);
      mockUpdate.mockResolvedValue(mockTokenRecord);

      await refreshToken('valid-token', mockClientInfo);

      expect(mockCreateHash).toHaveBeenCalledWith('sha256');
    });
  });

  describe('Performance and concurrency scenarios', () => {
    it('should handle concurrent refresh attempts', async () => {
      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockJwtVerify.mockReturnValue(mockPayload);
      mockFindUnique.mockResolvedValue(mockUser);
      mockCreate
        .mockResolvedValueOnce({
          ...mockNewTokenRecord,
          id: 'concurrent-1',
        })
        .mockResolvedValueOnce({
          ...mockNewTokenRecord,
          id: 'concurrent-2',
        });
      mockUpdate.mockResolvedValue(mockTokenRecord);

      const promises = [
        refreshToken('token-1', mockClientInfo),
        refreshToken('token-2', mockClientInfo),
      ];

      const results = await Promise.all(promises);

      expect(results).toHaveLength(2);
      results.forEach((result) => {
        expect(result).toHaveProperty('accessToken');
        expect(result).toHaveProperty('refreshToken');
      });
    });

    it('should handle slow database responses', async () => {
      const slowPromise = new Promise<typeof mockTokenRecord>((resolve) => {
        setTimeout(() => resolve(mockTokenRecord), 100);
      });
      mockFindFirst.mockImplementation(() => slowPromise as never);
      mockJwtVerify.mockReturnValue(mockPayload);
      mockFindUnique.mockResolvedValue(mockUser);
      mockCreate.mockResolvedValue(mockNewTokenRecord);
      mockUpdate.mockResolvedValue(mockTokenRecord);

      const startTime = Date.now();
      const result = await refreshToken('slow-token', mockClientInfo);
      const endTime = Date.now();

      expect(result).toBeDefined();
      expect(endTime - startTime).toBeGreaterThanOrEqual(100);
    });
  });

  describe('Token expiration scenarios', () => {
    it('should set correct expiration time for new refresh token', async () => {
      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockJwtVerify.mockReturnValue(mockPayload);
      mockFindUnique.mockResolvedValue(mockUser);
      mockCreate.mockResolvedValue(mockNewTokenRecord);
      mockUpdate.mockResolvedValue(mockTokenRecord);

      const beforeTime = Date.now();
      await refreshToken('valid-token', mockClientInfo);
      const afterTime = Date.now();

      const createCall = mockCreate.mock.calls[0][0];
      const expiresAt = (createCall.data.expiresAt as Date).getTime();
      const expectedMin = beforeTime + 7 * 24 * 60 * 60 * 1000;
      const expectedMax = afterTime + 7 * 24 * 60 * 60 * 1000;

      expect(expiresAt).toBeGreaterThanOrEqual(expectedMin);
      expect(expiresAt).toBeLessThanOrEqual(expectedMax);
    });

    it('should use correct JWT expiration times', async () => {
      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockJwtVerify.mockReturnValue(mockPayload);
      mockFindUnique.mockResolvedValue(mockUser);
      mockCreate.mockResolvedValue(mockNewTokenRecord);
      mockUpdate.mockResolvedValue(mockTokenRecord);

      await refreshToken('valid-token', mockClientInfo);

      expect(mockJwtSign).toHaveBeenCalledWith(
        expect.any(Object),
        'test-refresh-secret',
        { expiresIn: '7d' },
      );
      expect(mockJwtSign).toHaveBeenCalledWith(
        expect.any(Object),
        'test-jwt-secret',
        { expiresIn: '15m' },
      );
    });
  });

  describe('Logging scenarios', () => {
    it('should include correct client information in all logs', async () => {
      const customClientInfo: ClientInformation = {
        userAgent: 'Custom-Agent/1.0',
        ip: '10.0.0.1',
      };

      mockFindFirst.mockResolvedValue({
        ...mockTokenRecord,
        ipAddress: '10.0.0.1',
        userAgent: 'Custom-Agent/1.0',
      });
      mockJwtVerify.mockReturnValue(mockPayload);
      mockFindUnique.mockResolvedValue(mockUser);
      mockCreate.mockResolvedValue(mockNewTokenRecord);
      mockUpdate.mockResolvedValue(mockTokenRecord);

      await refreshToken('valid-token', customClientInfo);

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userAgent: 'Custom-Agent/1.0',
          ipAddress: '10.0.0.1',
        }),
      );
    });

    it('should not include user ID in failure logs when token not found', async () => {
      mockFindFirst.mockResolvedValue(null);

      await expect(
        refreshToken('invalid-token', mockClientInfo),
      ).rejects.toThrow();

      expect(mockLogger).toHaveBeenCalledWith(
        expect.not.objectContaining({
          userId: expect.anything(),
        }),
      );
    });

    it('should handle logging with IPv6 addresses', async () => {
      const ipv6ClientInfo: ClientInformation = {
        userAgent: mockClientInfo.userAgent,
        ip: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
      };

      mockFindFirst.mockResolvedValue({
        ...mockTokenRecord,
        ipAddress: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
      });
      mockJwtVerify.mockReturnValue(mockPayload);
      mockFindUnique.mockResolvedValue(mockUser);
      mockCreate.mockResolvedValue(mockNewTokenRecord);
      mockUpdate.mockResolvedValue(mockTokenRecord);

      const result = await refreshToken('valid-token', ipv6ClientInfo);

      expect(result).toBeDefined();
      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          ipAddress: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        }),
      );
    });
  });

  describe('JWT payload scenarios', () => {
    it('should handle custom JWT payload structures', async () => {
      const customPayload = {
        sub: 'user-456',
        jti: 'custom-jti',
        type: 'refresh',
        customField: 'value',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60,
      };

      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockJwtVerify.mockReturnValue(customPayload);
      mockFindUnique.mockResolvedValue({
        ...mockUser,
        id: 'user-456',
      });
      mockCreate.mockResolvedValue(mockNewTokenRecord);
      mockUpdate.mockResolvedValue(mockTokenRecord);

      const result = await refreshToken('custom-token', mockClientInfo);

      expect(result).toBeDefined();
      expect(mockFindUnique).toHaveBeenCalledWith({
        where: { id: 'user-456' },
      });
    });

    it('should handle missing sub in JWT payload', async () => {
      const invalidPayload = {
        jti: 'token-123',
        type: 'refresh',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60,
      };

      mockFindFirst.mockResolvedValue(mockTokenRecord);
      mockJwtVerify.mockReturnValue(invalidPayload);
      mockFindUnique.mockResolvedValue(null);

      await expect(
        refreshToken('invalid-payload-token', mockClientInfo),
      ).rejects.toMatchObject({
        message: 'User not found',
        statusCode: 404,
      });
    });
  });
});

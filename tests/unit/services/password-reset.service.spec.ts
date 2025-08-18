import {
  requestPasswordReset,
  resetPassword,
} from '../../../src/services/auth/password-reset.service';
import {
  RequestPasswordResetSchema,
  ResetPasswordSchema,
} from '../../../src/validators/password-reset.validator';
import {
  ClientInformation,
  EventTypes,
  ResetPasswordQuery,
} from '../../../src/utils/types';

jest.mock('../../../src/config/prisma-client', () => ({
  __esModule: true,
  default: {
    user: {
      findUnique: jest.fn(),
      update: jest.fn(),
    },
    passwordReset: {
      create: jest.fn(),
      findFirst: jest.fn(),
      updateMany: jest.fn(),
    },
  },
}));

jest.mock('../../../src/utils/logger', () => jest.fn());

jest.mock('../../../src/config/env', () => ({
  frontendUrl: 'http://localhost:3000/',
}));

jest.mock('../../../src/utils/send-email', () => ({
  sendEmail: jest.fn(),
}));

jest.mock('crypto', () => ({
  randomBytes: jest.fn(),
  createHash: jest.fn(),
}));

jest.mock('bcryptjs', () => ({
  hashSync: jest.fn(),
}));

import prismaClient from '../../../src/config/prisma-client';
import logger from '../../../src/utils/logger';
import { sendEmail } from '../../../src/utils/send-email';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';

const mockUserFindUnique = prismaClient.user.findUnique as jest.MockedFunction<
  typeof prismaClient.user.findUnique
>;
const mockUserUpdate = prismaClient.user.update as jest.MockedFunction<
  typeof prismaClient.user.update
>;
const mockPasswordResetCreate = prismaClient.passwordReset
  .create as jest.MockedFunction<typeof prismaClient.passwordReset.create>;
const mockPasswordResetFindFirst = prismaClient.passwordReset
  .findFirst as jest.MockedFunction<
  typeof prismaClient.passwordReset.findFirst
>;
const mockPasswordResetUpdateMany = prismaClient.passwordReset
  .updateMany as jest.MockedFunction<
  typeof prismaClient.passwordReset.updateMany
>;
const mockLogger = logger as jest.MockedFunction<typeof logger>;
const mockSendEmail = sendEmail as jest.MockedFunction<typeof sendEmail>;
const mockRandomBytes = crypto.randomBytes as jest.MockedFunction<
  typeof crypto.randomBytes
>;
const mockCreateHash = crypto.createHash as jest.MockedFunction<
  typeof crypto.createHash
>;
const mockHashSync = bcrypt.hashSync as jest.MockedFunction<
  typeof bcrypt.hashSync
>;

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

const mockPasswordResetToken = {
  id: 'reset-token-123',
  userId: 'user-123',
  resetTokenHash: 'token-hash-123',
  expiresAt: new Date(Date.now() + 60 * 60 * 1000),
  usedAt: null,
  createdAt: new Date(),
};

describe('requestPasswordReset', () => {
  beforeEach(() => {
    jest.clearAllMocks();

    const mockBuffer = Buffer.from('random-token-bytes');
    (mockRandomBytes as jest.Mock).mockReturnValue(mockBuffer);

    const mockHashInstance = {
      update: jest.fn().mockReturnThis(),
      digest: jest.fn().mockReturnValue('token-hash-123'),
    };
    (mockCreateHash as jest.Mock).mockReturnValue(
      mockHashInstance as unknown as crypto.Hash,
    );
  });

  describe('Successful password reset request scenarios', () => {
    it('should successfully request password reset for existing user', async () => {
      const requestData: RequestPasswordResetSchema = {
        email: 'test@example.com',
      };

      mockUserFindUnique.mockResolvedValue(mockUser);
      mockPasswordResetCreate.mockResolvedValue(mockPasswordResetToken);

      const result = await requestPasswordReset(requestData, mockClientInfo);

      expect(result).toEqual({
        message: "If account exists, we'll send the email",
      });

      expect(mockUserFindUnique).toHaveBeenCalledWith({
        where: { email: requestData.email },
      });
      expect(mockRandomBytes).toHaveBeenCalledWith(32);
      expect(mockPasswordResetCreate).toHaveBeenCalledWith({
        data: {
          userId: mockUser.id,
          resetTokenHash: 'token-hash-123',
          expiresAt: expect.any(Date),
        },
      });
      expect(mockSendEmail).toHaveBeenCalledWith(
        mockUser.email,
        'Password reset',
        'password-reset',
        'http://localhost:3000/reset-password?token=72616e646f6d2d746f6b656e2d6279746573&id=user-123',
      );
    });

    it('should generate secure random token', async () => {
      const requestData: RequestPasswordResetSchema = {
        email: 'test@example.com',
      };

      const customBuffer = Buffer.from('secure-random-bytes');
      (mockRandomBytes as jest.Mock).mockReturnValue(customBuffer);

      mockUserFindUnique.mockResolvedValue(mockUser);
      mockPasswordResetCreate.mockResolvedValue(mockPasswordResetToken);

      await requestPasswordReset(requestData, mockClientInfo);

      expect(mockRandomBytes).toHaveBeenCalledWith(32);
      expect(mockSendEmail).toHaveBeenCalledWith(
        mockUser.email,
        'Password reset',
        'password-reset',
        'http://localhost:3000/reset-password?token=7365637572652d72616e646f6d2d6279746573&id=user-123',
      );
    });

    it('should hash token before storing in database', async () => {
      const requestData: RequestPasswordResetSchema = {
        email: 'test@example.com',
      };

      const mockHashInstance = {
        update: jest.fn().mockReturnThis(),
        digest: jest.fn().mockReturnValue('unique-hash-456'),
      };
      (mockCreateHash as jest.Mock).mockReturnValue(
        mockHashInstance as unknown as crypto.Hash,
      );

      mockUserFindUnique.mockResolvedValue(mockUser);
      mockPasswordResetCreate.mockResolvedValue(mockPasswordResetToken);

      await requestPasswordReset(requestData, mockClientInfo);

      expect(mockCreateHash).toHaveBeenCalledWith('sha256');
      expect(mockHashInstance.update).toHaveBeenCalledWith(
        '72616e646f6d2d746f6b656e2d6279746573',
      );
      expect(mockHashInstance.digest).toHaveBeenCalledWith('hex');
      expect(mockPasswordResetCreate).toHaveBeenCalledWith({
        data: {
          userId: mockUser.id,
          resetTokenHash: 'unique-hash-456',
          expiresAt: expect.any(Date),
        },
      });
    });

    it('should set correct expiration time for reset token', async () => {
      const requestData: RequestPasswordResetSchema = {
        email: 'test@example.com',
      };

      mockUserFindUnique.mockResolvedValue(mockUser);
      mockPasswordResetCreate.mockResolvedValue(mockPasswordResetToken);

      const beforeTime = Date.now();
      await requestPasswordReset(requestData, mockClientInfo);
      const afterTime = Date.now();

      const createCall = mockPasswordResetCreate.mock.calls[0][0];
      const expiresAt = (createCall.data.expiresAt as Date).getTime();
      const expectedMin = beforeTime + 60 * 60 * 1000;
      const expectedMax = afterTime + 60 * 60 * 1000;

      expect(expiresAt).toBeGreaterThanOrEqual(expectedMin);
      expect(expiresAt).toBeLessThanOrEqual(expectedMax);
    });

    it('should log successful password reset request', async () => {
      const requestData: RequestPasswordResetSchema = {
        email: 'test@example.com',
      };

      mockUserFindUnique.mockResolvedValue(mockUser);
      mockPasswordResetCreate.mockResolvedValue(mockPasswordResetToken);

      await requestPasswordReset(requestData, mockClientInfo);

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockUser.id,
          eventType: EventTypes.PASSWORD_RESET_REQUEST,
          userAgent: mockClientInfo.userAgent,
          ipAddress: mockClientInfo.ip,
          metadata: JSON.stringify({
            message: 'Password reset requested',
          }),
        }),
      );
    });
  });

  describe('User not found scenarios', () => {
    it('should return success message even when user does not exist', async () => {
      const requestData: RequestPasswordResetSchema = {
        email: 'nonexistent@example.com',
      };

      mockUserFindUnique.mockResolvedValue(null);

      const result = await requestPasswordReset(requestData, mockClientInfo);

      expect(result).toEqual({
        message: "If account exists, we'll send the email",
      });

      expect(mockPasswordResetCreate).not.toHaveBeenCalled();
      expect(mockSendEmail).not.toHaveBeenCalled();
      expect(mockLogger).not.toHaveBeenCalled();
    });

    it('should not generate token when user does not exist', async () => {
      const requestData: RequestPasswordResetSchema = {
        email: 'nonexistent@example.com',
      };

      mockUserFindUnique.mockResolvedValue(null);

      await requestPasswordReset(requestData, mockClientInfo);

      expect(mockRandomBytes).not.toHaveBeenCalled();
      expect(mockCreateHash).not.toHaveBeenCalled();
    });

    it('should not send email when user does not exist', async () => {
      const requestData: RequestPasswordResetSchema = {
        email: 'fake@example.com',
      };

      mockUserFindUnique.mockResolvedValue(null);

      await requestPasswordReset(requestData, mockClientInfo);

      expect(mockSendEmail).not.toHaveBeenCalled();
    });
  });

  describe('Database error scenarios', () => {
    it('should throw 500 error when token creation fails', async () => {
      const requestData: RequestPasswordResetSchema = {
        email: 'test@example.com',
      };

      mockUserFindUnique.mockResolvedValue(mockUser);
      mockPasswordResetCreate.mockRejectedValue(new Error('Database error'));

      await expect(
        requestPasswordReset(requestData, mockClientInfo),
      ).rejects.toMatchObject({
        message: 'Failed to create token',
        statusCode: 500,
      });

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockUser.id,
          eventType: EventTypes.PASSWORD_RESET_FAIL,
          metadata: JSON.stringify({
            message: 'Failed to create token',
          }),
        }),
      );
    });

    it('should handle database connection errors during user lookup', async () => {
      const requestData: RequestPasswordResetSchema = {
        email: 'test@example.com',
      };

      mockUserFindUnique.mockRejectedValue(
        new Error('Database connection error'),
      );

      await expect(
        requestPasswordReset(requestData, mockClientInfo),
      ).rejects.toThrow('Database connection error');
    });

    it('should not send email when token creation fails', async () => {
      const requestData: RequestPasswordResetSchema = {
        email: 'test@example.com',
      };

      mockUserFindUnique.mockResolvedValue(mockUser);
      mockPasswordResetCreate.mockRejectedValue(new Error('Database error'));

      await expect(
        requestPasswordReset(requestData, mockClientInfo),
      ).rejects.toThrow();

      expect(mockSendEmail).not.toHaveBeenCalled();
    });
  });

  describe('Edge cases and security scenarios', () => {
    it('should handle empty client information gracefully', async () => {
      const requestData: RequestPasswordResetSchema = {
        email: 'test@example.com',
      };

      const emptyClientInfo: ClientInformation = {
        userAgent: '',
        ip: '',
      };

      mockUserFindUnique.mockResolvedValue(mockUser);
      mockPasswordResetCreate.mockResolvedValue(mockPasswordResetToken);

      const result = await requestPasswordReset(requestData, emptyClientInfo);

      expect(result).toBeDefined();
      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userAgent: '',
          ipAddress: '',
        }),
      );
    });

    it('should handle special characters in email', async () => {
      const requestData: RequestPasswordResetSchema = {
        email: 'test+special@example.com',
      };

      const userWithSpecialEmail = {
        ...mockUser,
        email: 'test+special@example.com',
      };

      mockUserFindUnique.mockResolvedValue(userWithSpecialEmail);
      mockPasswordResetCreate.mockResolvedValue(mockPasswordResetToken);

      const result = await requestPasswordReset(requestData, mockClientInfo);

      expect(result).toBeDefined();
      expect(mockUserFindUnique).toHaveBeenCalledWith({
        where: { email: 'test+special@example.com' },
      });
    });

    it('should handle case-sensitive email checking', async () => {
      const requestData: RequestPasswordResetSchema = {
        email: 'TEST@EXAMPLE.COM',
      };

      const userWithUpperEmail = {
        ...mockUser,
        email: 'TEST@EXAMPLE.COM',
      };

      mockUserFindUnique.mockResolvedValue(userWithUpperEmail);
      mockPasswordResetCreate.mockResolvedValue(mockPasswordResetToken);

      const result = await requestPasswordReset(requestData, mockClientInfo);

      expect(result).toBeDefined();
      expect(mockUserFindUnique).toHaveBeenCalledWith({
        where: { email: 'TEST@EXAMPLE.COM' },
      });
    });

    it('should handle long user agent strings', async () => {
      const requestData: RequestPasswordResetSchema = {
        email: 'test@example.com',
      };

      const longUserAgent =
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 EdgeAgent/91.0.864.59 Very-Long-Browser-String-That-Exceeds-Normal-Limits';
      const clientInfoWithLongUA: ClientInformation = {
        userAgent: longUserAgent,
        ip: mockClientInfo.ip,
      };

      mockUserFindUnique.mockResolvedValue(mockUser);
      mockPasswordResetCreate.mockResolvedValue(mockPasswordResetToken);

      const result = await requestPasswordReset(
        requestData,
        clientInfoWithLongUA,
      );

      expect(result).toBeDefined();
      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userAgent: longUserAgent,
        }),
      );
    });

    it('should handle IPv6 addresses', async () => {
      const requestData: RequestPasswordResetSchema = {
        email: 'test@example.com',
      };

      const ipv6ClientInfo: ClientInformation = {
        userAgent: mockClientInfo.userAgent,
        ip: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
      };

      mockUserFindUnique.mockResolvedValue(mockUser);
      mockPasswordResetCreate.mockResolvedValue(mockPasswordResetToken);

      const result = await requestPasswordReset(requestData, ipv6ClientInfo);

      expect(result).toBeDefined();
      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          ipAddress: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        }),
      );
    });
  });

  describe('Token generation scenarios', () => {
    it('should generate different tokens for multiple requests', async () => {
      const requestData: RequestPasswordResetSchema = {
        email: 'test@example.com',
      };

      const buffer1 = Buffer.from('token-bytes-1');
      const buffer2 = Buffer.from('token-bytes-2');

      (mockRandomBytes as jest.Mock)
        .mockReturnValueOnce(buffer1)
        .mockReturnValueOnce(buffer2);

      mockUserFindUnique.mockResolvedValue(mockUser);
      mockPasswordResetCreate.mockResolvedValue(mockPasswordResetToken);

      await requestPasswordReset(requestData, mockClientInfo);
      await requestPasswordReset(requestData, mockClientInfo);

      expect(mockSendEmail).toHaveBeenNthCalledWith(
        1,
        mockUser.email,
        'Password reset',
        'password-reset',
        'http://localhost:3000/reset-password?token=746f6b656e2d62797465732d31&id=user-123',
      );
      expect(mockSendEmail).toHaveBeenNthCalledWith(
        2,
        mockUser.email,
        'Password reset',
        'password-reset',
        'http://localhost:3000/reset-password?token=746f6b656e2d62797465732d32&id=user-123',
      );
    });

    it('should use SHA256 for token hashing', async () => {
      const requestData: RequestPasswordResetSchema = {
        email: 'test@example.com',
      };

      mockUserFindUnique.mockResolvedValue(mockUser);
      mockPasswordResetCreate.mockResolvedValue(mockPasswordResetToken);

      await requestPasswordReset(requestData, mockClientInfo);

      expect(mockCreateHash).toHaveBeenCalledWith('sha256');
    });
  });

  describe('Performance and concurrency scenarios', () => {
    it('should handle concurrent password reset requests', async () => {
      const requestData1: RequestPasswordResetSchema = {
        email: 'user1@example.com',
      };
      const requestData2: RequestPasswordResetSchema = {
        email: 'user2@example.com',
      };

      mockUserFindUnique.mockResolvedValue(mockUser);
      mockPasswordResetCreate.mockResolvedValue(mockPasswordResetToken);

      const promises = [
        requestPasswordReset(requestData1, mockClientInfo),
        requestPasswordReset(requestData2, mockClientInfo),
      ];

      const results = await Promise.all(promises);

      expect(results).toHaveLength(2);
      results.forEach((result) => {
        expect(result).toEqual({
          message: "If account exists, we'll send the email",
        });
      });
    });

    it('should handle slow database responses', async () => {
      const requestData: RequestPasswordResetSchema = {
        email: 'test@example.com',
      };

      const slowPromise = new Promise<typeof mockUser>((resolve) => {
        setTimeout(() => resolve(mockUser), 100);
      });
      mockUserFindUnique.mockImplementation(() => slowPromise as never);
      mockPasswordResetCreate.mockResolvedValue(mockPasswordResetToken);

      const startTime = Date.now();
      const result = await requestPasswordReset(requestData, mockClientInfo);
      const endTime = Date.now();

      expect(result).toBeDefined();
      expect(endTime - startTime).toBeGreaterThanOrEqual(100);
    });
  });
});

describe('resetPassword', () => {
  beforeEach(() => {
    jest.clearAllMocks();

    const mockHashInstance = {
      update: jest.fn().mockReturnThis(),
      digest: jest.fn().mockReturnValue('token-hash-123'),
    };
    (mockCreateHash as jest.Mock).mockReturnValue(
      mockHashInstance as unknown as crypto.Hash,
    );

    mockHashSync.mockReturnValue('$2a$12$newhashedpassword');
  });

  describe('Successful password reset scenarios', () => {
    it('should successfully reset password with valid token', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'NewPassword123!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'valid-reset-token',
        userId: 'user-123',
      };

      mockPasswordResetFindFirst.mockResolvedValue(mockPasswordResetToken);
      mockPasswordResetUpdateMany.mockResolvedValue({ count: 1 });
      mockUserUpdate.mockResolvedValue({
        ...mockUser,
        passwordHash: '$2a$12$newhashedpassword',
      });

      const result = await resetPassword(resetData, resetQuery, mockClientInfo);

      expect(result).toEqual({
        message: 'Successfully updated password',
      });

      expect(mockPasswordResetFindFirst).toHaveBeenCalledWith({
        where: { resetTokenHash: 'token-hash-123', userId: 'user-123' },
      });
      expect(mockHashSync).toHaveBeenCalledWith('NewPassword123!', 12);
      expect(mockUserUpdate).toHaveBeenCalledWith({
        where: { id: 'user-123' },
        data: { passwordHash: '$2a$12$newhashedpassword' },
      });
    });

    it('should hash incoming token before lookup', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'NewPassword123!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'test-token-456',
        userId: 'user-123',
      };

      const mockHashInstance = {
        update: jest.fn().mockReturnThis(),
        digest: jest.fn().mockReturnValue('unique-hash-789'),
      };
      (mockCreateHash as jest.Mock).mockReturnValue(
        mockHashInstance as unknown as crypto.Hash,
      );

      mockPasswordResetFindFirst.mockResolvedValue(mockPasswordResetToken);
      mockPasswordResetUpdateMany.mockResolvedValue({ count: 1 });
      mockUserUpdate.mockResolvedValue(mockUser);

      await resetPassword(resetData, resetQuery, mockClientInfo);

      expect(mockCreateHash).toHaveBeenCalledWith('sha256');
      expect(mockHashInstance.update).toHaveBeenCalledWith('test-token-456');
      expect(mockHashInstance.digest).toHaveBeenCalledWith('hex');
      expect(mockPasswordResetFindFirst).toHaveBeenCalledWith({
        where: { resetTokenHash: 'unique-hash-789', userId: 'user-123' },
      });
    });

    it('should mark token as used', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'NewPassword123!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'valid-token',
        userId: 'user-123',
      };

      mockPasswordResetFindFirst.mockResolvedValue(mockPasswordResetToken);
      mockPasswordResetUpdateMany.mockResolvedValue({ count: 1 });
      mockUserUpdate.mockResolvedValue(mockUser);

      await resetPassword(resetData, resetQuery, mockClientInfo);

      expect(mockPasswordResetUpdateMany).toHaveBeenCalledWith({
        where: { id: mockPasswordResetToken.id, usedAt: null },
        data: { usedAt: expect.any(Date) },
      });
    });

    it('should hash new password with correct salt rounds', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'SecurePassword456!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'valid-token',
        userId: 'user-123',
      };

      mockPasswordResetFindFirst.mockResolvedValue(mockPasswordResetToken);
      mockPasswordResetUpdateMany.mockResolvedValue({ count: 1 });
      mockUserUpdate.mockResolvedValue(mockUser);

      await resetPassword(resetData, resetQuery, mockClientInfo);

      expect(mockHashSync).toHaveBeenCalledWith('SecurePassword456!', 12);
    });

    it('should log successful password reset', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'NewPassword123!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'valid-token',
        userId: 'user-123',
      };

      mockPasswordResetFindFirst.mockResolvedValue(mockPasswordResetToken);
      mockPasswordResetUpdateMany.mockResolvedValue({ count: 1 });
      mockUserUpdate.mockResolvedValue(mockUser);

      await resetPassword(resetData, resetQuery, mockClientInfo);

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-123',
          eventType: EventTypes.PASSWORD_RESET_SUCCESS,
          userAgent: mockClientInfo.userAgent,
          ipAddress: mockClientInfo.ip,
          metadata: JSON.stringify({
            message: 'Successfully updated password',
          }),
        }),
      );
    });
  });

  describe('Invalid token scenarios', () => {
    it('should throw 401 error when reset token is not found', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'NewPassword123!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'invalid-token',
        userId: 'user-123',
      };

      mockPasswordResetFindFirst.mockResolvedValue(null);

      await expect(
        resetPassword(resetData, resetQuery, mockClientInfo),
      ).rejects.toMatchObject({
        message: 'Reset token is not valid',
        statusCode: 401,
      });

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: EventTypes.PASSWORD_RESET_FAIL,
          metadata: JSON.stringify({
            message: 'Reset token is not valid',
          }),
        }),
      );
    });

    it('should throw 401 error when reset token is expired', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'NewPassword123!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'expired-token',
        userId: 'user-123',
      };

      const expiredToken = {
        ...mockPasswordResetToken,
        expiresAt: new Date(Date.now() - 60 * 60 * 1000),
      };

      mockPasswordResetFindFirst.mockResolvedValue(expiredToken);

      await expect(
        resetPassword(resetData, resetQuery, mockClientInfo),
      ).rejects.toMatchObject({
        message: 'Reset token expired',
        statusCode: 401,
      });

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-123',
          eventType: EventTypes.PASSWORD_RESET_FAIL,
          metadata: JSON.stringify({
            message: 'Reset token expired',
          }),
        }),
      );
    });

    it('should throw 401 error when reset token is already used', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'NewPassword123!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'used-token',
        userId: 'user-123',
      };

      mockPasswordResetFindFirst.mockResolvedValue(mockPasswordResetToken);
      mockPasswordResetUpdateMany.mockResolvedValue({ count: 0 });

      await expect(
        resetPassword(resetData, resetQuery, mockClientInfo),
      ).rejects.toMatchObject({
        message: 'Reset token already used',
        statusCode: 401,
      });

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-123',
          eventType: EventTypes.PASSWORD_RESET_FAIL,
          metadata: JSON.stringify({
            message: 'Reset token already used',
          }),
        }),
      );
    });

    it('should not proceed with password update when token is invalid', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'NewPassword123!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'invalid-token',
        userId: 'user-123',
      };

      mockPasswordResetFindFirst.mockResolvedValue(null);

      await expect(
        resetPassword(resetData, resetQuery, mockClientInfo),
      ).rejects.toThrow();

      expect(mockPasswordResetUpdateMany).not.toHaveBeenCalled();
      expect(mockUserUpdate).not.toHaveBeenCalled();
    });

    it('should not proceed with password update when token is expired', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'NewPassword123!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'expired-token',
        userId: 'user-123',
      };

      const expiredToken = {
        ...mockPasswordResetToken,
        expiresAt: new Date(Date.now() - 1000),
      };

      mockPasswordResetFindFirst.mockResolvedValue(expiredToken);

      await expect(
        resetPassword(resetData, resetQuery, mockClientInfo),
      ).rejects.toThrow();

      expect(mockPasswordResetUpdateMany).not.toHaveBeenCalled();
      expect(mockUserUpdate).not.toHaveBeenCalled();
    });
  });

  describe('Database error scenarios', () => {
    it('should throw 500 error when password update fails', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'NewPassword123!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'valid-token',
        userId: 'user-123',
      };

      mockPasswordResetFindFirst.mockResolvedValue(mockPasswordResetToken);
      mockPasswordResetUpdateMany.mockResolvedValue({ count: 1 });
      mockUserUpdate.mockRejectedValue(new Error('Database error'));

      await expect(
        resetPassword(resetData, resetQuery, mockClientInfo),
      ).rejects.toMatchObject({
        message: 'Failed to updated password',
        statusCode: 500,
      });

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-123',
          eventType: EventTypes.PASSWORD_RESET_FAIL,
          metadata: JSON.stringify({
            message: 'Failed to updated password',
          }),
        }),
      );
    });

    it('should handle database connection errors during token lookup', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'NewPassword123!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'valid-token',
        userId: 'user-123',
      };

      mockPasswordResetFindFirst.mockRejectedValue(
        new Error('Database connection error'),
      );

      await expect(
        resetPassword(resetData, resetQuery, mockClientInfo),
      ).rejects.toThrow('Database connection error');
    });

    it('should handle database connection errors during token update', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'NewPassword123!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'valid-token',
        userId: 'user-123',
      };

      mockPasswordResetFindFirst.mockResolvedValue(mockPasswordResetToken);
      mockPasswordResetUpdateMany.mockRejectedValue(new Error('Update failed'));

      await expect(
        resetPassword(resetData, resetQuery, mockClientInfo),
      ).rejects.toThrow('Update failed');
    });
  });

  describe('Edge cases and security scenarios', () => {
    it('should handle empty client information gracefully', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'NewPassword123!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'valid-token',
        userId: 'user-123',
      };

      const emptyClientInfo: ClientInformation = {
        userAgent: '',
        ip: '',
      };

      mockPasswordResetFindFirst.mockResolvedValue(mockPasswordResetToken);
      mockPasswordResetUpdateMany.mockResolvedValue({ count: 1 });
      mockUserUpdate.mockResolvedValue(mockUser);

      const result = await resetPassword(
        resetData,
        resetQuery,
        emptyClientInfo,
      );

      expect(result).toBeDefined();
      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userAgent: '',
          ipAddress: '',
        }),
      );
    });

    it('should handle very long passwords', async () => {
      const longPassword = 'P@ssw0rd!' + 'a'.repeat(1000);
      const resetData: ResetPasswordSchema = {
        newPassword: longPassword,
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'valid-token',
        userId: 'user-123',
      };

      mockPasswordResetFindFirst.mockResolvedValue(mockPasswordResetToken);
      mockPasswordResetUpdateMany.mockResolvedValue({ count: 1 });
      mockUserUpdate.mockResolvedValue(mockUser);

      const result = await resetPassword(resetData, resetQuery, mockClientInfo);

      expect(result).toBeDefined();
      expect(mockHashSync).toHaveBeenCalledWith(longPassword, 12);
    });

    it('should handle passwords with special characters', async () => {
      const specialPassword = 'P@ssw0rd!#$%^&*()_+-=[]{}|;:,.<>?';
      const resetData: ResetPasswordSchema = {
        newPassword: specialPassword,
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'valid-token',
        userId: 'user-123',
      };

      mockPasswordResetFindFirst.mockResolvedValue(mockPasswordResetToken);
      mockPasswordResetUpdateMany.mockResolvedValue({ count: 1 });
      mockUserUpdate.mockResolvedValue(mockUser);

      const result = await resetPassword(resetData, resetQuery, mockClientInfo);

      expect(result).toBeDefined();
      expect(mockHashSync).toHaveBeenCalledWith(specialPassword, 12);
    });

    it('should handle long user agent strings', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'NewPassword123!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'valid-token',
        userId: 'user-123',
      };

      const longUserAgent =
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 EdgeAgent/91.0.864.59 Very-Long-Browser-String-That-Exceeds-Normal-Limits';
      const clientInfoWithLongUA: ClientInformation = {
        userAgent: longUserAgent,
        ip: mockClientInfo.ip,
      };

      mockPasswordResetFindFirst.mockResolvedValue(mockPasswordResetToken);
      mockPasswordResetUpdateMany.mockResolvedValue({ count: 1 });
      mockUserUpdate.mockResolvedValue(mockUser);

      const result = await resetPassword(
        resetData,
        resetQuery,
        clientInfoWithLongUA,
      );

      expect(result).toBeDefined();
      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userAgent: longUserAgent,
        }),
      );
    });

    it('should handle IPv6 addresses', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'NewPassword123!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'valid-token',
        userId: 'user-123',
      };

      const ipv6ClientInfo: ClientInformation = {
        userAgent: mockClientInfo.userAgent,
        ip: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
      };

      mockPasswordResetFindFirst.mockResolvedValue(mockPasswordResetToken);
      mockPasswordResetUpdateMany.mockResolvedValue({ count: 1 });
      mockUserUpdate.mockResolvedValue(mockUser);

      const result = await resetPassword(resetData, resetQuery, ipv6ClientInfo);

      expect(result).toBeDefined();
      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          ipAddress: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        }),
      );
    });

    it('should handle different user IDs', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'NewPassword123!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'valid-token',
        userId: 'different-user-456',
      };

      const tokenForDifferentUser = {
        ...mockPasswordResetToken,
        userId: 'different-user-456',
      };

      mockPasswordResetFindFirst.mockResolvedValue(tokenForDifferentUser);
      mockPasswordResetUpdateMany.mockResolvedValue({ count: 1 });
      mockUserUpdate.mockResolvedValue({
        ...mockUser,
        id: 'different-user-456',
      });

      const result = await resetPassword(resetData, resetQuery, mockClientInfo);

      expect(result).toBeDefined();
      expect(mockPasswordResetFindFirst).toHaveBeenCalledWith({
        where: {
          resetTokenHash: 'token-hash-123',
          userId: 'different-user-456',
        },
      });
      expect(mockUserUpdate).toHaveBeenCalledWith({
        where: { id: 'different-user-456' },
        data: { passwordHash: '$2a$12$newhashedpassword' },
      });
    });
  });

  describe('Token expiration edge cases', () => {
    it('should handle token that expires exactly now', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'NewPassword123!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'expiring-now-token',
        userId: 'user-123',
      };

      const tokenExpiringNow = {
        ...mockPasswordResetToken,
        expiresAt: new Date(Date.now() - 1),
      };

      mockPasswordResetFindFirst.mockResolvedValue(tokenExpiringNow);

      await expect(
        resetPassword(resetData, resetQuery, mockClientInfo),
      ).rejects.toMatchObject({
        message: 'Reset token expired',
        statusCode: 401,
      });
    });

    it('should handle token that expires in future', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'NewPassword123!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'future-token',
        userId: 'user-123',
      };

      const futureToken = {
        ...mockPasswordResetToken,
        expiresAt: new Date(Date.now() + 30 * 60 * 1000),
      };

      mockPasswordResetFindFirst.mockResolvedValue(futureToken);
      mockPasswordResetUpdateMany.mockResolvedValue({ count: 1 });
      mockUserUpdate.mockResolvedValue(mockUser);

      const result = await resetPassword(resetData, resetQuery, mockClientInfo);

      expect(result).toBeDefined();
    });
  });

  describe('Password hashing scenarios', () => {
    it('should use different hash for same password on multiple resets', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'SamePassword123!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'valid-token',
        userId: 'user-123',
      };

      mockHashSync
        .mockReturnValueOnce('$2a$12$hash1')
        .mockReturnValueOnce('$2a$12$hash2');

      mockPasswordResetFindFirst.mockResolvedValue(mockPasswordResetToken);
      mockPasswordResetUpdateMany.mockResolvedValue({ count: 1 });
      mockUserUpdate.mockResolvedValue(mockUser);

      await resetPassword(resetData, resetQuery, mockClientInfo);
      await resetPassword(resetData, resetQuery, mockClientInfo);

      expect(mockHashSync).toHaveBeenCalledTimes(2);
      expect(mockUserUpdate).toHaveBeenNthCalledWith(1, {
        where: { id: 'user-123' },
        data: { passwordHash: '$2a$12$hash1' },
      });
      expect(mockUserUpdate).toHaveBeenNthCalledWith(2, {
        where: { id: 'user-123' },
        data: { passwordHash: '$2a$12$hash2' },
      });
    });

    it('should handle bcrypt hashing errors', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'NewPassword123!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'valid-token',
        userId: 'user-123',
      };

      mockPasswordResetFindFirst.mockResolvedValue(mockPasswordResetToken);
      mockPasswordResetUpdateMany.mockResolvedValue({ count: 1 });
      mockHashSync.mockImplementation(() => {
        throw new Error('Bcrypt error');
      });

      await expect(
        resetPassword(resetData, resetQuery, mockClientInfo),
      ).rejects.toThrow('Bcrypt error');

      expect(mockUserUpdate).not.toHaveBeenCalled();
    });

    it('should always use salt rounds of 12', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'NewPassword123!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'valid-token',
        userId: 'user-123',
      };

      mockPasswordResetFindFirst.mockResolvedValue(mockPasswordResetToken);
      mockPasswordResetUpdateMany.mockResolvedValue({ count: 1 });
      mockUserUpdate.mockResolvedValue(mockUser);

      await resetPassword(resetData, resetQuery, mockClientInfo);

      expect(mockHashSync).toHaveBeenCalledWith('NewPassword123!', 12);
    });
  });

  describe('Performance and concurrency scenarios', () => {
    it('should handle concurrent password reset attempts', async () => {
      const resetData1: ResetPasswordSchema = {
        newPassword: 'Password1!',
      };

      const resetData2: ResetPasswordSchema = {
        newPassword: 'Password2!',
      };

      const resetQuery1: ResetPasswordQuery = {
        token: 'token1',
        userId: 'user-123',
      };

      const resetQuery2: ResetPasswordQuery = {
        token: 'token2',
        userId: 'user-456',
      };

      mockPasswordResetFindFirst.mockResolvedValue(mockPasswordResetToken);
      mockPasswordResetUpdateMany.mockResolvedValue({ count: 1 });
      mockUserUpdate.mockResolvedValue(mockUser);

      const promises = [
        resetPassword(resetData1, resetQuery1, mockClientInfo),
        resetPassword(resetData2, resetQuery2, mockClientInfo),
      ];

      const results = await Promise.all(promises);

      expect(results).toHaveLength(2);
      results.forEach((result) => {
        expect(result).toEqual({
          message: 'Successfully updated password',
        });
      });
    });

    it('should handle slow database responses', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'NewPassword123!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'slow-token',
        userId: 'user-123',
      };

      const slowPromise = new Promise<typeof mockPasswordResetToken>(
        (resolve) => {
          setTimeout(() => resolve(mockPasswordResetToken), 100);
        },
      );
      mockPasswordResetFindFirst.mockImplementation(() => slowPromise as never);
      mockPasswordResetUpdateMany.mockResolvedValue({ count: 1 });
      mockUserUpdate.mockResolvedValue(mockUser);

      const startTime = Date.now();
      const result = await resetPassword(resetData, resetQuery, mockClientInfo);
      const endTime = Date.now();

      expect(result).toBeDefined();
      expect(endTime - startTime).toBeGreaterThanOrEqual(100);
    });
  });

  describe('Logging scenarios', () => {
    it('should not include user ID in logs when token is invalid', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'NewPassword123!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'invalid-token',
        userId: 'user-123',
      };

      mockPasswordResetFindFirst.mockResolvedValue(null);

      await expect(
        resetPassword(resetData, resetQuery, mockClientInfo),
      ).rejects.toThrow();

      expect(mockLogger).toHaveBeenCalledWith(
        expect.not.objectContaining({
          userId: expect.anything(),
        }),
      );
    });

    it('should include user ID in logs when token is expired', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'NewPassword123!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'expired-token',
        userId: 'user-123',
      };

      const expiredToken = {
        ...mockPasswordResetToken,
        expiresAt: new Date(Date.now() - 1000),
      };

      mockPasswordResetFindFirst.mockResolvedValue(expiredToken);

      await expect(
        resetPassword(resetData, resetQuery, mockClientInfo),
      ).rejects.toThrow();

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-123',
        }),
      );
    });

    it('should include correct client information in all logs', async () => {
      const resetData: ResetPasswordSchema = {
        newPassword: 'NewPassword123!',
      };

      const resetQuery: ResetPasswordQuery = {
        token: 'valid-token',
        userId: 'user-123',
      };

      const customClientInfo: ClientInformation = {
        userAgent: 'Custom-Agent/1.0',
        ip: '10.0.0.1',
      };

      mockPasswordResetFindFirst.mockResolvedValue(mockPasswordResetToken);
      mockPasswordResetUpdateMany.mockResolvedValue({ count: 1 });
      mockUserUpdate.mockResolvedValue(mockUser);

      await resetPassword(resetData, resetQuery, customClientInfo);

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userAgent: 'Custom-Agent/1.0',
          ipAddress: '10.0.0.1',
        }),
      );
    });
  });
});

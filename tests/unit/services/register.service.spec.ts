import { registerUser } from '../../../src/services/auth/register.service';
import { UserAuthenticationSchema } from '../../../src/validators/auth.validator';
import { ClientInformation, EventTypes } from '../../../src/utils/types';

jest.mock('../../../src/config/prisma-client', () => ({
  __esModule: true,
  default: {
    user: {
      findUnique: jest.fn(),
      create: jest.fn(),
    },
  },
}));

jest.mock('../../../src/utils/logger', () => jest.fn());

jest.mock('bcryptjs', () => ({
  hashSync: jest.fn(),
}));

import prismaClient from '../../../src/config/prisma-client';
import logger from '../../../src/utils/logger';
import bcrypt from 'bcryptjs';

const mockFindUnique = prismaClient.user.findUnique as jest.MockedFunction<
  typeof prismaClient.user.findUnique
>;
const mockCreate = prismaClient.user.create as jest.MockedFunction<
  typeof prismaClient.user.create
>;
const mockLogger = logger as jest.MockedFunction<typeof logger>;
const mockHashSync = bcrypt.hashSync as jest.MockedFunction<
  typeof bcrypt.hashSync
>;

const mockClientInfo: ClientInformation = {
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
  ip: '192.168.1.1',
};

const mockAuthData: UserAuthenticationSchema = {
  email: 'test@example.com',
  password: 'Password123!',
};

const mockCreatedUser = {
  id: 'user-123',
  email: 'test@example.com',
  passwordHash: '$2a$12$hashedpassword',
  isActive: true,
  createdAt: new Date('2024-01-01T00:00:00Z'),
  updatedAt: new Date('2024-01-01T00:00:00Z'),
  lastLoginAt: null,
};

describe('registerUser', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockHashSync.mockReturnValue('$2a$12$hashedpassword');
  });

  describe('Successful registration scenarios', () => {
    it('should successfully register new user with valid data', async () => {
      mockFindUnique.mockResolvedValue(null);
      mockCreate.mockResolvedValue(mockCreatedUser);

      const result = await registerUser(mockAuthData, mockClientInfo);

      expect(result).toEqual({
        id: mockCreatedUser.id,
        email: mockCreatedUser.email,
        isActive: mockCreatedUser.isActive,
        createdAt: mockCreatedUser.createdAt,
        updatedAt: mockCreatedUser.updatedAt,
        lastLoginAt: mockCreatedUser.lastLoginAt,
      });

      expect(mockFindUnique).toHaveBeenCalledWith({
        where: { email: mockAuthData.email },
      });
      expect(mockHashSync).toHaveBeenCalledWith(mockAuthData.password, 12);
      expect(mockCreate).toHaveBeenCalledWith({
        data: {
          email: mockAuthData.email,
          passwordHash: '$2a$12$hashedpassword',
        },
      });
    });

    it('should hash password with correct salt rounds', async () => {
      mockFindUnique.mockResolvedValue(null);
      mockCreate.mockResolvedValue(mockCreatedUser);

      await registerUser(mockAuthData, mockClientInfo);

      expect(mockHashSync).toHaveBeenCalledWith(mockAuthData.password, 12);
    });

    it('should exclude password hash from returned user object', async () => {
      mockFindUnique.mockResolvedValue(null);
      mockCreate.mockResolvedValue(mockCreatedUser);

      const result = await registerUser(mockAuthData, mockClientInfo);

      expect(result).not.toHaveProperty('passwordHash');
      expect(result).toEqual({
        id: mockCreatedUser.id,
        email: mockCreatedUser.email,
        isActive: mockCreatedUser.isActive,
        createdAt: mockCreatedUser.createdAt,
        updatedAt: mockCreatedUser.updatedAt,
        lastLoginAt: mockCreatedUser.lastLoginAt,
      });
    });

    it('should log successful user creation', async () => {
      mockFindUnique.mockResolvedValue(null);
      mockCreate.mockResolvedValue(mockCreatedUser);

      await registerUser(mockAuthData, mockClientInfo);

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: mockCreatedUser.id,
          eventType: EventTypes.AUTH_SUCCESS,
          userAgent: mockClientInfo.userAgent,
          ipAddress: mockClientInfo.ip,
          metadata: JSON.stringify({
            message: 'User created successfully',
          }),
        }),
      );
    });
  });

  describe('User already exists scenarios', () => {
    it('should throw 409 error when user already exists', async () => {
      const existingUser = {
        id: 'existing-user-123',
        email: mockAuthData.email,
        passwordHash: '$2a$12$existingpassword',
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
        lastLoginAt: null,
      };

      mockFindUnique.mockResolvedValue(existingUser);

      await expect(
        registerUser(mockAuthData, mockClientInfo),
      ).rejects.toMatchObject({
        message: 'User with that email already exists',
        statusCode: 409,
      });

      expect(mockCreate).not.toHaveBeenCalled();
      expect(mockHashSync).not.toHaveBeenCalled();
    });

    it('should log failed registration attempt when user exists', async () => {
      const existingUser = { ...mockCreatedUser };
      mockFindUnique.mockResolvedValue(existingUser);

      await expect(
        registerUser(mockAuthData, mockClientInfo),
      ).rejects.toThrow();

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: EventTypes.AUTH_FAILED,
          userAgent: mockClientInfo.userAgent,
          ipAddress: mockClientInfo.ip,
          metadata: JSON.stringify({
            message: 'User with that email already exists',
          }),
        }),
      );
    });

    it('should not include user ID in logs when user already exists', async () => {
      const existingUser = { ...mockCreatedUser };
      mockFindUnique.mockResolvedValue(existingUser);

      await expect(
        registerUser(mockAuthData, mockClientInfo),
      ).rejects.toThrow();

      expect(mockLogger).toHaveBeenCalledWith(
        expect.not.objectContaining({
          userId: expect.anything(),
        }),
      );
    });
  });

  describe('Database error scenarios', () => {
    it('should throw 500 error when user creation fails', async () => {
      mockFindUnique.mockResolvedValue(null);
      mockCreate.mockRejectedValue(new Error('Database error'));

      await expect(
        registerUser(mockAuthData, mockClientInfo),
      ).rejects.toMatchObject({
        message: 'Failed to create user',
        statusCode: 500,
      });

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: EventTypes.DB_ERROR,
          userAgent: mockClientInfo.userAgent,
          ipAddress: mockClientInfo.ip,
          metadata: JSON.stringify({
            message: 'Failed to create user',
          }),
        }),
      );
    });

    it('should handle database connection errors during user lookup', async () => {
      mockFindUnique.mockRejectedValue(new Error('Database connection error'));

      await expect(registerUser(mockAuthData, mockClientInfo)).rejects.toThrow(
        'Database connection error',
      );
    });

    it('should handle unique constraint violations', async () => {
      mockFindUnique.mockResolvedValue(null);
      mockCreate.mockRejectedValue(new Error('UNIQUE constraint failed'));

      await expect(
        registerUser(mockAuthData, mockClientInfo),
      ).rejects.toMatchObject({
        message: 'Failed to create user',
        statusCode: 500,
      });
    });

    it('should not include user ID in logs when creation fails', async () => {
      mockFindUnique.mockResolvedValue(null);
      mockCreate.mockRejectedValue(new Error('Database error'));

      await expect(
        registerUser(mockAuthData, mockClientInfo),
      ).rejects.toThrow();

      expect(mockLogger).toHaveBeenCalledWith(
        expect.not.objectContaining({
          userId: expect.anything(),
        }),
      );
    });
  });

  describe('Edge cases and security scenarios', () => {
    it('should handle empty client information gracefully', async () => {
      const emptyClientInfo: ClientInformation = {
        userAgent: '',
        ip: '',
      };

      mockFindUnique.mockResolvedValue(null);
      mockCreate.mockResolvedValue(mockCreatedUser);

      const result = await registerUser(mockAuthData, emptyClientInfo);

      expect(result).toBeDefined();
      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userAgent: '',
          ipAddress: '',
        }),
      );
    });

    it('should handle special characters in email', async () => {
      const specialEmailData: UserAuthenticationSchema = {
        email: 'test+special@example.com',
        password: mockAuthData.password,
      };

      const userWithSpecialEmail = {
        ...mockCreatedUser,
        email: 'test+special@example.com',
      };

      mockFindUnique.mockResolvedValue(null);
      mockCreate.mockResolvedValue(userWithSpecialEmail);

      const result = await registerUser(specialEmailData, mockClientInfo);

      expect(result).toBeDefined();
      expect(mockFindUnique).toHaveBeenCalledWith({
        where: { email: specialEmailData.email },
      });
      expect(mockCreate).toHaveBeenCalledWith({
        data: {
          email: specialEmailData.email,
          passwordHash: '$2a$12$hashedpassword',
        },
      });
    });

    it('should handle very long passwords', async () => {
      const longPassword = 'P@ssw0rd!' + 'a'.repeat(1000);
      const longPasswordData: UserAuthenticationSchema = {
        email: mockAuthData.email,
        password: longPassword,
      };

      mockFindUnique.mockResolvedValue(null);
      mockCreate.mockResolvedValue(mockCreatedUser);

      const result = await registerUser(longPasswordData, mockClientInfo);

      expect(result).toBeDefined();
      expect(mockHashSync).toHaveBeenCalledWith(longPassword, 12);
    });

    it('should handle passwords with special characters', async () => {
      const specialPasswordData: UserAuthenticationSchema = {
        email: mockAuthData.email,
        password: 'P@ssw0rd!#$%^&*()_+-=[]{}|;:,.<>?',
      };

      mockFindUnique.mockResolvedValue(null);
      mockCreate.mockResolvedValue(mockCreatedUser);

      const result = await registerUser(specialPasswordData, mockClientInfo);

      expect(result).toBeDefined();
      expect(mockHashSync).toHaveBeenCalledWith(
        specialPasswordData.password,
        12,
      );
    });

    it('should handle long user agent strings', async () => {
      const longUserAgent =
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 EdgeAgent/91.0.864.59 Very-Long-Browser-String-That-Exceeds-Normal-Limits';
      const clientInfoWithLongUA: ClientInformation = {
        userAgent: longUserAgent,
        ip: mockClientInfo.ip,
      };

      mockFindUnique.mockResolvedValue(null);
      mockCreate.mockResolvedValue(mockCreatedUser);

      const result = await registerUser(mockAuthData, clientInfoWithLongUA);

      expect(result).toBeDefined();
      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userAgent: longUserAgent,
        }),
      );
    });

    it('should handle case-sensitive email checking', async () => {
      const upperCaseEmailData: UserAuthenticationSchema = {
        email: 'TEST@EXAMPLE.COM',
        password: mockAuthData.password,
      };

      mockFindUnique.mockResolvedValue(null);
      mockCreate.mockResolvedValue({
        ...mockCreatedUser,
        email: 'TEST@EXAMPLE.COM',
      });

      const result = await registerUser(upperCaseEmailData, mockClientInfo);

      expect(result).toBeDefined();
      expect(mockFindUnique).toHaveBeenCalledWith({
        where: { email: 'TEST@EXAMPLE.COM' },
      });
    });
  });

  describe('Password hashing scenarios', () => {
    it('should use different hash for same password on multiple calls', async () => {
      mockFindUnique.mockResolvedValue(null);
      mockCreate.mockResolvedValue(mockCreatedUser);

      mockHashSync
        .mockReturnValueOnce('$2a$12$hash1')
        .mockReturnValueOnce('$2a$12$hash2');

      await registerUser(mockAuthData, mockClientInfo);
      await registerUser(
        { ...mockAuthData, email: 'test2@example.com' },
        mockClientInfo,
      );

      expect(mockHashSync).toHaveBeenCalledTimes(2);
      expect(mockCreate).toHaveBeenNthCalledWith(1, {
        data: {
          email: mockAuthData.email,
          passwordHash: '$2a$12$hash1',
        },
      });
      expect(mockCreate).toHaveBeenNthCalledWith(2, {
        data: {
          email: 'test2@example.com',
          passwordHash: '$2a$12$hash2',
        },
      });
    });

    it('should handle bcrypt hashing errors', async () => {
      mockFindUnique.mockResolvedValue(null);
      mockHashSync.mockImplementation(() => {
        throw new Error('Bcrypt error');
      });

      await expect(registerUser(mockAuthData, mockClientInfo)).rejects.toThrow(
        'Bcrypt error',
      );
      expect(mockCreate).not.toHaveBeenCalled();
    });

    it('should always use salt rounds of 12', async () => {
      mockFindUnique.mockResolvedValue(null);
      mockCreate.mockResolvedValue(mockCreatedUser);

      await registerUser(mockAuthData, mockClientInfo);

      expect(mockHashSync).toHaveBeenCalledWith(mockAuthData.password, 12);
    });
  });

  describe('Performance and concurrency scenarios', () => {
    it('should handle concurrent registration attempts for different emails', async () => {
      mockFindUnique.mockResolvedValue(null);
      mockCreate
        .mockResolvedValueOnce({
          ...mockCreatedUser,
          id: 'user-1',
          email: 'user1@example.com',
        })
        .mockResolvedValueOnce({
          ...mockCreatedUser,
          id: 'user-2',
          email: 'user2@example.com',
        })
        .mockResolvedValueOnce({
          ...mockCreatedUser,
          id: 'user-3',
          email: 'user3@example.com',
        });

      const promises = [
        registerUser(
          { email: 'user1@example.com', password: 'Password123!' },
          mockClientInfo,
        ),
        registerUser(
          { email: 'user2@example.com', password: 'Password123!' },
          mockClientInfo,
        ),
        registerUser(
          { email: 'user3@example.com', password: 'Password123!' },
          mockClientInfo,
        ),
      ];

      const results = await Promise.all(promises);

      expect(results).toHaveLength(3);
      results.forEach((result) => {
        expect(result).toHaveProperty('id');
        expect(result).toHaveProperty('email');
        expect(result).not.toHaveProperty('passwordHash');
      });
    });

    it('should handle slow database responses', async () => {
      const slowPromise = new Promise((resolve) => {
        setTimeout(() => resolve(null), 100);
      });
      (mockFindUnique as jest.Mock).mockReturnValue(slowPromise);
      mockCreate.mockResolvedValue(mockCreatedUser);

      const startTime = Date.now();
      const result = await registerUser(mockAuthData, mockClientInfo);
      const endTime = Date.now();

      expect(result).toBeDefined();
      expect(endTime - startTime).toBeGreaterThanOrEqual(100);
    });

    it('should handle race condition scenarios', async () => {
      mockFindUnique.mockResolvedValueOnce(null);
      mockCreate.mockRejectedValueOnce(new Error('UNIQUE constraint failed'));

      await expect(
        registerUser(mockAuthData, mockClientInfo),
      ).rejects.toMatchObject({
        message: 'Failed to create user',
        statusCode: 500,
      });
    });
  });

  describe('Logging scenarios', () => {
    it('should include correct client information in all logs', async () => {
      const customClientInfo: ClientInformation = {
        userAgent: 'Custom-Agent/1.0',
        ip: '10.0.0.1',
      };

      mockFindUnique.mockResolvedValue(null);
      mockCreate.mockResolvedValue(mockCreatedUser);

      await registerUser(mockAuthData, customClientInfo);

      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userAgent: 'Custom-Agent/1.0',
          ipAddress: '10.0.0.1',
        }),
      );
    });

    it('should log success event only after user creation', async () => {
      mockFindUnique.mockResolvedValue(null);
      mockCreate.mockResolvedValue(mockCreatedUser);

      await registerUser(mockAuthData, mockClientInfo);

      expect(mockLogger).toHaveBeenCalledTimes(1);
      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: EventTypes.AUTH_SUCCESS,
        }),
      );
    });

    it('should handle logging with IPv6 addresses', async () => {
      const ipv6ClientInfo: ClientInformation = {
        userAgent: mockClientInfo.userAgent,
        ip: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
      };

      mockFindUnique.mockResolvedValue(null);
      mockCreate.mockResolvedValue(mockCreatedUser);

      const result = await registerUser(mockAuthData, ipv6ClientInfo);

      expect(result).toBeDefined();
      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          ipAddress: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        }),
      );
    });

    it('should handle logging with special characters in user agent', async () => {
      const specialUAClientInfo: ClientInformation = {
        userAgent: 'Special-Agent/1.0 (Test; +special@example.com)',
        ip: mockClientInfo.ip,
      };

      mockFindUnique.mockResolvedValue(null);
      mockCreate.mockResolvedValue(mockCreatedUser);

      const result = await registerUser(mockAuthData, specialUAClientInfo);

      expect(result).toBeDefined();
      expect(mockLogger).toHaveBeenCalledWith(
        expect.objectContaining({
          userAgent: 'Special-Agent/1.0 (Test; +special@example.com)',
        }),
      );
    });
  });

  describe('Data validation scenarios', () => {
    it('should maintain user data integrity', async () => {
      const userData: UserAuthenticationSchema = {
        email: 'integrity@example.com',
        password: 'IntegrityTest123!',
      };

      const createdUserData = {
        ...mockCreatedUser,
        email: 'integrity@example.com',
      };

      mockFindUnique.mockResolvedValue(null);
      mockCreate.mockResolvedValue(createdUserData);

      const result = await registerUser(userData, mockClientInfo);

      expect(result.email).toBe('integrity@example.com');
      expect(mockCreate).toHaveBeenCalledWith({
        data: {
          email: 'integrity@example.com',
          passwordHash: '$2a$12$hashedpassword',
        },
      });
    });

    it('should handle user creation with all default fields', async () => {
      const fullUserData = {
        ...mockCreatedUser,
        isActive: true,
        lastLoginAt: null,
      };

      mockFindUnique.mockResolvedValue(null);
      mockCreate.mockResolvedValue(fullUserData);

      const result = await registerUser(mockAuthData, mockClientInfo);

      expect(result).toEqual({
        id: fullUserData.id,
        email: fullUserData.email,
        isActive: true,
        createdAt: fullUserData.createdAt,
        updatedAt: fullUserData.updatedAt,
        lastLoginAt: null,
      });
    });
  });
});

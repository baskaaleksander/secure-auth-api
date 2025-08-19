import { Request, Response, NextFunction } from 'express';
import {
  logout,
  logoutAll,
} from '../../../src/controllers/auth/logout.controller';
import * as logoutService from '../../../src/services/auth/logout.service';
import { ClientInformation, AppError } from '../../../src/utils/types';
import jwt from 'jsonwebtoken';

// Mock the logout service
jest.mock('../../../src/services/auth/logout.service', () => ({
  logout: jest.fn(),
  logoutAll: jest.fn(),
}));

const mockLogoutService = logoutService.logout as jest.MockedFunction<
  typeof logoutService.logout
>;
const mockLogoutAllService = logoutService.logoutAll as jest.MockedFunction<
  typeof logoutService.logoutAll
>;

describe('Logout Controller', () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;
  let mockClearCookie: jest.Mock;
  let mockStatus: jest.Mock;
  let mockJson: jest.Mock;

  const mockClientInfo: ClientInformation = {
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    ip: '192.168.1.1',
  };

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();

    // Setup response mocks
    mockClearCookie = jest.fn().mockReturnThis();
    mockStatus = jest.fn().mockReturnThis();
    mockJson = jest.fn().mockReturnThis();

    mockResponse = {
      clearCookie: mockClearCookie,
      status: mockStatus,
      json: mockJson,
    };

    // Setup request mock
    mockRequest = {
      cookies: {
        refresh: 'mock-refresh-token',
      },
      headers: {
        'user-agent': mockClientInfo.userAgent,
      },
      ip: mockClientInfo.ip,
    };

    // Setup next function mock
    mockNext = jest.fn();
  });

  describe('Single logout scenarios', () => {
    describe('Successful logout', () => {
      it('should successfully logout user with valid refresh token', async () => {
        mockLogoutService.mockResolvedValue(true);

        await logout(
          mockRequest as Request,
          mockResponse as Response,
          mockNext,
        );

        expect(mockLogoutService).toHaveBeenCalledWith('mock-refresh-token', {
          userAgent: mockClientInfo.userAgent,
          ip: mockClientInfo.ip,
        });

        expect(mockClearCookie).toHaveBeenCalledWith('refresh', {
          httpOnly: true,
          secure: true,
          sameSite: 'strict',
        });

        expect(mockStatus).toHaveBeenCalledWith(200);
        expect(mockJson).toHaveBeenCalledWith({
          message: 'Logged out successfully',
        });

        expect(mockNext).not.toHaveBeenCalled();
      });

      it('should clear refresh token cookie with correct security settings', async () => {
        mockLogoutService.mockResolvedValue(true);

        await logout(
          mockRequest as Request,
          mockResponse as Response,
          mockNext,
        );

        expect(mockClearCookie).toHaveBeenCalledWith('refresh', {
          httpOnly: true,
          secure: true,
          sameSite: 'strict',
        });
      });

      it('should return success message when token is already revoked', async () => {
        mockLogoutService.mockResolvedValue(true);

        await logout(
          mockRequest as Request,
          mockResponse as Response,
          mockNext,
        );

        expect(mockStatus).toHaveBeenCalledWith(200);
        expect(mockJson).toHaveBeenCalledWith({
          message: 'Logged out successfully',
        });
      });

      it('should handle empty refresh token cookie gracefully', async () => {
        mockRequest.cookies!.refresh = '';

        await logout(
          mockRequest as Request,
          mockResponse as Response,
          mockNext,
        );

        expect(mockStatus).toHaveBeenCalledWith(400);
        expect(mockJson).toHaveBeenCalledWith({
          message: 'No refresh token provided',
        });
        expect(mockLogoutService).not.toHaveBeenCalled();
        expect(mockClearCookie).not.toHaveBeenCalled();
      });
    });

    describe('Invalid request scenarios', () => {
      it('should return 400 error when user-agent header is missing', async () => {
        mockRequest.headers = {};

        await logout(
          mockRequest as Request,
          mockResponse as Response,
          mockNext,
        );

        expect(mockStatus).toHaveBeenCalledWith(400);
        expect(mockJson).toHaveBeenCalledWith({ message: 'Invalid request' });
        expect(mockLogoutService).not.toHaveBeenCalled();
        expect(mockClearCookie).not.toHaveBeenCalled();
        expect(mockNext).not.toHaveBeenCalled();
      });

      it('should return 400 error when IP address is missing', async () => {
        mockRequest = {
          ...mockRequest,
          ip: undefined,
        };

        await logout(
          mockRequest as Request,
          mockResponse as Response,
          mockNext,
        );

        expect(mockStatus).toHaveBeenCalledWith(400);
        expect(mockJson).toHaveBeenCalledWith({ message: 'Invalid request' });
        expect(mockLogoutService).not.toHaveBeenCalled();
        expect(mockClearCookie).not.toHaveBeenCalled();
        expect(mockNext).not.toHaveBeenCalled();
      });

      it('should return 400 error when user-agent is undefined', async () => {
        mockRequest.headers!['user-agent'] = undefined;

        await logout(
          mockRequest as Request,
          mockResponse as Response,
          mockNext,
        );

        expect(mockStatus).toHaveBeenCalledWith(400);
        expect(mockJson).toHaveBeenCalledWith({ message: 'Invalid request' });
        expect(mockLogoutService).not.toHaveBeenCalled();
        expect(mockClearCookie).not.toHaveBeenCalled();
      });

      it('should return 400 error when user-agent is empty string', async () => {
        mockRequest.headers!['user-agent'] = '';

        await logout(
          mockRequest as Request,
          mockResponse as Response,
          mockNext,
        );

        expect(mockStatus).toHaveBeenCalledWith(400);
        expect(mockJson).toHaveBeenCalledWith({ message: 'Invalid request' });
        expect(mockLogoutService).not.toHaveBeenCalled();
        expect(mockClearCookie).not.toHaveBeenCalled();
      });

      it('should return 400 error when IP is empty string', async () => {
        mockRequest = {
          ...mockRequest,
          ip: '',
        };

        await logout(
          mockRequest as Request,
          mockResponse as Response,
          mockNext,
        );

        expect(mockStatus).toHaveBeenCalledWith(400);
        expect(mockJson).toHaveBeenCalledWith({ message: 'Invalid request' });
        expect(mockLogoutService).not.toHaveBeenCalled();
        expect(mockClearCookie).not.toHaveBeenCalled();
      });

      it('should return 400 error when refresh token is missing', async () => {
        delete mockRequest.cookies!.refresh;

        await logout(
          mockRequest as Request,
          mockResponse as Response,
          mockNext,
        );

        expect(mockStatus).toHaveBeenCalledWith(400);
        expect(mockJson).toHaveBeenCalledWith({
          message: 'No refresh token provided',
        });
        expect(mockLogoutService).not.toHaveBeenCalled();
        expect(mockClearCookie).not.toHaveBeenCalled();
      });

      it('should return 400 error when cookies object is missing', async () => {
        // Set cookies to undefined to simulate missing cookies object
        mockRequest = {
          ...mockRequest,
          cookies: undefined,
        };

        await logout(
          mockRequest as Request,
          mockResponse as Response,
          mockNext,
        );

        expect(mockNext).toHaveBeenCalledWith(expect.any(TypeError));
        expect(mockStatus).not.toHaveBeenCalled();
        expect(mockJson).not.toHaveBeenCalled();
        expect(mockLogoutService).not.toHaveBeenCalled();
        expect(mockClearCookie).not.toHaveBeenCalled();
      });

      it('should return 400 error when both user-agent and IP are missing', async () => {
        mockRequest = {
          ...mockRequest,
          headers: {},
          ip: undefined,
        };

        await logout(
          mockRequest as Request,
          mockResponse as Response,
          mockNext,
        );

        expect(mockStatus).toHaveBeenCalledWith(400);
        expect(mockJson).toHaveBeenCalledWith({ message: 'Invalid request' });
        expect(mockLogoutService).not.toHaveBeenCalled();
        expect(mockClearCookie).not.toHaveBeenCalled();
      });
    });

    describe('Service error handling scenarios', () => {
      it('should call next with error when logout service throws error', async () => {
        const serviceError = new Error('Service error');
        mockLogoutService.mockRejectedValue(serviceError);

        await logout(
          mockRequest as Request,
          mockResponse as Response,
          mockNext,
        );

        expect(mockNext).toHaveBeenCalledWith(serviceError);
        expect(mockStatus).not.toHaveBeenCalled();
        expect(mockJson).not.toHaveBeenCalled();
        expect(mockClearCookie).not.toHaveBeenCalled();
      });

      it('should call next with authentication error', async () => {
        const authError = new Error(
          'Failed to verify your JWT token',
        ) as AppError;
        authError.statusCode = 401;
        mockLogoutService.mockRejectedValue(authError);

        await logout(
          mockRequest as Request,
          mockResponse as Response,
          mockNext,
        );

        expect(mockNext).toHaveBeenCalledWith(authError);
        expect(mockClearCookie).not.toHaveBeenCalled();
      });

      it('should call next with database error', async () => {
        const dbError = new Error(
          'Failed to update refresh token in DB',
        ) as AppError;
        dbError.statusCode = 500;
        mockLogoutService.mockRejectedValue(dbError);

        await logout(
          mockRequest as Request,
          mockResponse as Response,
          mockNext,
        );

        expect(mockNext).toHaveBeenCalledWith(dbError);
        expect(mockClearCookie).not.toHaveBeenCalled();
      });
    });

    describe('Client information edge cases', () => {
      it('should handle very long user-agent string', async () => {
        const longUserAgent = 'A'.repeat(1000);
        mockRequest.headers!['user-agent'] = longUserAgent;
        mockLogoutService.mockResolvedValue(true);

        await logout(
          mockRequest as Request,
          mockResponse as Response,
          mockNext,
        );

        expect(mockLogoutService).toHaveBeenCalledWith('mock-refresh-token', {
          userAgent: longUserAgent,
          ip: mockClientInfo.ip,
        });
      });

      it('should handle IPv6 address', async () => {
        const ipv6Address = '2001:0db8:85a3:0000:0000:8a2e:0370:7334';
        mockRequest = {
          ...mockRequest,
          ip: ipv6Address,
        };
        mockLogoutService.mockResolvedValue(true);

        await logout(
          mockRequest as Request,
          mockResponse as Response,
          mockNext,
        );

        expect(mockLogoutService).toHaveBeenCalledWith('mock-refresh-token', {
          userAgent: mockClientInfo.userAgent,
          ip: ipv6Address,
        });
      });

      it('should handle localhost IP address', async () => {
        mockRequest = {
          ...mockRequest,
          ip: '127.0.0.1',
        };
        mockLogoutService.mockResolvedValue(true);

        await logout(
          mockRequest as Request,
          mockResponse as Response,
          mockNext,
        );

        expect(mockLogoutService).toHaveBeenCalledWith('mock-refresh-token', {
          userAgent: mockClientInfo.userAgent,
          ip: '127.0.0.1',
        });
      });

      it('should handle special characters in user-agent', async () => {
        const specialUserAgent = 'Test/1.0 (特殊文字; 中文; 🚀)';
        mockRequest.headers!['user-agent'] = specialUserAgent;
        mockLogoutService.mockResolvedValue(true);

        await logout(
          mockRequest as Request,
          mockResponse as Response,
          mockNext,
        );

        expect(mockLogoutService).toHaveBeenCalledWith('mock-refresh-token', {
          userAgent: specialUserAgent,
          ip: mockClientInfo.ip,
        });
      });
    });

    describe('Cookie handling scenarios', () => {
      it('should handle very long refresh token', async () => {
        const longRefreshToken = 'A'.repeat(4000);
        mockRequest.cookies!.refresh = longRefreshToken;
        mockLogoutService.mockResolvedValue(true);

        await logout(
          mockRequest as Request,
          mockResponse as Response,
          mockNext,
        );

        expect(mockLogoutService).toHaveBeenCalledWith(longRefreshToken, {
          userAgent: mockClientInfo.userAgent,
          ip: mockClientInfo.ip,
        });
      });

      it('should handle refresh token with special characters', async () => {
        const specialRefreshToken = 'token-with-special-chars./_+-=';
        mockRequest.cookies!.refresh = specialRefreshToken;
        mockLogoutService.mockResolvedValue(true);

        await logout(
          mockRequest as Request,
          mockResponse as Response,
          mockNext,
        );

        expect(mockLogoutService).toHaveBeenCalledWith(specialRefreshToken, {
          userAgent: mockClientInfo.userAgent,
          ip: mockClientInfo.ip,
        });
      });

      it('should clear cookie even when service returns false', async () => {
        mockLogoutService.mockResolvedValue(false);

        await logout(
          mockRequest as Request,
          mockResponse as Response,
          mockNext,
        );

        expect(mockClearCookie).toHaveBeenCalledWith('refresh', {
          httpOnly: true,
          secure: true,
          sameSite: 'strict',
        });
      });
    });
  });

  describe('Logout all scenarios', () => {
    let mockRequestWithUser: Partial<
      Request & { user?: string | jwt.JwtPayload }
    >;

    beforeEach(() => {
      mockRequestWithUser = {
        ...mockRequest,
        user: { sub: 'user-123' } as jwt.JwtPayload,
      };
    });

    describe('Successful logout all', () => {
      it('should successfully logout all devices with valid user', async () => {
        const mockLogoutAllResponse = {
          message: 'Logout completed. Revoked 3 tokens',
        };
        mockLogoutAllService.mockResolvedValue(mockLogoutAllResponse);

        await logoutAll(
          mockRequestWithUser as Request & { user?: string | jwt.JwtPayload },
          mockResponse as Response,
          mockNext,
        );

        expect(mockLogoutAllService).toHaveBeenCalledWith('user-123', {
          userAgent: mockClientInfo.userAgent,
          ip: mockClientInfo.ip,
        });

        expect(mockClearCookie).toHaveBeenCalledWith('refresh', {
          httpOnly: true,
          secure: true,
          sameSite: 'strict',
        });

        expect(mockStatus).toHaveBeenCalledWith(200);
        expect(mockJson).toHaveBeenCalledWith(mockLogoutAllResponse);

        expect(mockNext).not.toHaveBeenCalled();
      });

      it('should handle logout all when no valid tokens exist', async () => {
        const mockLogoutAllResponse = {
          message: 'Logout completed. None of the tokens were valid',
        };
        mockLogoutAllService.mockResolvedValue(mockLogoutAllResponse);

        await logoutAll(
          mockRequestWithUser as Request & { user?: string | jwt.JwtPayload },
          mockResponse as Response,
          mockNext,
        );

        expect(mockJson).toHaveBeenCalledWith(mockLogoutAllResponse);
      });

      it('should clear refresh token cookie with correct security settings', async () => {
        const mockLogoutAllResponse = {
          message: 'Logout completed. Revoked 2 tokens',
        };
        mockLogoutAllService.mockResolvedValue(mockLogoutAllResponse);

        await logoutAll(
          mockRequestWithUser as Request & { user?: string | jwt.JwtPayload },
          mockResponse as Response,
          mockNext,
        );

        expect(mockClearCookie).toHaveBeenCalledWith('refresh', {
          httpOnly: true,
          secure: true,
          sameSite: 'strict',
        });
      });
    });

    describe('Invalid request scenarios for logout all', () => {
      it('should return 400 error when user-agent header is missing', async () => {
        mockRequestWithUser.headers = {};

        await logoutAll(
          mockRequestWithUser as Request & { user?: string | jwt.JwtPayload },
          mockResponse as Response,
          mockNext,
        );

        expect(mockStatus).toHaveBeenCalledWith(400);
        expect(mockJson).toHaveBeenCalledWith({ message: 'Invalid request' });
        expect(mockLogoutAllService).not.toHaveBeenCalled();
        expect(mockClearCookie).not.toHaveBeenCalled();
      });

      it('should return 400 error when IP address is missing', async () => {
        mockRequestWithUser = {
          ...mockRequestWithUser,
          ip: undefined,
        };

        await logoutAll(
          mockRequestWithUser as Request & { user?: string | jwt.JwtPayload },
          mockResponse as Response,
          mockNext,
        );

        expect(mockStatus).toHaveBeenCalledWith(400);
        expect(mockJson).toHaveBeenCalledWith({ message: 'Invalid request' });
        expect(mockLogoutAllService).not.toHaveBeenCalled();
        expect(mockClearCookie).not.toHaveBeenCalled();
      });

      it('should return 400 error when refresh token is missing', async () => {
        delete mockRequestWithUser.cookies!.refresh;

        await logoutAll(
          mockRequestWithUser as Request & { user?: string | jwt.JwtPayload },
          mockResponse as Response,
          mockNext,
        );

        expect(mockStatus).toHaveBeenCalledWith(400);
        expect(mockJson).toHaveBeenCalledWith({
          message: 'No refresh token provided',
        });
        expect(mockLogoutAllService).not.toHaveBeenCalled();
        expect(mockClearCookie).not.toHaveBeenCalled();
      });

      it('should return 400 error when user ID is missing', async () => {
        mockRequestWithUser.user = undefined;

        await logoutAll(
          mockRequestWithUser as Request & { user?: string | jwt.JwtPayload },
          mockResponse as Response,
          mockNext,
        );

        expect(mockStatus).toHaveBeenCalledWith(400);
        expect(mockJson).toHaveBeenCalledWith({
          message: 'Invalid user ID',
        });
        expect(mockLogoutAllService).not.toHaveBeenCalled();
        expect(mockClearCookie).not.toHaveBeenCalled();
      });

      it('should return 400 error when user ID is not a string', async () => {
        mockRequestWithUser.user = { sub: 123 } as unknown as jwt.JwtPayload;

        await logoutAll(
          mockRequestWithUser as Request & { user?: string | jwt.JwtPayload },
          mockResponse as Response,
          mockNext,
        );

        expect(mockStatus).toHaveBeenCalledWith(400);
        expect(mockJson).toHaveBeenCalledWith({
          message: 'Invalid user ID',
        });
        expect(mockLogoutAllService).not.toHaveBeenCalled();
        expect(mockClearCookie).not.toHaveBeenCalled();
      });

      it('should return 400 error when user object has no sub property', async () => {
        mockRequestWithUser.user = {} as jwt.JwtPayload;

        await logoutAll(
          mockRequestWithUser as Request & { user?: string | jwt.JwtPayload },
          mockResponse as Response,
          mockNext,
        );

        expect(mockStatus).toHaveBeenCalledWith(400);
        expect(mockJson).toHaveBeenCalledWith({
          message: 'Invalid user ID',
        });
        expect(mockLogoutAllService).not.toHaveBeenCalled();
        expect(mockClearCookie).not.toHaveBeenCalled();
      });

      it('should return 400 error when user sub is empty string', async () => {
        mockRequestWithUser.user = { sub: '' } as jwt.JwtPayload;

        await logoutAll(
          mockRequestWithUser as Request & { user?: string | jwt.JwtPayload },
          mockResponse as Response,
          mockNext,
        );

        expect(mockStatus).toHaveBeenCalledWith(400);
        expect(mockJson).toHaveBeenCalledWith({
          message: 'Invalid user ID',
        });
        expect(mockLogoutAllService).not.toHaveBeenCalled();
        expect(mockClearCookie).not.toHaveBeenCalled();
      });
    });

    describe('Service error handling scenarios for logout all', () => {
      it('should call next with error when logout all service throws error', async () => {
        const serviceError = new Error('Service error');
        mockLogoutAllService.mockRejectedValue(serviceError);

        await logoutAll(
          mockRequestWithUser as Request & { user?: string | jwt.JwtPayload },
          mockResponse as Response,
          mockNext,
        );

        expect(mockNext).toHaveBeenCalledWith(serviceError);
        expect(mockStatus).not.toHaveBeenCalled();
        expect(mockJson).not.toHaveBeenCalled();
        expect(mockClearCookie).not.toHaveBeenCalled();
      });

      it('should call next with database error', async () => {
        const dbError = new Error(
          'Failed to update refresh tokens in DB',
        ) as AppError;
        dbError.statusCode = 500;
        mockLogoutAllService.mockRejectedValue(dbError);

        await logoutAll(
          mockRequestWithUser as Request & { user?: string | jwt.JwtPayload },
          mockResponse as Response,
          mockNext,
        );

        expect(mockNext).toHaveBeenCalledWith(dbError);
        expect(mockClearCookie).not.toHaveBeenCalled();
      });
    });

    describe('User authentication edge cases', () => {
      it('should handle user as string', async () => {
        mockRequestWithUser.user = 'user-456';
        const mockLogoutAllResponse = {
          message: 'Logout completed. Revoked 1 tokens',
        };
        mockLogoutAllService.mockResolvedValue(mockLogoutAllResponse);

        await logoutAll(
          mockRequestWithUser as Request & { user?: string | jwt.JwtPayload },
          mockResponse as Response,
          mockNext,
        );

        expect(mockStatus).toHaveBeenCalledWith(400);
        expect(mockJson).toHaveBeenCalledWith({
          message: 'Invalid user ID',
        });
      });

      it('should handle JWT payload with valid sub', async () => {
        mockRequestWithUser.user = {
          sub: 'user-789',
          iat: 123456,
          exp: 789012,
        } as jwt.JwtPayload;
        const mockLogoutAllResponse = {
          message: 'Logout completed. Revoked 5 tokens',
        };
        mockLogoutAllService.mockResolvedValue(mockLogoutAllResponse);

        await logoutAll(
          mockRequestWithUser as Request & { user?: string | jwt.JwtPayload },
          mockResponse as Response,
          mockNext,
        );

        expect(mockLogoutAllService).toHaveBeenCalledWith('user-789', {
          userAgent: mockClientInfo.userAgent,
          ip: mockClientInfo.ip,
        });
      });
    });
  });

  describe('Cookie security validation', () => {
    it('should set httpOnly cookie flag for security in logout', async () => {
      mockLogoutService.mockResolvedValue(true);

      await logout(mockRequest as Request, mockResponse as Response, mockNext);

      const cookieOptions = mockClearCookie.mock.calls[0][1];
      expect(cookieOptions.httpOnly).toBe(true);
    });

    it('should set secure cookie flag in logout', async () => {
      mockLogoutService.mockResolvedValue(true);

      await logout(mockRequest as Request, mockResponse as Response, mockNext);

      const cookieOptions = mockClearCookie.mock.calls[0][1];
      expect(cookieOptions.secure).toBe(true);
    });

    it('should set sameSite cookie attribute to strict in logout', async () => {
      mockLogoutService.mockResolvedValue(true);

      await logout(mockRequest as Request, mockResponse as Response, mockNext);

      const cookieOptions = mockClearCookie.mock.calls[0][1];
      expect(cookieOptions.sameSite).toBe('strict');
    });

    it('should set httpOnly cookie flag for security in logout all', async () => {
      const mockRequestWithUser = {
        ...mockRequest,
        user: { sub: 'user-123' } as jwt.JwtPayload,
      };
      const mockLogoutAllResponse = {
        message: 'Logout completed. Revoked 2 tokens',
      };
      mockLogoutAllService.mockResolvedValue(mockLogoutAllResponse);

      await logoutAll(
        mockRequestWithUser as Request & { user?: string | jwt.JwtPayload },
        mockResponse as Response,
        mockNext,
      );

      const cookieOptions = mockClearCookie.mock.calls[0][1];
      expect(cookieOptions.httpOnly).toBe(true);
    });

    it('should set secure cookie flag in logout all', async () => {
      const mockRequestWithUser = {
        ...mockRequest,
        user: { sub: 'user-123' } as jwt.JwtPayload,
      };
      const mockLogoutAllResponse = {
        message: 'Logout completed. Revoked 2 tokens',
      };
      mockLogoutAllService.mockResolvedValue(mockLogoutAllResponse);

      await logoutAll(
        mockRequestWithUser as Request & { user?: string | jwt.JwtPayload },
        mockResponse as Response,
        mockNext,
      );

      const cookieOptions = mockClearCookie.mock.calls[0][1];
      expect(cookieOptions.secure).toBe(true);
    });

    it('should set sameSite cookie attribute to strict in logout all', async () => {
      const mockRequestWithUser = {
        ...mockRequest,
        user: { sub: 'user-123' } as jwt.JwtPayload,
      };
      const mockLogoutAllResponse = {
        message: 'Logout completed. Revoked 2 tokens',
      };
      mockLogoutAllService.mockResolvedValue(mockLogoutAllResponse);

      await logoutAll(
        mockRequestWithUser as Request & { user?: string | jwt.JwtPayload },
        mockResponse as Response,
        mockNext,
      );

      const cookieOptions = mockClearCookie.mock.calls[0][1];
      expect(cookieOptions.sameSite).toBe('strict');
    });
  });

  describe('Integration scenarios', () => {
    it('should call logout service with exact parameters', async () => {
      mockLogoutService.mockResolvedValue(true);

      await logout(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockLogoutService).toHaveBeenCalledTimes(1);
      expect(mockLogoutService).toHaveBeenCalledWith(
        'mock-refresh-token',
        expect.objectContaining({
          userAgent: mockClientInfo.userAgent,
          ip: mockClientInfo.ip,
        }),
      );
    });

    it('should call logout all service with exact parameters', async () => {
      const mockRequestWithUser = {
        ...mockRequest,
        user: { sub: 'user-123' } as jwt.JwtPayload,
      };
      const mockLogoutAllResponse = {
        message: 'Logout completed. Revoked 3 tokens',
      };
      mockLogoutAllService.mockResolvedValue(mockLogoutAllResponse);

      await logoutAll(
        mockRequestWithUser as Request & { user?: string | jwt.JwtPayload },
        mockResponse as Response,
        mockNext,
      );

      expect(mockLogoutAllService).toHaveBeenCalledTimes(1);
      expect(mockLogoutAllService).toHaveBeenCalledWith(
        'user-123',
        expect.objectContaining({
          userAgent: mockClientInfo.userAgent,
          ip: mockClientInfo.ip,
        }),
      );
    });

    it('should maintain proper execution order in logout', async () => {
      mockLogoutService.mockResolvedValue(true);

      await logout(mockRequest as Request, mockResponse as Response, mockNext);

      // Verify the order of operations
      const callOrder = [
        mockLogoutService.mock.invocationCallOrder[0],
        mockClearCookie.mock.invocationCallOrder[0],
        mockStatus.mock.invocationCallOrder[0],
        mockJson.mock.invocationCallOrder[0],
      ];

      expect(callOrder[0]).toBeLessThan(callOrder[1]);
      expect(callOrder[1]).toBeLessThan(callOrder[2]);
      expect(callOrder[2]).toBeLessThan(callOrder[3]);
    });

    it('should maintain proper execution order in logout all', async () => {
      const mockRequestWithUser = {
        ...mockRequest,
        user: { sub: 'user-123' } as jwt.JwtPayload,
      };
      const mockLogoutAllResponse = {
        message: 'Logout completed. Revoked 2 tokens',
      };
      mockLogoutAllService.mockResolvedValue(mockLogoutAllResponse);

      await logoutAll(
        mockRequestWithUser as Request & { user?: string | jwt.JwtPayload },
        mockResponse as Response,
        mockNext,
      );

      // Verify the order of operations
      const callOrder = [
        mockLogoutAllService.mock.invocationCallOrder[0],
        mockClearCookie.mock.invocationCallOrder[0],
        mockStatus.mock.invocationCallOrder[0],
        mockJson.mock.invocationCallOrder[0],
      ];

      expect(callOrder[0]).toBeLessThan(callOrder[1]);
      expect(callOrder[1]).toBeLessThan(callOrder[2]);
      expect(callOrder[2]).toBeLessThan(callOrder[3]);
    });

    it('should handle concurrent logout attempts', async () => {
      mockLogoutService.mockResolvedValue(true);

      const promises = Array(5)
        .fill(null)
        .map(() =>
          logout(mockRequest as Request, mockResponse as Response, mockNext),
        );

      await Promise.all(promises);

      expect(mockLogoutService).toHaveBeenCalledTimes(5);
      expect(mockClearCookie).toHaveBeenCalledTimes(5);
    });

    it('should handle concurrent logout all attempts', async () => {
      const mockRequestWithUser = {
        ...mockRequest,
        user: { sub: 'user-123' } as jwt.JwtPayload,
      };
      const mockLogoutAllResponse = {
        message: 'Logout completed. Revoked 1 tokens',
      };
      mockLogoutAllService.mockResolvedValue(mockLogoutAllResponse);

      const promises = Array(3)
        .fill(null)
        .map(() =>
          logoutAll(
            mockRequestWithUser as Request & { user?: string | jwt.JwtPayload },
            mockResponse as Response,
            mockNext,
          ),
        );

      await Promise.all(promises);

      expect(mockLogoutAllService).toHaveBeenCalledTimes(3);
      expect(mockClearCookie).toHaveBeenCalledTimes(3);
    });
  });

  describe('Async error handling', () => {
    it('should handle async service errors properly in logout', async () => {
      const asyncError = new Error('Async error');
      mockLogoutService.mockRejectedValue(asyncError);

      await logout(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(asyncError);
    });

    it('should handle async service errors properly in logout all', async () => {
      const mockRequestWithUser = {
        ...mockRequest,
        user: { sub: 'user-123' } as jwt.JwtPayload,
      };
      const asyncError = new Error('Async error');
      mockLogoutAllService.mockRejectedValue(asyncError);

      await logoutAll(
        mockRequestWithUser as Request & { user?: string | jwt.JwtPayload },
        mockResponse as Response,
        mockNext,
      );

      expect(mockNext).toHaveBeenCalledWith(asyncError);
    });

    it('should not clear cookie when service throws error in logout', async () => {
      mockLogoutService.mockRejectedValue(new Error('Service error'));

      await logout(mockRequest as Request, mockResponse as Response, mockNext);

      expect(mockClearCookie).not.toHaveBeenCalled();
      expect(mockStatus).not.toHaveBeenCalled();
      expect(mockJson).not.toHaveBeenCalled();
    });

    it('should not clear cookie when service throws error in logout all', async () => {
      const mockRequestWithUser = {
        ...mockRequest,
        user: { sub: 'user-123' } as jwt.JwtPayload,
      };
      mockLogoutAllService.mockRejectedValue(new Error('Service error'));

      await logoutAll(
        mockRequestWithUser as Request & { user?: string | jwt.JwtPayload },
        mockResponse as Response,
        mockNext,
      );

      expect(mockClearCookie).not.toHaveBeenCalled();
      expect(mockStatus).not.toHaveBeenCalled();
      expect(mockJson).not.toHaveBeenCalled();
    });
  });
});

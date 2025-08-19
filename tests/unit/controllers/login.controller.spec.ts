import { Request, Response, NextFunction } from 'express';
import { loginUser } from '../../../src/controllers/auth/login.controller';
import * as loginService from '../../../src/services/auth/login.service';
import { ClientInformation, AppError } from '../../../src/utils/types';

// Mock the login service
jest.mock('../../../src/services/auth/login.service', () => ({
  loginUser: jest.fn(),
}));

const mockLoginService = loginService.loginUser as jest.MockedFunction<
  typeof loginService.loginUser
>;

describe('Login Controller', () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;
  let mockCookie: jest.Mock;
  let mockStatus: jest.Mock;
  let mockJson: jest.Mock;

  const mockUser = {
    id: 'user-123',
    email: 'test@example.com',
    isActive: true,
    createdAt: new Date('2024-01-01T00:00:00Z'),
    updatedAt: new Date('2024-01-01T00:00:00Z'),
    lastLoginAt: null,
  };

  const mockLoginData = {
    email: 'test@example.com',
    password: 'password123',
  };

  const mockClientInfo: ClientInformation = {
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    ip: '192.168.1.1',
  };

  const mockLoginResponse = {
    accessToken: 'mock-access-token',
    refreshToken: 'mock-refresh-token',
    user: mockUser,
  };

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();

    // Setup response mocks
    mockCookie = jest.fn().mockReturnThis();
    mockStatus = jest.fn().mockReturnThis();
    mockJson = jest.fn().mockReturnThis();

    mockResponse = {
      cookie: mockCookie,
      status: mockStatus,
      json: mockJson,
    };

    // Setup request mock
    mockRequest = {
      body: mockLoginData,
      headers: {
        'user-agent': mockClientInfo.userAgent,
      },
      ip: mockClientInfo.ip,
    };

    // Setup next function mock
    mockNext = jest.fn();
  });

  describe('Successful login scenarios', () => {
    it('should successfully login user with valid credentials', async () => {
      mockLoginService.mockResolvedValue(mockLoginResponse);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockLoginService).toHaveBeenCalledWith(mockLoginData, {
        userAgent: mockClientInfo.userAgent,
        ip: mockClientInfo.ip,
      });

      expect(mockCookie).toHaveBeenCalledWith('refresh', 'mock-refresh-token', {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      expect(mockStatus).toHaveBeenCalledWith(200);
      expect(mockJson).toHaveBeenCalledWith({
        accessToken: 'mock-access-token',
        user: mockUser,
      });

      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should set refresh token cookie with correct security settings', async () => {
      mockLoginService.mockResolvedValue(mockLoginResponse);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockCookie).toHaveBeenCalledWith('refresh', 'mock-refresh-token', {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
      });
    });

    it('should not include refresh token in response body', async () => {
      mockLoginService.mockResolvedValue(mockLoginResponse);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockJson).toHaveBeenCalledWith({
        accessToken: 'mock-access-token',
        user: mockUser,
      });

      // Ensure refresh token is not in the response body
      const responseBody = mockJson.mock.calls[0][0];
      expect(responseBody).not.toHaveProperty('refreshToken');
    });

    it('should handle user with minimal required fields', async () => {
      const minimalUser = {
        id: 'user-456',
        email: 'minimal@example.com',
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
        lastLoginAt: new Date(),
      };

      const minimalLoginResponse = {
        accessToken: 'minimal-access-token',
        refreshToken: 'minimal-refresh-token',
        user: minimalUser,
      };

      mockLoginService.mockResolvedValue(minimalLoginResponse);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockJson).toHaveBeenCalledWith({
        accessToken: 'minimal-access-token',
        user: minimalUser,
      });
    });

    it('should handle user with additional fields', async () => {
      const extendedUser = {
        ...mockUser,
        firstName: 'John',
        lastName: 'Doe',
        profilePicture: 'https://example.com/profile.jpg',
      };

      const extendedLoginResponse = {
        ...mockLoginResponse,
        user: extendedUser,
      };

      mockLoginService.mockResolvedValue(extendedLoginResponse);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockJson).toHaveBeenCalledWith({
        accessToken: 'mock-access-token',
        user: extendedUser,
      });
    });
  });

  describe('Invalid request scenarios', () => {
    it('should return 400 error when user-agent header is missing', async () => {
      mockRequest.headers = {}; // Remove user-agent header

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockStatus).toHaveBeenCalledWith(400);
      expect(mockJson).toHaveBeenCalledWith({ message: 'Invalid request' });
      expect(mockLoginService).not.toHaveBeenCalled();
      expect(mockCookie).not.toHaveBeenCalled();
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 400 error when IP address is missing', async () => {
      mockRequest = {
        ...mockRequest,
        ip: undefined,
      };

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockStatus).toHaveBeenCalledWith(400);
      expect(mockJson).toHaveBeenCalledWith({ message: 'Invalid request' });
      expect(mockLoginService).not.toHaveBeenCalled();
      expect(mockCookie).not.toHaveBeenCalled();
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 400 error when user-agent is undefined', async () => {
      mockRequest.headers!['user-agent'] = undefined;

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockStatus).toHaveBeenCalledWith(400);
      expect(mockJson).toHaveBeenCalledWith({ message: 'Invalid request' });
      expect(mockLoginService).not.toHaveBeenCalled();
    });

    it('should return 400 error when user-agent is empty string', async () => {
      mockRequest.headers!['user-agent'] = '';

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockStatus).toHaveBeenCalledWith(400);
      expect(mockJson).toHaveBeenCalledWith({ message: 'Invalid request' });
      expect(mockLoginService).not.toHaveBeenCalled();
    });

    it('should return 400 error when IP is empty string', async () => {
      mockRequest = {
        ...mockRequest,
        ip: '',
      };

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockStatus).toHaveBeenCalledWith(400);
      expect(mockJson).toHaveBeenCalledWith({ message: 'Invalid request' });
      expect(mockLoginService).not.toHaveBeenCalled();
    });

    it('should return 400 error when both user-agent and IP are missing', async () => {
      mockRequest = {
        ...mockRequest,
        headers: {},
        ip: undefined,
      };

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockStatus).toHaveBeenCalledWith(400);
      expect(mockJson).toHaveBeenCalledWith({ message: 'Invalid request' });
      expect(mockLoginService).not.toHaveBeenCalled();
    });
  });

  describe('Service error handling scenarios', () => {
    it('should call next with error when login service throws error', async () => {
      const serviceError = new Error('Service error');
      mockLoginService.mockRejectedValue(serviceError);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockNext).toHaveBeenCalledWith(serviceError);
      expect(mockStatus).not.toHaveBeenCalled();
      expect(mockJson).not.toHaveBeenCalled();
      expect(mockCookie).not.toHaveBeenCalled();
    });

    it('should call next with authentication error', async () => {
      const authError = new Error('Invalid credentials') as AppError;
      authError.statusCode = 401;
      mockLoginService.mockRejectedValue(authError);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockNext).toHaveBeenCalledWith(authError);
      expect(mockCookie).not.toHaveBeenCalled();
    });

    it('should call next with user not found error', async () => {
      const notFoundError = new Error('User not found') as AppError;
      notFoundError.statusCode = 404;
      mockLoginService.mockRejectedValue(notFoundError);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockNext).toHaveBeenCalledWith(notFoundError);
      expect(mockCookie).not.toHaveBeenCalled();
    });

    it('should call next with database error', async () => {
      const dbError = new Error('Database connection failed') as AppError;
      dbError.statusCode = 500;
      mockLoginService.mockRejectedValue(dbError);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockNext).toHaveBeenCalledWith(dbError);
      expect(mockCookie).not.toHaveBeenCalled();
    });
  });

  describe('Request body handling scenarios', () => {
    it('should handle empty request body', async () => {
      mockRequest.body = {};
      mockLoginService.mockResolvedValue(mockLoginResponse);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockLoginService).toHaveBeenCalledWith(
        {},
        {
          userAgent: mockClientInfo.userAgent,
          ip: mockClientInfo.ip,
        },
      );
    });

    it('should handle request body with additional fields', async () => {
      const requestBodyWithExtra = {
        ...mockLoginData,
        extraField: 'should be ignored',
        rememberMe: true,
      };
      mockRequest.body = requestBodyWithExtra;
      mockLoginService.mockResolvedValue(mockLoginResponse);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockLoginService).toHaveBeenCalledWith(requestBodyWithExtra, {
        userAgent: mockClientInfo.userAgent,
        ip: mockClientInfo.ip,
      });
    });

    it('should handle null request body', async () => {
      mockRequest.body = null;
      mockLoginService.mockResolvedValue(mockLoginResponse);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockLoginService).toHaveBeenCalledWith(null, {
        userAgent: mockClientInfo.userAgent,
        ip: mockClientInfo.ip,
      });
    });
  });

  describe('Client information edge cases', () => {
    it('should handle very long user-agent string', async () => {
      const longUserAgent = 'A'.repeat(1000);
      mockRequest.headers!['user-agent'] = longUserAgent;
      mockLoginService.mockResolvedValue(mockLoginResponse);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockLoginService).toHaveBeenCalledWith(mockLoginData, {
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
      mockLoginService.mockResolvedValue(mockLoginResponse);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockLoginService).toHaveBeenCalledWith(mockLoginData, {
        userAgent: mockClientInfo.userAgent,
        ip: ipv6Address,
      });
    });

    it('should handle localhost IP address', async () => {
      mockRequest = {
        ...mockRequest,
        ip: '127.0.0.1',
      };
      mockLoginService.mockResolvedValue(mockLoginResponse);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockLoginService).toHaveBeenCalledWith(mockLoginData, {
        userAgent: mockClientInfo.userAgent,
        ip: '127.0.0.1',
      });
    });

    it('should handle special characters in user-agent', async () => {
      const specialUserAgent = 'Test/1.0 (特殊文字; 中文; 🚀)';
      mockRequest.headers!['user-agent'] = specialUserAgent;
      mockLoginService.mockResolvedValue(mockLoginResponse);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockLoginService).toHaveBeenCalledWith(mockLoginData, {
        userAgent: specialUserAgent,
        ip: mockClientInfo.ip,
      });
    });
  });

  describe('Cookie security and configuration', () => {
    it('should set httpOnly cookie flag for security', async () => {
      mockLoginService.mockResolvedValue(mockLoginResponse);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      const cookieOptions = mockCookie.mock.calls[0][2];
      expect(cookieOptions.httpOnly).toBe(true);
    });

    it('should set secure cookie flag', async () => {
      mockLoginService.mockResolvedValue(mockLoginResponse);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      const cookieOptions = mockCookie.mock.calls[0][2];
      expect(cookieOptions.secure).toBe(true);
    });

    it('should set sameSite cookie attribute to strict', async () => {
      mockLoginService.mockResolvedValue(mockLoginResponse);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      const cookieOptions = mockCookie.mock.calls[0][2];
      expect(cookieOptions.sameSite).toBe('strict');
    });

    it('should set correct cookie expiration (7 days)', async () => {
      mockLoginService.mockResolvedValue(mockLoginResponse);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      const cookieOptions = mockCookie.mock.calls[0][2];
      const expectedMaxAge = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds
      expect(cookieOptions.maxAge).toBe(expectedMaxAge);
    });

    it('should set cookie with correct name and value', async () => {
      mockLoginService.mockResolvedValue(mockLoginResponse);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockCookie).toHaveBeenCalledWith(
        'refresh',
        'mock-refresh-token',
        expect.any(Object),
      );
    });

    it('should handle very long refresh token in cookie', async () => {
      const longRefreshToken = 'A'.repeat(4000);
      const responseWithLongToken = {
        ...mockLoginResponse,
        refreshToken: longRefreshToken,
      };
      mockLoginService.mockResolvedValue(responseWithLongToken);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockCookie).toHaveBeenCalledWith(
        'refresh',
        longRefreshToken,
        expect.any(Object),
      );
    });

    it('should handle refresh token with special characters', async () => {
      const specialRefreshToken = 'token-with-special-chars./_+-=';
      const responseWithSpecialToken = {
        ...mockLoginResponse,
        refreshToken: specialRefreshToken,
      };
      mockLoginService.mockResolvedValue(responseWithSpecialToken);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockCookie).toHaveBeenCalledWith(
        'refresh',
        specialRefreshToken,
        expect.any(Object),
      );
    });
  });

  describe('Response handling scenarios', () => {
    it('should return correct HTTP status code for successful login', async () => {
      mockLoginService.mockResolvedValue(mockLoginResponse);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockStatus).toHaveBeenCalledWith(200);
    });

    it('should handle service response with empty access token', async () => {
      const responseWithEmptyToken = {
        ...mockLoginResponse,
        accessToken: '',
      };
      mockLoginService.mockResolvedValue(responseWithEmptyToken);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockJson).toHaveBeenCalledWith({
        accessToken: '',
        user: mockUser,
      });
    });

    it('should handle empty string refresh token', async () => {
      const responseWithEmptyRefreshToken = {
        ...mockLoginResponse,
        refreshToken: '',
      };
      mockLoginService.mockResolvedValue(responseWithEmptyRefreshToken);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockCookie).toHaveBeenCalledWith(
        'refresh',
        '',
        expect.any(Object),
      );
    });
  });

  describe('Async error handling', () => {
    it('should handle async service errors properly', async () => {
      const asyncError = new Error('Async error');
      mockLoginService.mockRejectedValue(asyncError);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockNext).toHaveBeenCalledWith(asyncError);
    });

    it('should not set cookie when service throws error', async () => {
      mockLoginService.mockRejectedValue(new Error('Service error'));

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockCookie).not.toHaveBeenCalled();
      expect(mockStatus).not.toHaveBeenCalled();
      expect(mockJson).not.toHaveBeenCalled();
    });
  });

  describe('Integration scenarios', () => {
    it('should call login service with exact client information', async () => {
      mockLoginService.mockResolvedValue(mockLoginResponse);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockLoginService).toHaveBeenCalledTimes(1);
      expect(mockLoginService).toHaveBeenCalledWith(
        mockLoginData,
        expect.objectContaining({
          userAgent: mockClientInfo.userAgent,
          ip: mockClientInfo.ip,
        }),
      );
    });

    it('should maintain proper execution order', async () => {
      mockLoginService.mockResolvedValue(mockLoginResponse);

      await loginUser(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      // Verify the order of operations
      const callOrder = [
        mockLoginService.mock.invocationCallOrder[0],
        mockCookie.mock.invocationCallOrder[0],
        mockStatus.mock.invocationCallOrder[0],
        mockJson.mock.invocationCallOrder[0],
      ];

      expect(callOrder[0]).toBeLessThan(callOrder[1]);
      expect(callOrder[1]).toBeLessThan(callOrder[2]);
      expect(callOrder[2]).toBeLessThan(callOrder[3]);
    });

    it('should handle concurrent login attempts', async () => {
      mockLoginService.mockResolvedValue(mockLoginResponse);

      const promises = Array(5)
        .fill(null)
        .map(() =>
          loginUser(mockRequest as Request, mockResponse as Response, mockNext),
        );

      await Promise.all(promises);

      expect(mockLoginService).toHaveBeenCalledTimes(5);
      expect(mockCookie).toHaveBeenCalledTimes(5);
    });
  });
});

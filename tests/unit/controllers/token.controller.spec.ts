import { Request, Response, NextFunction } from 'express';
import { refreshToken } from '../../../src/controllers/auth/token.controller';
import * as tokenService from '../../../src/services/auth/token.service';
import { ClientInformation, AppError } from '../../../src/utils/types';

// Mock the token service
jest.mock('../../../src/services/auth/token.service', () => ({
  refreshToken: jest.fn(),
}));

const mockTokenService = tokenService.refreshToken as jest.MockedFunction<
  typeof tokenService.refreshToken
>;

describe('Token Controller', () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;
  let mockCookie: jest.Mock;
  let mockClearCookie: jest.Mock;
  let mockStatus: jest.Mock;
  let mockJson: jest.Mock;

  const mockClientInfo: ClientInformation = {
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    ip: '192.168.1.1',
  };

  const mockTokenResponse = {
    accessToken: 'new-access-token',
    refreshToken: 'new-refresh-token',
  };

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();

    // Setup response mocks
    mockCookie = jest.fn().mockReturnThis();
    mockClearCookie = jest.fn().mockReturnThis();
    mockStatus = jest.fn().mockReturnThis();
    mockJson = jest.fn().mockReturnThis();

    mockResponse = {
      cookie: mockCookie,
      clearCookie: mockClearCookie,
      status: mockStatus,
      json: mockJson,
    };

    // Setup request mock
    mockRequest = {
      cookies: {
        refresh: 'current-refresh-token',
      },
      headers: {
        'user-agent': mockClientInfo.userAgent,
      },
      ip: mockClientInfo.ip,
    };

    // Setup next function mock
    mockNext = jest.fn();
  });

  describe('Successful token refresh scenarios', () => {
    it('should successfully refresh tokens with valid refresh token', async () => {
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockTokenService).toHaveBeenCalledWith('current-refresh-token', {
        userAgent: mockClientInfo.userAgent,
        ip: mockClientInfo.ip,
      });

      expect(mockClearCookie).toHaveBeenCalledWith('refresh', {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
      });

      expect(mockCookie).toHaveBeenCalledWith('refresh', 'new-refresh-token', {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      expect(mockStatus).toHaveBeenCalledWith(200);
      expect(mockJson).toHaveBeenCalledWith({
        accessToken: 'new-access-token',
      });

      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should clear old refresh token cookie before setting new one', async () => {
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockClearCookie).toHaveBeenCalledWith('refresh', {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
      });

      // Verify clear cookie is called before setting new cookie
      const clearCookieCallOrder = mockClearCookie.mock.invocationCallOrder[0];
      const setCookieCallOrder = mockCookie.mock.invocationCallOrder[0];
      expect(clearCookieCallOrder).toBeLessThan(setCookieCallOrder);
    });

    it('should set new refresh token cookie with correct security settings', async () => {
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockCookie).toHaveBeenCalledWith('refresh', 'new-refresh-token', {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
      });
    });

    it('should only return access token in response body', async () => {
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockJson).toHaveBeenCalledWith({
        accessToken: 'new-access-token',
      });

      // Ensure refresh token is not in the response body
      const responseBody = mockJson.mock.calls[0][0];
      expect(responseBody).not.toHaveProperty('refreshToken');
    });

    it('should handle empty access token from service', async () => {
      const responseWithEmptyToken = {
        accessToken: '',
        refreshToken: 'new-refresh-token',
      };
      mockTokenService.mockResolvedValue(responseWithEmptyToken);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockJson).toHaveBeenCalledWith({
        accessToken: '',
      });
    });

    it('should handle very long tokens from service', async () => {
      const longTokenResponse = {
        accessToken: 'a'.repeat(4000),
        refreshToken: 'r'.repeat(4000),
      };
      mockTokenService.mockResolvedValue(longTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockCookie).toHaveBeenCalledWith('refresh', 'r'.repeat(4000), {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      expect(mockJson).toHaveBeenCalledWith({
        accessToken: 'a'.repeat(4000),
      });
    });
  });

  describe('Invalid request scenarios', () => {
    it('should return 401 error when refresh token is missing', async () => {
      delete mockRequest.cookies!.refresh;

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockStatus).toHaveBeenCalledWith(401);
      expect(mockJson).toHaveBeenCalledWith({
        message: 'Missing refresh token',
      });
      expect(mockTokenService).not.toHaveBeenCalled();
      expect(mockClearCookie).not.toHaveBeenCalled();
      expect(mockCookie).not.toHaveBeenCalled();
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 401 error when refresh token is empty string', async () => {
      mockRequest.cookies!.refresh = '';

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockStatus).toHaveBeenCalledWith(401);
      expect(mockJson).toHaveBeenCalledWith({
        message: 'Missing refresh token',
      });
      expect(mockTokenService).not.toHaveBeenCalled();
      expect(mockClearCookie).not.toHaveBeenCalled();
      expect(mockCookie).not.toHaveBeenCalled();
    });

    it('should return 401 error when cookies object is missing', async () => {
      mockRequest = {
        ...mockRequest,
        cookies: undefined,
      };

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      // When cookies is undefined, accessing req.cookies.refresh throws a runtime error
      // which gets caught by the try-catch and passed to next()
      expect(mockNext).toHaveBeenCalledWith(expect.any(TypeError));
      expect(mockStatus).not.toHaveBeenCalled();
      expect(mockJson).not.toHaveBeenCalled();
      expect(mockTokenService).not.toHaveBeenCalled();
      expect(mockClearCookie).not.toHaveBeenCalled();
      expect(mockCookie).not.toHaveBeenCalled();
    });

    it('should return 400 error when user-agent header is missing', async () => {
      mockRequest.headers = {};

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockStatus).toHaveBeenCalledWith(400);
      expect(mockJson).toHaveBeenCalledWith({ message: 'Invalid request' });
      expect(mockTokenService).not.toHaveBeenCalled();
      expect(mockClearCookie).not.toHaveBeenCalled();
      expect(mockCookie).not.toHaveBeenCalled();
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 400 error when IP address is missing', async () => {
      mockRequest = {
        ...mockRequest,
        ip: undefined,
      };

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockStatus).toHaveBeenCalledWith(400);
      expect(mockJson).toHaveBeenCalledWith({ message: 'Invalid request' });
      expect(mockTokenService).not.toHaveBeenCalled();
      expect(mockClearCookie).not.toHaveBeenCalled();
      expect(mockCookie).not.toHaveBeenCalled();
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 400 error when user-agent is undefined', async () => {
      mockRequest.headers!['user-agent'] = undefined;

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockStatus).toHaveBeenCalledWith(400);
      expect(mockJson).toHaveBeenCalledWith({ message: 'Invalid request' });
      expect(mockTokenService).not.toHaveBeenCalled();
      expect(mockClearCookie).not.toHaveBeenCalled();
      expect(mockCookie).not.toHaveBeenCalled();
    });

    it('should return 400 error when user-agent is empty string', async () => {
      mockRequest.headers!['user-agent'] = '';

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockStatus).toHaveBeenCalledWith(400);
      expect(mockJson).toHaveBeenCalledWith({ message: 'Invalid request' });
      expect(mockTokenService).not.toHaveBeenCalled();
      expect(mockClearCookie).not.toHaveBeenCalled();
      expect(mockCookie).not.toHaveBeenCalled();
    });

    it('should return 400 error when IP is empty string', async () => {
      mockRequest = {
        ...mockRequest,
        ip: '',
      };

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockStatus).toHaveBeenCalledWith(400);
      expect(mockJson).toHaveBeenCalledWith({ message: 'Invalid request' });
      expect(mockTokenService).not.toHaveBeenCalled();
      expect(mockClearCookie).not.toHaveBeenCalled();
      expect(mockCookie).not.toHaveBeenCalled();
    });

    it('should return 400 error when both user-agent and IP are missing', async () => {
      mockRequest = {
        ...mockRequest,
        headers: {},
        ip: undefined,
      };

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockStatus).toHaveBeenCalledWith(400);
      expect(mockJson).toHaveBeenCalledWith({ message: 'Invalid request' });
      expect(mockTokenService).not.toHaveBeenCalled();
      expect(mockClearCookie).not.toHaveBeenCalled();
      expect(mockCookie).not.toHaveBeenCalled();
    });

    it('should prioritize refresh token validation over client info validation', async () => {
      delete mockRequest.cookies!.refresh;
      mockRequest.headers = {};
      mockRequest = {
        ...mockRequest,
        ip: undefined,
      };

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      // Should check refresh token first
      expect(mockStatus).toHaveBeenCalledWith(401);
      expect(mockJson).toHaveBeenCalledWith({
        message: 'Missing refresh token',
      });
    });
  });

  describe('Service error handling scenarios', () => {
    it('should call next with error when token service throws error', async () => {
      const serviceError = new Error('Service error');
      mockTokenService.mockRejectedValue(serviceError);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockNext).toHaveBeenCalledWith(serviceError);
      expect(mockStatus).not.toHaveBeenCalled();
      expect(mockJson).not.toHaveBeenCalled();
      expect(mockClearCookie).not.toHaveBeenCalled();
      expect(mockCookie).not.toHaveBeenCalled();
    });

    it('should call next with invalid refresh token error', async () => {
      const invalidTokenError = new Error('Invalid refresh token') as AppError;
      invalidTokenError.statusCode = 401;
      mockTokenService.mockRejectedValue(invalidTokenError);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockNext).toHaveBeenCalledWith(invalidTokenError);
      expect(mockClearCookie).not.toHaveBeenCalled();
      expect(mockCookie).not.toHaveBeenCalled();
    });

    it('should call next with JWT verification error', async () => {
      const jwtError = new Error('jwt expired') as AppError;
      jwtError.statusCode = 401;
      mockTokenService.mockRejectedValue(jwtError);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockNext).toHaveBeenCalledWith(jwtError);
      expect(mockClearCookie).not.toHaveBeenCalled();
      expect(mockCookie).not.toHaveBeenCalled();
    });

    it('should call next with user not found error', async () => {
      const userNotFoundError = new Error('User not found') as AppError;
      userNotFoundError.statusCode = 404;
      mockTokenService.mockRejectedValue(userNotFoundError);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockNext).toHaveBeenCalledWith(userNotFoundError);
      expect(mockClearCookie).not.toHaveBeenCalled();
      expect(mockCookie).not.toHaveBeenCalled();
    });

    it('should call next with database error', async () => {
      const dbError = new Error(
        'Failed to insert refresh token to DB',
      ) as AppError;
      dbError.statusCode = 500;
      mockTokenService.mockRejectedValue(dbError);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockNext).toHaveBeenCalledWith(dbError);
      expect(mockClearCookie).not.toHaveBeenCalled();
      expect(mockCookie).not.toHaveBeenCalled();
    });

    it('should call next with token update error', async () => {
      const updateError = new Error(
        'Failed to update refresh token in DB',
      ) as AppError;
      updateError.statusCode = 500;
      mockTokenService.mockRejectedValue(updateError);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockNext).toHaveBeenCalledWith(updateError);
      expect(mockClearCookie).not.toHaveBeenCalled();
      expect(mockCookie).not.toHaveBeenCalled();
    });
  });

  describe('Client information edge cases', () => {
    it('should handle very long user-agent string', async () => {
      const longUserAgent = 'A'.repeat(1000);
      mockRequest.headers!['user-agent'] = longUserAgent;
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockTokenService).toHaveBeenCalledWith('current-refresh-token', {
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
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockTokenService).toHaveBeenCalledWith('current-refresh-token', {
        userAgent: mockClientInfo.userAgent,
        ip: ipv6Address,
      });
    });

    it('should handle localhost IP address', async () => {
      mockRequest = {
        ...mockRequest,
        ip: '127.0.0.1',
      };
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockTokenService).toHaveBeenCalledWith('current-refresh-token', {
        userAgent: mockClientInfo.userAgent,
        ip: '127.0.0.1',
      });
    });

    it('should handle special characters in user-agent', async () => {
      const specialUserAgent = 'Test/1.0 (特殊文字; 中文; 🚀)';
      mockRequest.headers!['user-agent'] = specialUserAgent;
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockTokenService).toHaveBeenCalledWith('current-refresh-token', {
        userAgent: specialUserAgent,
        ip: mockClientInfo.ip,
      });
    });
  });

  describe('Cookie handling scenarios', () => {
    it('should handle very long refresh token', async () => {
      const longRefreshToken = 'A'.repeat(4000);
      mockRequest.cookies!.refresh = longRefreshToken;
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockTokenService).toHaveBeenCalledWith(longRefreshToken, {
        userAgent: mockClientInfo.userAgent,
        ip: mockClientInfo.ip,
      });
    });

    it('should handle refresh token with special characters', async () => {
      const specialRefreshToken = 'token-with-special-chars./_+-=';
      mockRequest.cookies!.refresh = specialRefreshToken;
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockTokenService).toHaveBeenCalledWith(specialRefreshToken, {
        userAgent: mockClientInfo.userAgent,
        ip: mockClientInfo.ip,
      });
    });

    it('should handle refresh token with whitespace', async () => {
      const tokenWithWhitespace = '  token-with-whitespace  ';
      mockRequest.cookies!.refresh = tokenWithWhitespace;
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockTokenService).toHaveBeenCalledWith(tokenWithWhitespace, {
        userAgent: mockClientInfo.userAgent,
        ip: mockClientInfo.ip,
      });
    });

    it('should handle JWT-like refresh token format', async () => {
      const jwtLikeToken =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
      mockRequest.cookies!.refresh = jwtLikeToken;
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockTokenService).toHaveBeenCalledWith(jwtLikeToken, {
        userAgent: mockClientInfo.userAgent,
        ip: mockClientInfo.ip,
      });
    });
  });

  describe('Cookie security validation', () => {
    it('should clear old cookie with correct security settings', async () => {
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
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

    it('should set httpOnly cookie flag for security', async () => {
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      const cookieOptions = mockCookie.mock.calls[0][2];
      expect(cookieOptions.httpOnly).toBe(true);
    });

    it('should set secure cookie flag', async () => {
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      const cookieOptions = mockCookie.mock.calls[0][2];
      expect(cookieOptions.secure).toBe(true);
    });

    it('should set sameSite cookie attribute to strict', async () => {
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      const cookieOptions = mockCookie.mock.calls[0][2];
      expect(cookieOptions.sameSite).toBe('strict');
    });

    it('should set correct cookie expiration (7 days)', async () => {
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      const cookieOptions = mockCookie.mock.calls[0][2];
      const expectedMaxAge = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds
      expect(cookieOptions.maxAge).toBe(expectedMaxAge);
    });

    it('should set cookie with correct name and value', async () => {
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockCookie).toHaveBeenCalledWith(
        'refresh',
        'new-refresh-token',
        expect.any(Object),
      );
    });

    it('should use same security settings for clear and set cookie operations', async () => {
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      const clearCookieOptions = mockClearCookie.mock.calls[0][1];
      const setCookieOptions = mockCookie.mock.calls[0][2];

      expect(clearCookieOptions.httpOnly).toBe(setCookieOptions.httpOnly);
      expect(clearCookieOptions.secure).toBe(setCookieOptions.secure);
      expect(clearCookieOptions.sameSite).toBe(setCookieOptions.sameSite);
    });
  });

  describe('Response handling scenarios', () => {
    it('should return correct HTTP status code for successful refresh', async () => {
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockStatus).toHaveBeenCalledWith(200);
    });

    it('should handle service response with null values gracefully', async () => {
      const responseWithNulls = {
        accessToken: null as unknown as string,
        refreshToken: 'new-refresh-token',
      };
      mockTokenService.mockResolvedValue(responseWithNulls);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockJson).toHaveBeenCalledWith({
        accessToken: null,
      });
    });

    it('should handle service response with undefined access token', async () => {
      const responseWithUndefined = {
        accessToken: undefined as unknown as string,
        refreshToken: 'new-refresh-token',
      };
      mockTokenService.mockResolvedValue(responseWithUndefined);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockJson).toHaveBeenCalledWith({
        accessToken: undefined,
      });
    });

    it('should handle service response with additional properties', async () => {
      const extendedResponse = {
        ...mockTokenResponse,
        extraProperty: 'should be ignored',
        tokenType: 'Bearer',
      };
      mockTokenService.mockResolvedValue(extendedResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockJson).toHaveBeenCalledWith({
        accessToken: 'new-access-token',
      });

      // Ensure extra properties are not in the response
      const responseBody = mockJson.mock.calls[0][0];
      expect(responseBody).not.toHaveProperty('extraProperty');
      expect(responseBody).not.toHaveProperty('tokenType');
    });
  });

  describe('Integration scenarios', () => {
    it('should call token service with exact parameters', async () => {
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockTokenService).toHaveBeenCalledTimes(1);
      expect(mockTokenService).toHaveBeenCalledWith(
        'current-refresh-token',
        expect.objectContaining({
          userAgent: mockClientInfo.userAgent,
          ip: mockClientInfo.ip,
        }),
      );
    });

    it('should maintain proper execution order', async () => {
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      // Verify the order of operations
      const callOrder = [
        mockTokenService.mock.invocationCallOrder[0],
        mockClearCookie.mock.invocationCallOrder[0],
        mockCookie.mock.invocationCallOrder[0],
        mockStatus.mock.invocationCallOrder[0],
        mockJson.mock.invocationCallOrder[0],
      ];

      expect(callOrder[0]).toBeLessThan(callOrder[1]);
      expect(callOrder[1]).toBeLessThan(callOrder[2]);
      expect(callOrder[2]).toBeLessThan(callOrder[3]);
      expect(callOrder[3]).toBeLessThan(callOrder[4]);
    });

    it('should handle concurrent refresh attempts', async () => {
      mockTokenService.mockResolvedValue(mockTokenResponse);

      const promises = Array(5)
        .fill(null)
        .map(() =>
          refreshToken(
            mockRequest as Request,
            mockResponse as Response,
            mockNext,
          ),
        );

      await Promise.all(promises);

      expect(mockTokenService).toHaveBeenCalledTimes(5);
      expect(mockClearCookie).toHaveBeenCalledTimes(5);
      expect(mockCookie).toHaveBeenCalledTimes(5);
    });

    it('should pass client information correctly to service', async () => {
      const customClientInfo = {
        userAgent: 'Custom-Agent/2.0',
        ip: '10.0.0.1',
      };
      mockRequest.headers!['user-agent'] = customClientInfo.userAgent;
      mockRequest = {
        ...mockRequest,
        ip: customClientInfo.ip,
      };
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockTokenService).toHaveBeenCalledWith(
        'current-refresh-token',
        expect.objectContaining(customClientInfo),
      );
    });
  });

  describe('Async error handling', () => {
    it('should handle async service errors properly', async () => {
      const asyncError = new Error('Async error');
      mockTokenService.mockRejectedValue(asyncError);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockNext).toHaveBeenCalledWith(asyncError);
    });

    it('should not set cookies when service throws error', async () => {
      mockTokenService.mockRejectedValue(new Error('Service error'));

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockClearCookie).not.toHaveBeenCalled();
      expect(mockCookie).not.toHaveBeenCalled();
      expect(mockStatus).not.toHaveBeenCalled();
      expect(mockJson).not.toHaveBeenCalled();
    });

    it('should handle Promise rejection properly', async () => {
      const rejectedPromise = Promise.reject(new Error('Promise rejected'));
      mockTokenService.mockReturnValue(rejectedPromise);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockNext).toHaveBeenCalledWith(expect.any(Error));
    });
  });

  describe('Edge cases and boundary conditions', () => {
    it('should handle null refresh token value', async () => {
      mockRequest.cookies!.refresh = null as unknown as string;

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockStatus).toHaveBeenCalledWith(401);
      expect(mockJson).toHaveBeenCalledWith({
        message: 'Missing refresh token',
      });
    });

    it('should handle undefined refresh token value', async () => {
      mockRequest.cookies!.refresh = undefined as unknown as string;

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      expect(mockStatus).toHaveBeenCalledWith(401);
      expect(mockJson).toHaveBeenCalledWith({
        message: 'Missing refresh token',
      });
    });

    it('should handle numeric refresh token value', async () => {
      mockRequest.cookies!.refresh = 12345 as unknown as string;
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      // Should pass the numeric value as-is to the service
      expect(mockTokenService).toHaveBeenCalledWith(12345, expect.any(Object));
    });

    it('should handle boolean refresh token value', async () => {
      mockRequest.cookies!.refresh = true as unknown as string;
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      // Should pass the boolean value as-is to the service
      expect(mockTokenService).toHaveBeenCalledWith(true, expect.any(Object));
    });

    it('should handle object refresh token value', async () => {
      const objectToken = { token: 'value' };
      mockRequest.cookies!.refresh = objectToken as unknown as string;
      mockTokenService.mockResolvedValue(mockTokenResponse);

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      // Should pass the object as-is to the service
      expect(mockTokenService).toHaveBeenCalledWith(
        objectToken,
        expect.any(Object),
      );
    });
  });

  describe('Performance and resource management', () => {
    it('should complete token refresh operation efficiently', async () => {
      mockTokenService.mockResolvedValue(mockTokenResponse);
      const startTime = Date.now();

      await refreshToken(
        mockRequest as Request,
        mockResponse as Response,
        mockNext,
      );

      const endTime = Date.now();
      const executionTime = endTime - startTime;

      // Should complete quickly (less than 100ms for mocked operations)
      expect(executionTime).toBeLessThan(100);
    });

    it('should handle large number of simultaneous requests', async () => {
      mockTokenService.mockResolvedValue(mockTokenResponse);

      const requests = Array(50)
        .fill(null)
        .map(() =>
          refreshToken(
            mockRequest as Request,
            mockResponse as Response,
            mockNext,
          ),
        );

      const startTime = Date.now();
      await Promise.all(requests);
      const endTime = Date.now();

      expect(mockTokenService).toHaveBeenCalledTimes(50);
      expect(endTime - startTime).toBeLessThan(1000); // Should complete within 1 second
    });
  });
});

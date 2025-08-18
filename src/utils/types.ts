export interface AppError extends Error {
  statusCode?: number;
}

export interface ClientInformation {
  userAgent: string;
  ip: string;
}

export enum EventTypes {
  AUTH_FAILED = 'AUTH_FAILED',
  AUTH_SUCCESS = 'AUTH_SUCCESS',
  REFRESH_TOKEN_FAIL = 'REFRESH_TOKEN_FAIL',
  REFRESH_TOKEN_SUCCESS = 'REFRESH_TOKEN_SUCCESS',
  LOGOUT_ALL = 'LOGOUT_ALL',
  LOGOUT = 'LOGOUT',
  DB_ERROR = 'DB_ERROR',
  PASSWORD_RESET_REQUEST = 'PASSWORD_RESET_REQUEST',
  PASSWORD_RESET_FAIL = 'PASSWORD_RESET_FAIL',
  PASSWORD_RESET_SUCCESS = 'PASSWORD_RESET_SUCCESS',
}

export interface LogDataInterface {
  userId?: string;
  eventType: EventTypes;
  ipAddress?: string;
  userAgent?: string;
  metadata?: string;
}

export interface MailData {
  link: string;
}

export interface ResetPasswordQuery {
  token: string;
  userId: string;
}

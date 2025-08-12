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
  DB_ERROR = 'DB_ERROR',
}

export interface LogDataInterface {
  userId?: string;
  eventType: EventTypes;
  ipAddress?: string;
  userAgent?: string;
  metadata?: string;
}

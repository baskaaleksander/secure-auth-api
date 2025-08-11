export interface AppError extends Error {
  statusCode?: number;
}

export interface ClientInformation {
  userAgent: string;
  ip: string;
}

export interface LogDataInterface {
  userId?: string;
  eventType: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: string;
}

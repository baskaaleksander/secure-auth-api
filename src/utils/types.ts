export interface AppError extends Error {
  statusCode?: number;
}

export interface ClientInformation {
  userAgent: string;
  ip: string;
}

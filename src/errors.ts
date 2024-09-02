/**
 * Custom error class for Supabase authentication errors.
 */
export class SupabaseAuthError extends Error {
  constructor(public code: SupabaseAuthErrorCode, message: string) {
    super(message);
    this.name = 'SupabaseAuthError';
  }
}

/**
 * Enum representing various error codes for Supabase authentication.
 */
export enum SupabaseAuthErrorCode {
  // Cookie-related errors
  /** No authentication cookie found in the request */
  NO_COOKIE = 'NO_COOKIE',
  /** The authentication cookie is invalid or malformed */
  INVALID_COOKIE = 'INVALID_COOKIE',

  // Token-related errors
  /** Failed to verify the authentication token */
  TOKEN_VERIFICATION_FAILED = 'TOKEN_VERIFICATION_FAILED',
  /** The authentication token has expired */
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
  /** The signature of the authentication token is invalid */
  TOKEN_INVALID_SIGNATURE = 'TOKEN_INVALID_SIGNATURE',
  /** The issuer of the authentication token is invalid */
  TOKEN_INVALID_ISSUER = 'TOKEN_INVALID_ISSUER',
  /** One or more claims in the authentication token are invalid */
  TOKEN_INVALID_CLAIMS = 'TOKEN_INVALID_CLAIMS',

  // Session-related errors
  /** No valid session found for the user */
  SESSION_MISSING = 'SESSION_MISSING',
  /** The session is invalid or malformed */
  SESSION_INVALID = 'SESSION_INVALID',
  /** The session does not have a user */
  USER_NOT_FOUND = 'USER_NOT_FOUND',

  // General errors
  /** An unknown error occurred during the authentication process */
  UNKNOWN_ERROR = 'UNKNOWN_ERROR',
}

import type { Session } from '@supabase/supabase-js';
import { SignJWT } from 'jose';
import { beforeEach, describe, expect, it } from 'vitest';

import { SupabaseAuthError, SupabaseAuthErrorCode } from './errors';
import {
  ReadonlyRequestCookies,
  SupabaseAuthHelper,
  SupabaseAuthHelperOptions,
} from './index';

describe('SupabaseAuthHelper', () => {
  const options: SupabaseAuthHelperOptions = {
    supabaseId: 'test-supabase-id',
    supabaseUrl: 'https://test-supabase-id.supabase.co',
    jwtSecret: 'test-jwt-secret',
  };

  let supabaseAuthHelper: SupabaseAuthHelper;

  beforeEach(() => {
    supabaseAuthHelper = new SupabaseAuthHelper(options);
  });

  describe('decodeAuthCookie', () => {
    it('should return null if no valid auth cookie is found', () => {
      const cookies = new Map<string, string>([['some-other-cookie', 'value']]);

      const result = supabaseAuthHelper.decodeAuthCookie(cookies);
      expect(result).toBeNull();
    });

    it('should return a session object if a valid auth cookie is found', () => {
      const session: Session = {
        access_token: 'test-access-token',
        token_type: 'bearer',
        expires_in: 3600,
        refresh_token: 'test-refresh-token',
        user: {
          id: 'test-user-id',
          aud: 'authenticated',
          role: 'authenticated',
          email: 'test@example.com',
          phone: '1234567890',
          app_metadata: {},
          user_metadata: {},
          created_at: '2021-01-01T00:00:00Z',
          updated_at: '2021-01-01T00:00:00Z',
        },
      };

      const cookies = new Map<string, string>([
        [`sb-${options.supabaseId}-auth-token`, JSON.stringify(session)],
      ]);

      const result = supabaseAuthHelper.decodeAuthCookie(cookies);
      expect(result).toEqual(session);
    });

    it('should return a session object if a valid base64 auth cookie is found', () => {
      const session: Session = {
        access_token: 'test-access-token',
        token_type: 'bearer',
        expires_in: 3600,
        refresh_token: 'test-refresh-token',
        user: {
          id: 'test-user-id',
          aud: 'authenticated',
          role: 'authenticated',
          email: 'test@example.com',
          phone: '1234567890',
          app_metadata: {},
          user_metadata: {},
          created_at: '2021-01-01T00:00:00Z',
          updated_at: '2021-01-01T00:00:00Z',
        },
      };

      const base64Session = btoa(JSON.stringify(session));
      const cookies = new Map<string, string>([
        [`sb-${options.supabaseId}-auth-token`, `base64-${base64Session}`],
      ]);

      const result = supabaseAuthHelper.decodeAuthCookie(cookies);
      expect(result).toEqual(session);
    });

    it('should return null if the auth cookie is not parsable', () => {
      const cookies = new Map<string, string>([
        [`sb-${options.supabaseId}-auth-token`, 'invalid-json'],
      ]);

      const result = supabaseAuthHelper.decodeAuthCookie(cookies);
      expect(result).toBeNull();
    });

    it('should return a session object if both single and composite cookies are found', () => {
      const session: Session = {
        access_token: 'test-access-token',
        token_type: 'bearer',
        expires_in: 3600,
        refresh_token: 'test-refresh-token',
        user: {
          id: 'test-user-id',
          aud: 'authenticated',
          role: 'authenticated',
          email: 'test@example.com',
          phone: '1234567890',
          app_metadata: {},
          user_metadata: {},
          created_at: '2021-01-01T00:00:00Z',
          updated_at: '2021-01-01T00:00:00Z',
        },
      };

      const sessionString = JSON.stringify(session);
      const part1 = sessionString.slice(0, sessionString.length / 2);
      const part2 = sessionString.slice(sessionString.length / 2);

      const cookies = new Map<string, string>([
        [`sb-${options.supabaseId}-auth-token`, JSON.stringify(session)],
        [`sb-${options.supabaseId}-auth-token.1`, part1],
        [`sb-${options.supabaseId}-auth-token.2`, part2],
      ]);

      const result = supabaseAuthHelper.decodeAuthCookie(cookies);
      expect(result).toEqual(session);
    });

    it('should return null if no cookies are provided', () => {
      const cookies = new Map<string, string>();

      const result = supabaseAuthHelper.decodeAuthCookie(cookies);
      expect(result).toBeNull();
    });

    it('should return a session object if only composite cookies are found', () => {
      const session: Session = {
        access_token: 'test-access-token',
        token_type: 'bearer',
        expires_in: 3600,
        refresh_token: 'test-refresh-token',
        user: {
          id: 'test-user-id',
          aud: 'authenticated',
          role: 'authenticated',
          email: 'test@example.com',
          phone: '1234567890',
          app_metadata: {},
          user_metadata: {},
          created_at: '2021-01-01T00:00:00Z',
          updated_at: '2021-01-01T00:00:00Z',
        },
      };

      const sessionString = JSON.stringify(session);
      const part1 = sessionString.slice(0, sessionString.length / 2);
      const part2 = sessionString.slice(sessionString.length / 2);

      const cookies = new Map<string, string>([
        [`sb-${options.supabaseId}-auth-token.1`, part1],
        [`sb-${options.supabaseId}-auth-token.2`, part2],
      ]);

      const result = supabaseAuthHelper.decodeAuthCookie(cookies);
      expect(result).toEqual(session);
    });

    it('should return null if mixed valid and invalid cookies are found', () => {
      const session: Session = {
        access_token: 'test-access-token',
        token_type: 'bearer',
        expires_in: 3600,
        refresh_token: 'test-refresh-token',
        user: {
          id: 'test-user-id',
          aud: 'authenticated',
          role: 'authenticated',
          email: 'test@example.com',
          phone: '1234567890',
          app_metadata: {},
          user_metadata: {},
          created_at: '2021-01-01T00:00:00Z',
          updated_at: '2021-01-01T00:00:00Z',
        },
      };

      const sessionString = JSON.stringify(session);
      const part1 = sessionString.slice(0, sessionString.length / 2);
      const part2 = sessionString.slice(sessionString.length / 2);

      const cookies = new Map<string, string>([
        [`sb-${options.supabaseId}-auth-token.1`, part1],
        [`sb-${options.supabaseId}-auth-token.2`, 'invalid-json'],
      ]);

      const result = supabaseAuthHelper.decodeAuthCookie(cookies);
      expect(result).toBeNull();
    });

    it('should return null if no auth cookies are found', () => {
      const cookies = new Map<string, string>([['some-other-cookie', 'value']]);

      const result = supabaseAuthHelper.decodeAuthCookie(cookies);
      expect(result).toBeNull();
    });

    it('should handle multiple auth cookies correctly', () => {
      const session: Session = {
        access_token: 'test-access-token',
        token_type: 'bearer',
        expires_in: 3600,
        refresh_token: 'test-refresh-token',
        user: {
          id: 'test-user-id',
          aud: 'authenticated',
          role: 'authenticated',
          email: 'test@example.com',
          phone: '1234567890',
          app_metadata: {},
          user_metadata: {},
          created_at: '2021-01-01T00:00:00Z',
          updated_at: '2021-01-01T00:00:00Z',
        },
      };

      const sessionString = JSON.stringify(session);
      const part1 = sessionString.slice(0, sessionString.length / 2);
      const part2 = sessionString.slice(sessionString.length / 2);

      const cookies = new Map<string, string>([
        [`sb-${options.supabaseId}-auth-token.1`, part1],
        [`sb-${options.supabaseId}-auth-token.2`, part2],
      ]);

      const result = supabaseAuthHelper.decodeAuthCookie(cookies);
      expect(result).toEqual(session);
    });
  });

  describe('getUnsafeSession', () => {
    it('should throw NO_COOKIE error when no cookies are present', () => {
      const req = new Request('https://example.com');

      expect(() => supabaseAuthHelper.getUnsafeSession(req)).toThrow(
        new SupabaseAuthError(
          SupabaseAuthErrorCode.NO_COOKIE,
          'No cookies found',
        ),
      );
    });

    it('should throw INVALID_COOKIE error when auth cookie is invalid', () => {
      const req = new Request('https://example.com', {
        headers: {
          cookie: `sb-${options.supabaseId}-auth-token=invalid-json`,
        },
      });

      expect(() => supabaseAuthHelper.getUnsafeSession(req)).toThrow(
        new SupabaseAuthError(
          SupabaseAuthErrorCode.INVALID_COOKIE,
          'Invalid auth cookie',
        ),
      );
    });

    it('should return session when valid auth cookie is present', () => {
      const session: Session = {
        access_token: 'test-access-token',
        token_type: 'bearer',
        expires_in: 3600,
        refresh_token: 'test-refresh-token',
        user: {
          id: 'test-user-id',
          aud: 'authenticated',
          role: 'authenticated',
          email: 'test@example.com',
          phone: '1234567890',
          app_metadata: {},
          user_metadata: {},
          created_at: '2021-01-01T00:00:00Z',
          updated_at: '2021-01-01T00:00:00Z',
        },
      };

      const req = new Request('https://example.com', {
        headers: {
          cookie: `sb-${options.supabaseId}-auth-token=${JSON.stringify(
            session,
          )}`,
        },
      });

      const result = supabaseAuthHelper.getUnsafeSession(req);
      expect(result).toEqual(session);
    });
  });

  describe('getUserWithError', () => {
    it('should return user data when valid token is in Authorization header', async () => {
      const mockUser = {
        id: 'user-id',
        email: 'user@example.com',
        phone: '1234567890',
        role: 'authenticated',
        is_anonymous: false,
        app_metadata: {},
        user_metadata: {},
        session_id: 'session-id',
      };

      const secret = new TextEncoder().encode(options.jwtSecret);
      const token = await new SignJWT(mockUser)
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('1h')
        .setIssuer(new URL('/auth/v1', options.supabaseUrl).toString())
        .setSubject(mockUser.id)
        .sign(secret);

      const req = new Request('https://example.com', {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const result = await supabaseAuthHelper.getUserWithError(req);
      expect(result).toEqual(expect.objectContaining(mockUser));
    });

    it('should throw SESSION_MISSING error when no session or token is found', async () => {
      const req = new Request('https://example.com');

      await expect(supabaseAuthHelper.getUserWithError(req)).rejects.toThrow(
        new SupabaseAuthError(
          SupabaseAuthErrorCode.SESSION_MISSING,
          'No valid session or token found',
        ),
      );
    });

    it('should throw TOKEN_EXPIRED error when token has expired', async () => {
      const mockUser = {
        id: 'user-id',
        email: 'user@example.com',
        phone: '1234567890',
        role: 'authenticated',
        is_anonymous: false,
        app_metadata: {},
        user_metadata: {},
        session_id: 'session-id',
      };

      const secret = new TextEncoder().encode(options.jwtSecret);
      const token = await new SignJWT(mockUser)
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('-1h')
        .setIssuer(new URL('/auth/v1', options.supabaseUrl).toString())
        .setSubject(mockUser.id)
        .sign(secret);

      const req = new Request('https://example.com', {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      await expect(supabaseAuthHelper.getUserWithError(req)).rejects.toThrow(
        new SupabaseAuthError(
          SupabaseAuthErrorCode.TOKEN_EXPIRED,
          'Token has expired',
        ),
      );
    });

    it('should throw TOKEN_INVALID_SIGNATURE error when token signature is invalid', async () => {
      const mockUser = {
        id: 'user-id',
        email: 'user@example.com',
        phone: '1234567890',
        role: 'authenticated',
        is_anonymous: false,
        app_metadata: {},
        user_metadata: {},
        session_id: 'session-id',
      };

      const secret = new TextEncoder().encode('invalid-secret');
      const token = await new SignJWT(mockUser)
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('1h')
        .setIssuer(new URL('/auth/v1', options.supabaseUrl).toString())
        .setSubject(mockUser.id)
        .sign(secret);

      const req = new Request('https://example.com', {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      await expect(supabaseAuthHelper.getUserWithError(req)).rejects.toThrow(
        new SupabaseAuthError(
          SupabaseAuthErrorCode.TOKEN_INVALID_SIGNATURE,
          'Invalid token signature',
        ),
      );
    });

    it('should throw SESSION_MISSING error when request has no cookies or Authorization header', async () => {
      const req = new Request('https://example.com');

      await expect(supabaseAuthHelper.getUserWithError(req)).rejects.toThrow(
        new SupabaseAuthError(
          SupabaseAuthErrorCode.SESSION_MISSING,
          'No valid session or token found',
        ),
      );
    });

    it('should throw SESSION_MISSING error when request has invalid auth cookie and no Authorization header', async () => {
      const req = new Request('https://example.com', {
        headers: {
          cookie: `sb-${options.supabaseId}-auth-token=invalid-json`,
        },
      });

      await expect(supabaseAuthHelper.getUserWithError(req)).rejects.toThrow(
        new SupabaseAuthError(
          SupabaseAuthErrorCode.SESSION_MISSING,
          'No valid session or token found',
        ),
      );
    });

    it('should throw SESSION_MISSING error for ReadonlyRequestCookies with no auth cookie', async () => {
      const mockCookieStore = {
        getAll: () => [],
      } as unknown as ReadonlyRequestCookies;

      await expect(
        supabaseAuthHelper.getUserWithError(mockCookieStore),
      ).rejects.toThrow(
        new SupabaseAuthError(
          SupabaseAuthErrorCode.SESSION_MISSING,
          'No valid session or token found',
        ),
      );
    });

    it('should throw SESSION_MISSING error for ReadonlyRequestCookies with invalid auth cookie', async () => {
      const mockCookieStore = {
        getAll: () => [
          {
            name: `sb-${options.supabaseId}-auth-token`,
            value: 'invalid-json',
          },
        ],
      } as unknown as ReadonlyRequestCookies;

      await expect(
        supabaseAuthHelper.getUserWithError(mockCookieStore),
      ).rejects.toThrow(
        new SupabaseAuthError(
          SupabaseAuthErrorCode.SESSION_MISSING,
          'No valid session or token found',
        ),
      );
    });
  });

  describe('getUser', () => {
    it('should return user data when valid token is in Authorization header', async () => {
      const mockUser = {
        id: 'user-id',
        email: 'user@example.com',
        phone: '1234567890',
        role: 'authenticated',
        is_anonymous: false,
        app_metadata: {},
        user_metadata: {},
        session_id: 'session-id',
      };

      const secret = new TextEncoder().encode(options.jwtSecret);
      const token = await new SignJWT(mockUser)
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('1h')
        .setIssuer(new URL('/auth/v1', options.supabaseUrl).toString())
        .setSubject(mockUser.id)
        .sign(secret);

      const req = new Request('https://example.com', {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const result = await supabaseAuthHelper.getUser(req);
      expect(result).toEqual(expect.objectContaining(mockUser));
    });

    it('should return null when no session or token is found', async () => {
      const req = new Request('https://example.com');

      const result = await supabaseAuthHelper.getUser(req);
      expect(result).toBeNull();
    });

    it('should return null when invalid token is in Authorization header', async () => {
      const invalidToken = 'invalid.jwt.token';
      const req = new Request('https://example.com', {
        headers: {
          Authorization: `Bearer ${invalidToken}`,
        },
      });

      const result = await supabaseAuthHelper.getUser(req);
      expect(result).toBeNull();
    });

    it('should return null for ReadonlyRequestCookies with no auth cookie', async () => {
      const mockCookieStore = {
        getAll: () => [],
      } as unknown as ReadonlyRequestCookies;

      const result = await supabaseAuthHelper.getUser(mockCookieStore);
      expect(result).toBeNull();
    });

    it('should return null for ReadonlyRequestCookies with invalid auth cookie', async () => {
      const mockCookieStore = {
        getAll: () => [
          {
            name: `sb-${options.supabaseId}-auth-token`,
            value: 'invalid-json',
          },
        ],
      } as unknown as ReadonlyRequestCookies;

      const result = await supabaseAuthHelper.getUser(mockCookieStore);
      expect(result).toBeNull();
    });
  });
});

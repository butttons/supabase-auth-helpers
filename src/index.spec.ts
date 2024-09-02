import type { Session } from '@supabase/supabase-js';
import { beforeEach, describe, expect, it, vi } from 'vitest';

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
    const mockSession: Session = {
      access_token: 'mock-access-token',
      token_type: 'bearer',
      expires_in: 3600,
      refresh_token: 'mock-refresh-token',
      user: {
        id: 'mock-user-id',
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

    it('should return user data when valid session is found', async () => {
      vi.spyOn(supabaseAuthHelper, 'getUnsafeSession').mockReturnValue(
        mockSession,
      );
      vi.spyOn(supabaseAuthHelper, 'authenticateToken').mockResolvedValue({
        id: 'mock-user-id',
        email: 'test@example.com',
        phone: '1234567890',
        role: 'authenticated',
        is_anonymous: false,
        app_metadata: {},
        user_metadata: {},
        session_id: 'mock-session-id',
      });

      const result = await supabaseAuthHelper.getUserWithError(
        new Request('https://example.com'),
      );
      expect(result).toEqual(
        expect.objectContaining({
          id: 'mock-user-id',
          email: 'test@example.com',
        }),
      );
    });

    it('should throw SESSION_MISSING error when no session is found', async () => {
      vi.spyOn(supabaseAuthHelper, 'getUnsafeSession').mockReturnValue(null);

      await expect(
        supabaseAuthHelper.getUserWithError(new Request('https://example.com')),
      ).rejects.toThrow(
        new SupabaseAuthError(
          SupabaseAuthErrorCode.SESSION_MISSING,
          'No valid session found',
        ),
      );
    });

    it('should throw SESSION_INVALID error when access token is missing', async () => {
      vi.spyOn(supabaseAuthHelper, 'getUnsafeSession').mockReturnValue({
        ...mockSession,
        // @ts-expect-error: access_token is required
        access_token: undefined,
      });

      await expect(
        supabaseAuthHelper.getUserWithError(new Request('https://example.com')),
      ).rejects.toThrow(
        new SupabaseAuthError(
          SupabaseAuthErrorCode.SESSION_INVALID,
          'Invalid session: missing access token',
        ),
      );
    });

    it('should throw TOKEN_EXPIRED error when token has expired', async () => {
      vi.spyOn(supabaseAuthHelper, 'getUnsafeSession').mockReturnValue(
        mockSession,
      );
      vi.spyOn(supabaseAuthHelper, 'authenticateToken').mockRejectedValue(
        new SupabaseAuthError(
          SupabaseAuthErrorCode.TOKEN_EXPIRED,
          'Token has expired',
        ),
      );

      await expect(
        supabaseAuthHelper.getUserWithError(new Request('https://example.com')),
      ).rejects.toThrow(
        new SupabaseAuthError(
          SupabaseAuthErrorCode.TOKEN_EXPIRED,
          'Token has expired',
        ),
      );
    });

    it('should throw TOKEN_INVALID_SIGNATURE error when token signature is invalid', async () => {
      vi.spyOn(supabaseAuthHelper, 'getUnsafeSession').mockReturnValue(
        mockSession,
      );
      vi.spyOn(supabaseAuthHelper, 'authenticateToken').mockRejectedValue(
        new SupabaseAuthError(
          SupabaseAuthErrorCode.TOKEN_INVALID_SIGNATURE,
          'Invalid token signature',
        ),
      );

      await expect(
        supabaseAuthHelper.getUserWithError(new Request('https://example.com')),
      ).rejects.toThrow(
        new SupabaseAuthError(
          SupabaseAuthErrorCode.TOKEN_INVALID_SIGNATURE,
          'Invalid token signature',
        ),
      );
    });

    it('should throw UNKNOWN_ERROR for unexpected errors', async () => {
      vi.spyOn(supabaseAuthHelper, 'getUnsafeSession').mockReturnValue(
        mockSession,
      );
      vi.spyOn(supabaseAuthHelper, 'authenticateToken').mockRejectedValue(
        new Error('Unexpected error'),
      );

      await expect(
        supabaseAuthHelper.getUserWithError(new Request('https://example.com')),
      ).rejects.toThrow(
        new SupabaseAuthError(
          SupabaseAuthErrorCode.UNKNOWN_ERROR,
          'An unknown error occurred',
        ),
      );
    });

    it('should throw NO_COOKIE error when request has no cookies', async () => {
      const req = new Request('https://example.com');

      await expect(supabaseAuthHelper.getUserWithError(req)).rejects.toThrow(
        new SupabaseAuthError(
          SupabaseAuthErrorCode.NO_COOKIE,
          'No cookies found',
        ),
      );
    });

    it('should throw INVALID_COOKIE error when request has invalid auth cookie', async () => {
      const req = new Request('https://example.com', {
        headers: {
          cookie: `sb-${options.supabaseId}-auth-token=invalid-json`,
        },
      });

      await expect(supabaseAuthHelper.getUserWithError(req)).rejects.toThrow(
        new SupabaseAuthError(
          SupabaseAuthErrorCode.INVALID_COOKIE,
          'Invalid auth cookie',
        ),
      );
    });

    it('should handle ReadonlyRequestCookies with no auth cookie', async () => {
      const mockCookieStore = {
        getAll: vi.fn().mockReturnValue([]),
      } as unknown as ReadonlyRequestCookies;

      await expect(
        supabaseAuthHelper.getUserWithError(mockCookieStore),
      ).rejects.toThrow(
        new SupabaseAuthError(
          SupabaseAuthErrorCode.INVALID_COOKIE,
          'Invalid auth cookie',
        ),
      );
    });

    it('should handle ReadonlyRequestCookies with invalid auth cookie', async () => {
      const mockCookieStore = {
        getAll: vi.fn().mockReturnValue([
          {
            name: `sb-${options.supabaseId}-auth-token`,
            value: 'invalid-json',
          },
        ]),
      } as unknown as ReadonlyRequestCookies;

      await expect(
        supabaseAuthHelper.getUserWithError(mockCookieStore),
      ).rejects.toThrow(
        new SupabaseAuthError(
          SupabaseAuthErrorCode.INVALID_COOKIE,
          'Invalid auth cookie',
        ),
      );
    });
  });
});

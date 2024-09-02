import type { Session } from '@supabase/supabase-js';
import { beforeEach, describe, expect, it } from 'vitest';

import { SupabaseAuthHelper, SupabaseAuthHelperOptions } from './index';

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

    it('should return a session object if multiple valid auth cookies are found', () => {
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
  });
});

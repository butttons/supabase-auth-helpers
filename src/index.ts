import type {
  Session,
  UserAppMetadata,
  UserMetadata,
} from '@supabase/supabase-js';
import { type JWTPayload, jwtVerify } from 'jose';
import { parseCookies } from 'oslo/cookie';

type SupabaseAuthHelperOptions = {
  /**
   * The Supabase project ID
   */
  supabaseId: string;
  /**
   * The Supabase project URL. This is used to verify the issuer of the JWT.
   */
  supabaseUrl: string;
  /**
   * The JWT secret used to sign the JWT.
   */
  jwtSecret: string;
};

/**
 * A simple user object in the JWT payload. This is safer than `getSession().session.user`.
 */
type SupabaseTokenUser = {
  id: string;
  email: string;
  phone: string;
  role: string;
  is_anonymous: boolean;
  app_metadata: UserAppMetadata;
  user_metadata: UserMetadata;
  session_id: string;
};

type SafeResponse<T> =
  | { type: 'success'; payload: T }
  | { type: 'error'; error: unknown };

/**
 * A collection of server side helpers to work with Supabase Auth.
 *
 * @param options
 * @returns
 */

const createSupabaseAuthHelpers = (options: SupabaseAuthHelperOptions) => {
  const decodeAuthCookie = (cookies: Map<string, string>) => {
    const supabaseCookie = Array.from(cookies.entries())
      .sort(([a, b]) => a[0].localeCompare(b[0]))
      .reduce((acc, [name, value]) => {
        if (name.includes(`${options.supabaseId}-auth-token.`)) {
          acc += value;
        }
        return acc;
      }, '');

    try {
      return JSON.parse(supabaseCookie) as Session;
    } catch {
      console.warn('Failed to parse cookie');
      return null;
    }
  };

  /**
   * Returns the session object from the request. Similar to `supabase.auth.getSession()`.
   * The data returned here should be treated as untrusted.
   *
   * Use the `getTokenPayload(req)` method to get the validated payload.
   * @param req
   * @returns - Supabase Session from `@supabase/supabase-js`
   */
  const getUnsafeSession = (req: Request): Session | null => {
    const cookieHeader = req.headers.get('cookie');
    if (!cookieHeader) {
      return null;
    }

    const session = decodeAuthCookie(parseCookies(cookieHeader));
    return session;
  };

  /**
   * Authenticates the token and returns the payload.
   * Updated the payload to include the `id` field from the `sub` field.
   * @param token
   * @returns A minimal user object from the JWT payload.
   */
  const authenticateToken = async (token: string) => {
    const { payload } = await jwtVerify<SupabaseTokenUser>(
      token,
      new TextEncoder().encode(options.jwtSecret),
      {
        issuer: new URL('/auth/v1', options.supabaseUrl).toString(),
      },
    );
    payload.id = payload.sub ?? payload.id;
    return payload;
  };

  /**
   * Alternative to `authenticateToken` that returns a `SafeResponse` object, instead of throwing the error.
   * @param token
   * @returns A `SafeResponse` object which contains the payload or the error.
   *
   * @example
   *
   * ```ts
   * const result = await authenticateTokenSafely(token);
   *
   * if (result.type === 'error') {
   *  console.error('Could not verify token', result.error);
   *  return;
   * }
   *
   * const payload = result.payload;
   *
   * ```
   */
  const authenticateTokenSafely = async (
    token: string,
  ): Promise<SafeResponse<SupabaseTokenUser & JWTPayload>> => {
    try {
      const payload = await authenticateToken(token);
      return { type: 'success', payload };
    } catch (error) {
      return { type: 'error', error };
    }
  };

  /**
   * Gets the minimal user object from the request.
   * @param req Request
   * @returns The token payload or null if the token is invalid.
   */
  const getSession = async (req: Request) => {
    const session = getUnsafeSession(req);
    if (!session) {
      return null;
    }

    const result = await authenticateTokenSafely(session.access_token);
    if (result.type === 'error') {
      return null;
    }

    return result.payload;
  };

  return {
    getSession,
    getUnsafeSession,

    authenticateToken,
    authenticateTokenSafely,
  };
};

export default createSupabaseAuthHelpers;

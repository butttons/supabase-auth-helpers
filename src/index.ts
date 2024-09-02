import type {
  Session,
  UserAppMetadata,
  UserMetadata,
} from '@supabase/supabase-js';
import debugFactory from 'debug';
import { type JWTPayload, jwtVerify } from 'jose';
import type { cookies } from 'next/headers';
import { parseCookies } from 'oslo/cookie';
import { SupabaseAuthError, SupabaseAuthErrorCode } from './errors';

const debug = debugFactory('@butttons/supabase-auth-helpers');
export type ReadonlyRequestCookies = ReturnType<typeof cookies>;

/**
 * @module
 * @name @butttons/supabase-auth-helpers
 * @description A utility to work with Supabase Auth.
 */

/**
 * Options for the `SupabaseAuthHelper` class.
 */
export type SupabaseAuthHelperOptions = {
  /**
   * The Supabase project ID. This is used to identify the the supabase cookies in the request.
   * If you are using custom domains, this should be the subdomain. For example,
   * if your custom domain is `auth.example.com`, the `supabaseId` should be `auth`.
   *
   * You can find out the cookie name by looking at the cookies in the browser. The cookie name should be in the format `sb-[SUPABASE_ID]-auth-token.[NUMBER]`.
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
export type SupabaseTokenUser = {
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
 * A helper utility to work with Supabase Auth.
 * Provides methods to get the session, authenticate tokens, and get the user object from the token.
 *
 * @example
 *
 * ```ts
 * const supabaseAuthHelper = new SupabaseAuthHelper({
 *  supabaseId: 'your-supabase-id',
 *  supabaseUrl: 'https://your-supabase-id.supabase.co',
 *  jwtSecret: 'your-jwt-secret',
 * });
 *
 * const session = await supabaseAuthHelper.getUserFromRequest(req);
 *
 * ```
 */
export class SupabaseAuthHelper {
  public options: SupabaseAuthHelperOptions;

  constructor(options: SupabaseAuthHelperOptions) {
    this.options = options;
  }

  /**
   * Decodes the Supabase auth cookie and returns the session object.
   *
   * This method is used internally to get the session object from the request.
   * @param cookies {Map<string, string>}
   * @returns Session or null if the cookie is not parsable.
   */
  public decodeAuthCookie = (cookies: Map<string, string>): Session | null => {
    const supabaseAuthCookie = Array.from(cookies.entries())
      .filter(
        ([name]) =>
          name.includes(`${this.options.supabaseId}-auth-token`) &&
          !name.includes('auth-token-code-verifier'),
      )
      .sort((cookieA, cookieB) => cookieA[0].localeCompare(cookieB[0]));

    const singleCookie = supabaseAuthCookie.find(
      ([name]) => name === `sb-${this.options.supabaseId}-auth-token`,
    );
    const compositeCookies = supabaseAuthCookie.filter(
      ([name]) => name !== `sb-${this.options.supabaseId}-auth-token`,
    );

    const supabaseCookie =
      singleCookie?.[1] ?? compositeCookies.map(([, value]) => value).join('');

    try {
      return JSON.parse(supabaseCookie) as Session;
    } catch (error) {
      debug(
        'decodeAuthCookie(): Failed to parse cookie: %s. Error: %o',
        supabaseCookie,
        error,
      );
      return null;
    }
  };

  /**
   * Returns the session object from the request. Similar to `supabase.auth.getSession()`.
   * The data returned here should be treated as untrusted.
   *
   * Use the `getUserFromRequest(req)` method to get the validated payload.
   * @param req
   * @returns - Supabase Session from `@supabase/supabase-js`
   */
  public getUnsafeSession = (req: Request): Session | null => {
    const cookieHeader = req.headers.get('cookie');
    if (!cookieHeader) {
      debug('getUnsafeSession(): Cookies not found');
      throw new SupabaseAuthError(
        SupabaseAuthErrorCode.NO_COOKIE,
        'No cookies found',
      );
    }

    try {
      const cookies = this.decodeAuthCookie(parseCookies(cookieHeader));
      if (!cookies) {
        throw new SupabaseAuthError(
          SupabaseAuthErrorCode.INVALID_COOKIE,
          'Invalid auth cookie',
        );
      }
      return cookies;
    } catch (error) {
      if (error instanceof SupabaseAuthError) {
        throw error;
      }
      throw new SupabaseAuthError(
        SupabaseAuthErrorCode.INVALID_COOKIE,
        'Invalid auth cookie',
      );
    }
  };

  /**
   * Authenticates the token and returns the payload.
   * Updated the payload to include the `id` field from the `sub` field.
   * @param token
   * @returns A minimal user object from the JWT payload.
   */
  public authenticateToken = async (
    token: string,
  ): Promise<SupabaseTokenUser & JWTPayload> => {
    try {
      const { payload } = await jwtVerify<SupabaseTokenUser>(
        token,
        new TextEncoder().encode(this.options.jwtSecret),
        {
          issuer: new URL('/auth/v1', this.options.supabaseUrl).toString(),
        },
      );
      payload.id = payload.sub ?? payload.id;
      return payload;
    } catch (error) {
      if (error instanceof Error) {
        switch (error.name) {
          case 'JWTExpired':
            throw new SupabaseAuthError(
              SupabaseAuthErrorCode.TOKEN_EXPIRED,
              'Token has expired',
            );
          case 'JWSSignatureVerificationFailed':
            throw new SupabaseAuthError(
              SupabaseAuthErrorCode.TOKEN_INVALID_SIGNATURE,
              'Invalid token signature',
            );
          case 'JWTClaimValidationFailed':
            if (error.message.includes('iss')) {
              throw new SupabaseAuthError(
                SupabaseAuthErrorCode.TOKEN_INVALID_ISSUER,
                'Invalid token issuer',
              );
            } else {
              throw new SupabaseAuthError(
                SupabaseAuthErrorCode.TOKEN_INVALID_CLAIMS,
                'Invalid token claims',
              );
            }
          default:
            throw new SupabaseAuthError(
              SupabaseAuthErrorCode.TOKEN_VERIFICATION_FAILED,
              'Token verification failed',
            );
        }
      }
      throw new SupabaseAuthError(
        SupabaseAuthErrorCode.UNKNOWN_ERROR,
        'An unknown error occurred during token verification',
      );
    }
  };

  /**
   * Alternative to `authenticateToken` that returns a `SafeResponse` object, instead of throwing the error.
   * @param token
   * @returns A `SafeResponse` object which contains the payload or the error.
   *
   * @example
   *
   * ```ts
   * const result = await supabaseHelper.authenticateTokenSafely(token);
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
  public authenticateTokenSafely = async (
    token: string,
  ): Promise<SafeResponse<SupabaseTokenUser & JWTPayload>> => {
    try {
      const payload = await this.authenticateToken(token);
      return { type: 'success', payload };
    } catch (error) {
      return { type: 'error', error };
    }
  };

  public getUserWithError = async (
    reqOrCookie: Request | ReadonlyRequestCookies,
  ): Promise<SupabaseTokenUser & JWTPayload> => {
    try {
      let session: Session | null;

      if (reqOrCookie instanceof Request) {
        session = this.getUnsafeSession(reqOrCookie);
      } else {
        const cookieMap = this.cookieStoreToMap(reqOrCookie);
        session = this.decodeAuthCookie(cookieMap);
        if (!session) {
          throw new SupabaseAuthError(
            SupabaseAuthErrorCode.INVALID_COOKIE,
            'Invalid auth cookie',
          );
        }
      }

      if (!session) {
        throw new SupabaseAuthError(
          SupabaseAuthErrorCode.SESSION_MISSING,
          'No valid session found',
        );
      }

      if (!session.access_token) {
        throw new SupabaseAuthError(
          SupabaseAuthErrorCode.SESSION_INVALID,
          'Invalid session: missing access token',
        );
      }

      const user = await this.authenticateToken(session.access_token);

      if (!user) {
        throw new SupabaseAuthError(
          SupabaseAuthErrorCode.USER_NOT_FOUND,
          'User not found in token payload',
        );
      }

      return user;
    } catch (error) {
      if (error instanceof SupabaseAuthError) {
        throw error;
      }
      throw new SupabaseAuthError(
        SupabaseAuthErrorCode.UNKNOWN_ERROR,
        'An unknown error occurred',
      );
    }
  };

  private cookieStoreToMap(
    cookieStore: ReadonlyRequestCookies,
  ): Map<string, string> {
    return cookieStore.getAll().reduce<Map<string, string>>((acc, ck) => {
      acc.set(ck.name, ck.value);
      return acc;
    }, new Map());
  }

  public getUserFromRequest = async (
    req: Request,
  ): Promise<(SupabaseTokenUser & JWTPayload) | null> => {
    const session = this.getUnsafeSession(req);
    if (!session) {
      debug('getUserFromRequest(): Session not found in the request');
      return null;
    }

    const result = await this.authenticateTokenSafely(session.access_token);
    if (result.type === 'error') {
      debug('getUserFromRequest(): Failed to parse token - %o', result.error);
      return null;
    }

    return result.payload;
  };

  /**
   * Gets the minimal user object from the cookies.
   * This is useful when working with next.js server actions.
   * @param cookieStore
   * @returns The token payload or null if the token is invalid.
   */
  public getUserFromCookies = async (
    cookieStore: ReadonlyRequestCookies,
  ): Promise<(SupabaseTokenUser & JWTPayload) | null> => {
    const cookieMap = cookieStore
      .getAll()
      .reduce<Map<string, string>>((acc, ck) => {
        acc.set(ck.name, ck.value);
        return acc;
      }, new Map());
    const session = this.decodeAuthCookie(cookieMap);
    if (!session) {
      debug('getUserFromCookies(): Session not found in the cookies');
      return null;
    }

    const result = await this.authenticateTokenSafely(session.access_token);
    if (result.type === 'error') {
      debug('getUserFromCookies(): Failed to parse token - %o', result.error);
      return null;
    }

    return result.payload;
  };

  public getUser = async (
    reqOrCookie: Request | ReadonlyRequestCookies,
  ): Promise<(SupabaseTokenUser & JWTPayload) | null> => {
    if (reqOrCookie instanceof Request) {
      return this.getUserFromRequest(reqOrCookie);
    }
    return this.getUserFromCookies(reqOrCookie);
  };

  /**
   * Safely gets the user object from the request or cookies.
   * Returns a SafeResponse object containing either the user data or an error.
   *
   * @param reqOrCookie - The request object or ReadonlyRequestCookies
   * @returns A SafeResponse with the user data or an error
   */
  public getUserSafely = async (
    reqOrCookie: Request | ReadonlyRequestCookies,
  ): Promise<SafeResponse<SupabaseTokenUser & JWTPayload>> => {
    try {
      const user = await this.getUserWithError(reqOrCookie);
      return { type: 'success', payload: user };
    } catch (error) {
      if (error instanceof SupabaseAuthError) {
        return { type: 'error', error };
      }
      return {
        type: 'error',
        error: new SupabaseAuthError(
          SupabaseAuthErrorCode.UNKNOWN_ERROR,
          'An unknown error occurred',
        ),
      };
    }
  };
}

# supabase-auth-helpers

A collection of auth related helpers to be used with supabase auth.

## Setup

- Get your Supabase project ID at the [project settings page](https://supabase.com/dashboard/project/_/settings/general). Under _General settings_ > _Reference ID_.
- Get your JWT secret at [configuration page](https://supabase.com/dashboard/project/_/settings/api). Under _JWT Settings_ > _JWT Secret_.
- Get the supabase project URL as well on the configuration page. Under _Project URL_ > _URL_.

- Set up the auth helper somewhere in your application:

```ts
// file: src/lib/supabase-auth-helper.ts
import { SupabaseAuthHelper } from '@butttons/supabase-auth-helpers';

export const supabaseAuthHelper = new SupabaseAuthHelper({
  supabaseId: 'your-supabase-id',
  supabaseUrl: 'your-supabase-url',
  jwtSecret: 'your-jwt-secret',
});
```

Now, you can import it safely in server components, route handlers, middleware to validate the incoming requests easily.

Middleware

```ts
// file: src/middleware.ts
import { NextResponse } from 'next/server';
import { SupabaseAuthHelper } from '@butttons/supabase-auth-helpers';

export async function middleware(req: NextRequest) {
  const { getTokenPayload } = new SupabaseAuthHelper({
    supabaseId: 'your-supabase-id',
    supabaseUrl: 'your-supabase-url',
    jwtSecret: 'your-jwt-secret',
  });

  const user = await getTokenPayload(req);

  if (!user) {
    return new Response('Unauthorized', {
      status: 401,
    });
  }

  return NextResponse.next({
    request: {
      headers: req.headers,
    },
  });
}
```

Route handler

```ts
// file: src/app/api/me.ts

export const GET = async (req: Request) => {
  const { getTokenPayload } = new SupabaseAuthHelper({
    supabaseId: 'your-supabase-id',
    supabaseUrl: 'your-supabase-url',
    jwtSecret: 'your-jwt-secret',
  });

  const user = await getTokenPayload(req);

  if (!user) {
    return new Response('Unauthorized', {
      status: 401,
    });
  }

  return Response.json(user);
};
```

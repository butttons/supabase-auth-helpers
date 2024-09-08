# supabase-auth-helpers

A collection of auth related helpers to be used with supabase auth.

## Installation
Published on jsr.io - https://jsr.io/@butttons/supabase-auth-helpers

npm
```
npx jsr add @butttons/supabase-auth-helpers
```

pnpm
```
pnpm dlx jsr add @butttons/supabase-auth-helpers
```

yarn
```
yarn dlx jsr add @butttons/supabase-auth-helpers
```

deno
```
deno add @butttons/supabase-auth-helpers
```

bun
```
bunx jsr add @butttons/supabase-auth-helpers
```

## Setup

### Frontend
- Set up your project to use the PCKE auth flow - https://supabase.com/docs/guides/auth/sessions/pkce-flow. This will set the appropriate cookies when making requests.
- Alternatively, you can pass in the `access_token` from the `Session` object as a `Authorization: Bearer ${access_token}` header.

### Backend
- Get your Supabase project ID at the [project settings page](https://supabase.com/dashboard/project/_/settings/general). Under _General settings_ > _Reference ID_.
  - If you are using custom domains, this should be the subdomain. For example, if your custom domain is `auth.example.com`, the `supabaseId` should be `auth`. You can find out supabase ID by looking at the cookies in the browser. The cookie name should be in the format `sb-[SUPABASE_ID]-auth-token.[NUMBER]`.
  - On localhost, this ID is typically `127`.
- Get your JWT secret at [configuration page](https://supabase.com/dashboard/project/_/settings/api). Under _JWT Settings_ > _JWT Secret_.
- Get the supabase project URL as well on the configuration page. Under _Project URL_ > _URL_.



## Usage
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
import { supabaseAuthHelper } from '@/lib/supabase-auth-helper';

export async function middleware(req: NextRequest) {
  const user = await supabaseAuthHelper.getUser(req);

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
import { supabaseAuthHelper } from '@/lib/supabase-auth-helper';

export const GET = async (req: Request) => {
  const user = await supabaseAuthHelper.getUser(req);

  if (!user) {
    return new Response('Unauthorized', {
      status: 401,
    });
  }

  return Response.json(user);
};
```

Server actions
```ts
// file: src/app/actions.ts
"use server"
import { cookies } from 'next/headers'; 

import { supabaseAuthHelper } from '@/lib/supabase-auth-helper';

export const updateProfile = async (input: UserProfile) => {
  const user = await supabaseAuthHelper.getUser(cookies());

  if (!user) {
    return new Response('Unauthorized', {
      status: 401,
    });
  }

  // Update the user

  return { user }
}

```
/**
 * TURN credential issuer for the Chitchatter deployment on azaleasun.top.
 *
 * The site itself is a Workers static-assets project, which has no runtime of
 * its own to hang an endpoint off, so the endpoint lives here as a separate
 * Worker.
 *
 * Deploying:
 *
 *   cd turn-api
 *   npx wrangler deploy
 *   npx wrangler secret put TURN_AUTH_SECRET     # the coturn shared secret
 *
 * Then point the site at it by setting, in the site project's build variables:
 *
 *   VITE_RTC_CONFIG_ENDPOINT = https://<worker-name>.<subdomain>.workers.dev
 *
 * and trigger a new build - VITE_* variables are inlined at build time.
 *
 * The credential scheme is coturn's `use-auth-secret`:
 *
 *   username   = "<unix expiry>:<label>"
 *   credential = base64(HMAC-SHA1(shared secret, username))
 *
 * so the shared secret stays here and the browser only ever receives a
 * credential that expires. Rotating the secret invalidates every issued
 * credential at once.
 */

// The app caches a config for the lifetime of the page, so this has to cover
// how long one tab may stay open. The value of the expiry is that it exists at
// all, not that it is short.
const credentialTtlSeconds = 24 * 60 * 60

const iceUrls = [
  'stun:124.220.174.142:3478',
  'turn:124.220.174.142:3478?transport=udp',
  'turn:124.220.174.142:3478?transport=tcp',
]

// This endpoint is public by design - every visitor to the site calls it - so
// the origin is not an access control. If it ever gets abused, the levers are
// coturn's quotas and rotating TURN_AUTH_SECRET, not this header.
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Accept',
}

const toBase64 = bytes => {
  let binary = ''

  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }

  return btoa(binary)
}

const mintCredential = async secret => {
  const username = `${Math.floor(Date.now() / 1000) + credentialTtlSeconds}:chitchatter`

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  )

  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(username)
  )

  return { username, credential: toBase64(new Uint8Array(signature)) }
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders })
    }

    if (!env.TURN_AUTH_SECRET) {
      return new Response('TURN_AUTH_SECRET is not configured', {
        status: 500,
        headers: corsHeaders,
      })
    }

    const { username, credential } = await mintCredential(env.TURN_AUTH_SECRET)

    return Response.json(
      { urls: iceUrls, username, credential },
      {
        headers: {
          ...corsHeaders,
          // A credential must never be cached by a CDN or an intermediary.
          'Cache-Control': 'no-store',
        },
      }
    )
  },
}

// Cloudflare Pages Function - route: /api/turn-config
//
// Issues a short-lived TURN credential instead of serving a permanent one, so
// the long-lived shared secret never reaches the browser. Pair this with
// coturn's `use-auth-secret` / `static-auth-secret`, which is the same scheme:
//
//   username   = "<unix expiry>:<label>"
//   credential = base64(HMAC-SHA1(shared secret, username))
//
// Set TURN_AUTH_SECRET in the Pages project's environment variables. It must
// match coturn's static-auth-secret.

// The app caches this for the lifetime of the page (staleTime: Infinity), so
// the lifetime has to cover how long a single tab may stay open - a chat
// session can run for hours. The protection here is that the credential
// expires at all and that rotating TURN_AUTH_SECRET invalidates every one of
// them at once; if the endpoint is ever abused, add rate limiting to it.
const credentialTtlSeconds = 24 * 60 * 60

const iceUrls = [
  'stun:124.220.174.142:3478',
  'turn:124.220.174.142:3478?transport=udp',
  'turn:124.220.174.142:3478?transport=tcp',
]

const toBase64 = bytes => {
  let binary = ''

  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }

  return btoa(binary)
}

export const onRequestGet = async ({ env }) => {
  const secret = env.TURN_AUTH_SECRET

  if (!secret) {
    return new Response('TURN_AUTH_SECRET is not configured', { status: 500 })
  }

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

  return Response.json(
    {
      urls: iceUrls,
      username,
      credential: toBase64(new Uint8Array(signature)),
    },
    {
      // A credential must never be cached by a CDN or an intermediary.
      headers: { 'Cache-Control': 'no-store' },
    }
  )
}

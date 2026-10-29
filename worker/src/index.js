// Relays GitHub release webhooks from app repositories to a repository_dispatch
// on yscoopy, so the token that can write to yscoopy is kept here and not in
// each app repository.

export default {
  async fetch(request, env) {
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    const body = await request.text();

    const signature = request.headers.get('X-Hub-Signature-256');
    if (!signature) {
      return new Response('Missing signature', { status: 401 });
    }

    const valid = await verifySignature(body, signature, env.WEBHOOK_SECRET);
    if (!valid) {
      return new Response('Invalid signature', { status: 401 });
    }

    const event = request.headers.get('X-GitHub-Event');
    if (event !== 'release') {
      return new Response('Ignored event: ' + event, { status: 200 });
    }

    const payload = JSON.parse(body);

    if (payload.action !== 'published') {
      return new Response('Ignored action: ' + payload.action, { status: 200 });
    }

    const repo = payload.repository?.full_name ?? 'unknown';
    const tag = payload.release?.tag_name ?? 'unknown';

    const res = await fetch('https://api.github.com/repos/ycookiey/yscoopy/dispatches', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.GITHUB_PAT}`,
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'yscoopy-webhook-relay',
        'X-GitHub-Api-Version': '2022-11-28',
      },
      body: JSON.stringify({
        event_type: 'release-update',
        client_payload: { repo, tag },
      }),
    });

    if (!res.ok) {
      const text = await res.text();
      console.error(`GitHub API error: ${res.status} ${text}`);
      return new Response('Failed to dispatch', { status: 502 });
    }

    return new Response(`Dispatched for ${repo}@${tag}`, { status: 200 });
  },
};

async function verifySignature(body, signature, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(body));
  const expected = 'sha256=' + [...new Uint8Array(sig)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return signature === expected;
}

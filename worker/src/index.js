// yscoopy-webhook-relay
// GitHub release webhook を受けて yscoopy の repository_dispatch をトリガーする

export default {
  async fetch(request, env) {
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    const body = await request.text();

    // webhook 署名を検証
    const signature = request.headers.get('X-Hub-Signature-256');
    if (!signature) {
      return new Response('Missing signature', { status: 401 });
    }

    const valid = await verifySignature(body, signature, env.WEBHOOK_SECRET);
    if (!valid) {
      return new Response('Invalid signature', { status: 401 });
    }

    // release イベント以外は無視
    const event = request.headers.get('X-GitHub-Event');
    if (event !== 'release') {
      return new Response('Ignored event: ' + event, { status: 200 });
    }

    const payload = JSON.parse(body);

    // published 以外のアクションは無視
    if (payload.action !== 'published') {
      return new Response('Ignored action: ' + payload.action, { status: 200 });
    }

    // yscoopy の repository_dispatch をトリガー
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

// HMAC-SHA256 で webhook 署名を検証
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

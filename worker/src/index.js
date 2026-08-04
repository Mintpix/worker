const GITHUB_API = "https://api.github.com";
const BRANCH = "master";
const EVENT_NAME = /^[a-zA-Z0-9_-]+$/;

export default {
  async fetch(request, env) {
    if (request.method !== "POST") return new Response("Not found", { status: 404 });

    const signature = request.headers.get("X-Hub-Signature-256");
    const delivery = request.headers.get("X-GitHub-Delivery");
    const event = request.headers.get("X-GitHub-Event");
    if (!signature || !delivery) return new Response("Bad request", { status: 400 });

    const body = await request.arrayBuffer();
    if (!(await verifySignature(body, signature, env.WEBHOOK_SECRET))) return new Response("Unauthorized", { status: 401 });

    if (event !== "push") return new Response("Ignored", { status: 202 });

    let payload;
    try {
      payload = JSON.parse(new TextDecoder().decode(body));
    } catch {
      return new Response("Bad request", { status: 400 });
    }

    const repository = payload.repository?.full_name;
    const branch = payload.ref === `refs/heads/${BRANCH}`;
    const isPush = payload.deleted !== true && payload.created !== true;
    if (!repository || !branch || !isPush) return new Response("Ignored", { status: 202 });
    if (!env.WORKER_REPO || !env.GITHUB_TOKEN) return new Response("Configuration error", { status: 500 });

    const eventType = repository.split("/")[1];
    if (!EVENT_NAME.test(eventType)) return new Response("Ignored", { status: 202 });

    const response = await fetch(`${GITHUB_API}/repos/${env.WORKER_REPO}/dispatches`, {
      method: "POST",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${env.GITHUB_TOKEN}`,
        "User-Agent": "mintpix-worker",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ event_type: eventType }),
    });

    if (!response.ok) return new Response("Dispatch failed", { status: 502 });
    return new Response("Accepted", { status: 202 });
  },
};

async function verifySignature(body, header, secret = "") {
  const [algorithm, encoded] = header.split("=");
  if (algorithm !== "sha256" || !encoded || !secret) return false;
  const expected = await crypto.subtle.sign(
    "HMAC",
    await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]),
    body,
  );
  const actual = hexToBytes(encoded);
  return actual.length === expected.byteLength && constantTimeEqual(new Uint8Array(expected), actual);
}

function hexToBytes(value) {
  if (!/^[0-9a-f]{64}$/i.test(value)) return new Uint8Array();
  return Uint8Array.from(value.match(/../g), (pair) => Number.parseInt(pair, 16));
}

function constantTimeEqual(left, right) {
  let difference = left.length ^ right.length;
  for (let index = 0; index < Math.min(left.length, right.length); index++) difference |= left[index] ^ right[index];
  return difference === 0;
}
import { Env } from '../types';

export { SSHSessionDO } from './durable-object';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/api/ssh') {
      return handleSSHConnection(request, env);
    }

    if (url.pathname === '/api/health') {
      return Response.json({ status: 'ok', timestamp: Date.now() });
    }

    return env.ASSETS.fetch(request);
  },
};

async function handleSSHConnection(request: Request, env: Env): Promise<Response> {
  const upgradeHeader = request.headers.get('Upgrade');
  if (upgradeHeader !== 'websocket') {
    return Response.json(
      { error: 'Expected WebSocket upgrade' },
      { status: 426 }
    );
  }

  const url = new URL(request.url);
  const host = url.searchParams.get('host');
  const port = parseInt(url.searchParams.get('port') || '22');
  const username = url.searchParams.get('user');
  const password = url.searchParams.get('pass');

  if (!host || !username || !password) {
    return Response.json(
      { error: 'Missing required parameters: host, user, pass' },
      { status: 400 }
    );
  }

  const doId = env.SSH_SESSION.idFromName(`ssh:${host}:${port}:${username}`);
  const stub = env.SSH_SESSION.get(doId);

  return stub.fetch(request);
}

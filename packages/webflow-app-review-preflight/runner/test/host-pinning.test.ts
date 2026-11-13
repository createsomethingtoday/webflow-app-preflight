import { createServer as createHttpServer, request as httpRequest } from 'node:http';
import { connect, createServer, type AddressInfo, type Server, type Socket } from 'node:net';
import { brotliCompressSync, deflateSync, gzipSync } from 'node:zlib';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import {
  isPrivateNetworkAddress,
  pinnedGet,
  readCapped,
  resolveHostPins,
  startPinnedEgressProxy,
  type PinnedEgressProxy
} from '../src/index.js';

// The only DNS in these tests. Every call is recorded, so a test can show
// that a connection did not ask for a second answer.
const dns = vi.hoisted(() => ({
  answers: new Map<string, Array<{ address: string; family: number }>>(),
  calls: [] as string[]
}));
vi.mock('node:dns/promises', () => ({
  lookup: async (host: string) => {
    dns.calls.push(host);
    const answer = dns.answers.get(host);
    if (!answer) {
      throw Object.assign(new Error(`getaddrinfo ENOTFOUND ${host}`), { code: 'ENOTFOUND' });
    }
    return answer;
  }
}));

beforeEach(() => {
  dns.answers.clear();
  dns.calls.length = 0;
  delete process.env.RUNTIME_ALLOW_PRIVATE_HOSTS;
});
afterEach(() => {
  delete process.env.RUNTIME_ALLOW_PRIVATE_HOSTS;
});

describe('non-public address check', () => {
  test('finds every loopback, private, link-local and reserved form', () => {
    for (const address of [
      '127.0.0.1',
      '127.255.255.254',
      '10.1.2.3',
      '172.16.0.1',
      '172.31.255.255',
      '192.168.1.1',
      '169.254.169.254',
      '100.64.0.1',
      '100.100.100.200',
      '0.0.0.0',
      '198.18.0.1',
      '224.0.0.1',
      '255.255.255.255',
      '::1',
      '::',
      '[::1]',
      'fd00:ec2::254',
      'FD00:EC2::254',
      'fe80::1%eth0',
      '::ffff:127.0.0.1',
      '::ffff:7f00:1',
      '::ffff:a00:1'
    ]) {
      expect(isPrivateNetworkAddress(address), address).toBe(true);
    }
  });

  test('passes a public address', () => {
    for (const address of [
      '8.8.8.8',
      '172.32.0.1',
      '100.63.255.255',
      '192.169.0.1',
      '2606:4700::1111',
      '::ffff:8.8.8.8'
    ]) {
      expect(isPrivateNetworkAddress(address), address).toBe(false);
    }
  });

  test('never reads a host name as an address', () => {
    // These names start with the hex digits of a private IPv6 range.
    for (const name of ['fcdn.example.test', 'fd-assets.example.test', 'feb.example.test']) {
      expect(isPrivateNetworkAddress(name), name).toBe(false);
    }
  });
});

describe('host pins', () => {
  test('resolves each allowed host one time and keeps the answer', async () => {
    dns.answers.set('runtime.partner.test', [
      { address: '203.0.113.10', family: 4 },
      { address: '2001:db8::10', family: 6 }
    ]);
    dns.answers.set('fcdn.partner.test', [{ address: '203.0.113.11', family: 4 }]);
    const pins = await resolveHostPins(new Set(['runtime.partner.test', 'fcdn.partner.test']));
    expect(pins.get('runtime.partner.test')).toEqual([
      { address: '203.0.113.10', family: 4 },
      { address: '2001:db8::10', family: 6 }
    ]);
    expect(pins.get('fcdn.partner.test')).toEqual([{ address: '203.0.113.11', family: 4 }]);
    expect(dns.calls).toEqual(['runtime.partner.test', 'fcdn.partner.test']);
  });

  test('pins a public IP literal to itself without a lookup', async () => {
    const pins = await resolveHostPins(new Set(['203.0.113.20']));
    expect(pins.get('203.0.113.20')).toEqual([{ address: '203.0.113.20', family: 4 }]);
    expect(dns.calls).toEqual([]);
  });

  test('fails a host when any one of its addresses is not public', async () => {
    for (const hidden of ['127.0.0.1', '169.254.169.254', '100.100.100.200', '::ffff:7f00:1', '::']) {
      dns.answers.set('rebind.partner.test', [
        { address: '203.0.113.10', family: 4 },
        { address: hidden, family: hidden.includes(':') ? 6 : 4 }
      ]);
      await expect(resolveHostPins(new Set(['rebind.partner.test'])), hidden).rejects.toThrow(
        'did not resolve to a public network address'
      );
    }
  });

  test('fails a host that has no address', async () => {
    dns.answers.set('empty.partner.test', []);
    await expect(resolveHostPins(new Set(['empty.partner.test']))).rejects.toThrow(
      'did not resolve to a public network address'
    );
  });

  test('fails a loopback or private host named directly', async () => {
    for (const host of ['localhost', '127.0.0.1', '[::1]', '10.0.0.5', '169.254.169.254']) {
      await expect(resolveHostPins(new Set([host])), host).rejects.toThrow(
        'loopback or private-network address'
      );
    }
    expect(dns.calls).toEqual([]);
  });

  test('permits private addresses only with the fixture switch', async () => {
    process.env.RUNTIME_ALLOW_PRIVATE_HOSTS = '1';
    dns.answers.set('fixture.partner.test', [{ address: '127.0.0.1', family: 4 }]);
    const pins = await resolveHostPins(new Set(['127.0.0.1', 'fixture.partner.test']));
    expect(pins.get('127.0.0.1')).toEqual([{ address: '127.0.0.1', family: 4 }]);
    expect(pins.get('fixture.partner.test')).toEqual([{ address: '127.0.0.1', family: 4 }]);
  });
});

describe('pinned egress proxy', () => {
  let upstream: Server;
  let upstreamPort = 0;
  let upstreamConnections = 0;
  let proxy: PinnedEgressProxy | undefined;

  beforeEach(async () => {
    upstreamConnections = 0;
    upstream = createServer((socket) => {
      upstreamConnections += 1;
      socket.on('error', () => undefined);
      socket.pipe(socket);
    });
    await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
    upstreamPort = (upstream.address() as AddressInfo).port;
  });
  afterEach(async () => {
    await proxy?.close();
    proxy = undefined;
    await new Promise<void>((resolve) => upstream.close(() => resolve()));
  });

  const loopbackPin = (host: string) => new Map([[host, [{ address: '127.0.0.1', family: 4 }]]]);

  // Sends one CONNECT. Resolves with the reply head and the open socket, or
  // with `socket: null` when the proxy closed the connection.
  function openTunnel(authority: string): Promise<{ reply: string; socket: Socket | null }> {
    return new Promise((resolve) => {
      const socket = connect(Number(new URL(proxy!.url).port), '127.0.0.1', () => {
        socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`);
      });
      let reply = '';
      const onData = (chunk: Buffer): void => {
        reply += chunk.toString('latin1');
        if (reply.includes('\r\n\r\n')) {
          socket.off('data', onData);
          resolve({ reply, socket });
        }
      };
      socket.on('data', onData);
      socket.on('error', () => undefined);
      socket.on('close', () => resolve({ reply, socket: null }));
    });
  }

  test('connects to the pinned address and asks DNS nothing', async () => {
    process.env.RUNTIME_ALLOW_PRIVATE_HOSTS = '1';
    // The name has no DNS answer at all. Only the pin can make this work.
    proxy = await startPinnedEgressProxy({
      pins: loopbackPin('pinned.partner.test'),
      connectTimeoutMs: 5_000
    });
    const { reply, socket } = await openTunnel(`pinned.partner.test:${upstreamPort}`);
    expect(reply).toMatch(/^HTTP\/1\.1 200 /);
    const echoed = new Promise<string>((resolve) =>
      socket!.once('data', (chunk) => resolve(chunk.toString()))
    );
    socket!.write('ping');
    expect(await echoed).toBe('ping');
    socket!.destroy();
    expect(upstreamConnections).toBe(1);
    expect(dns.calls).toEqual([]);
  });

  test('refuses a host that has no pin, with no HTTP reply, and reports it one time', async () => {
    process.env.RUNTIME_ALLOW_PRIVATE_HOSTS = '1';
    const refused: string[] = [];
    proxy = await startPinnedEgressProxy({
      pins: loopbackPin('pinned.partner.test'),
      connectTimeoutMs: 5_000
    });
    proxy.onRefused = (authority) => refused.push(authority);
    for (const authority of [
      `other.partner.test:${upstreamPort}`,
      `other.partner.test:${upstreamPort}`,
      `127.0.0.1:${upstreamPort}`,
      'pinned.partner.test:0',
      `user@pinned.partner.test:${upstreamPort}`
    ]) {
      expect(await openTunnel(authority)).toEqual({ reply: '', socket: null });
    }
    expect(refused).toEqual([
      `other.partner.test:${upstreamPort}`,
      `127.0.0.1:${upstreamPort}`,
      'pinned.partner.test:0',
      '[invalid-authority]'
    ]);
    expect(upstreamConnections).toBe(0);
    expect(dns.calls).toEqual([]);
  });

  test('does not connect to a private address, even when a pin holds one', async () => {
    // Without the fixture switch a pin can never hold a private address. This
    // is the last check: it holds even if the vetting made an error.
    const refused: string[] = [];
    proxy = await startPinnedEgressProxy({
      pins: loopbackPin('flipped.partner.test'),
      connectTimeoutMs: 5_000
    });
    proxy.onRefused = (authority) => refused.push(authority);
    expect(await openTunnel(`flipped.partner.test:${upstreamPort}`)).toEqual({
      reply: '',
      socket: null
    });
    expect(refused).toEqual([`flipped.partner.test:${upstreamPort}`]);
    expect(upstreamConnections).toBe(0);
  });

  test('closes the tunnel without a reply when the pinned address does not answer', async () => {
    process.env.RUNTIME_ALLOW_PRIVATE_HOSTS = '1';
    const refused: string[] = [];
    // A TCP connection to a multicast address fails at once.
    proxy = await startPinnedEgressProxy({
      pins: new Map([['down.partner.test', [{ address: '224.0.0.1', family: 4 }]]]),
      connectTimeoutMs: 5_000
    });
    proxy.onRefused = (authority) => refused.push(authority);
    expect(await openTunnel('down.partner.test:443')).toEqual({ reply: '', socket: null });
    // A failed connection is not a policy refusal.
    expect(refused).toEqual([]);
  });

  test('does not forward a plain HTTP request', async () => {
    process.env.RUNTIME_ALLOW_PRIVATE_HOSTS = '1';
    proxy = await startPinnedEgressProxy({
      pins: loopbackPin('pinned.partner.test'),
      connectTimeoutMs: 5_000
    });
    const status = await new Promise<number>((resolve, reject) => {
      const request = httpRequest(
        {
          host: '127.0.0.1',
          port: Number(new URL(proxy!.url).port),
          path: `http://pinned.partner.test:${upstreamPort}/`,
          agent: false
        },
        (response) => {
          response.resume();
          resolve(response.statusCode ?? 0);
        }
      );
      request.on('error', reject);
      request.end();
    });
    expect(status).toBe(403);
    expect(upstreamConnections).toBe(0);
  });
});

describe('pinned request from the runner', () => {
  const body = 'export const runtime = "fixture";\n'.repeat(40);
  let server: ReturnType<typeof createHttpServer>;
  let port = 0;
  let requests = 0;

  beforeEach(async () => {
    process.env.RUNTIME_ALLOW_PRIVATE_HOSTS = '1';
    requests = 0;
    server = createHttpServer((request, response) => {
      requests += 1;
      const path = request.url ?? '/';
      if (path === '/plain') {
        response.writeHead(200, { 'content-length': Buffer.byteLength(body) }).end(body);
      } else if (path === '/gzip') {
        response.writeHead(200, { 'content-encoding': 'gzip' }).end(gzipSync(body));
      } else if (path === '/br') {
        response.writeHead(200, { 'content-encoding': 'br' }).end(brotliCompressSync(body));
      } else if (path === '/deflate') {
        response.writeHead(200, { 'content-encoding': 'deflate' }).end(deflateSync(body));
      } else if (path === '/bomb') {
        // 20 MB of zeros in a few kilobytes on the wire.
        response
          .writeHead(200, { 'content-encoding': 'gzip' })
          .end(gzipSync(Buffer.alloc(20 * 1024 * 1024)));
      } else if (path === '/unknown-encoding') {
        response.writeHead(200, { 'content-encoding': 'compress' }).end('x');
      } else if (path === '/redirect') {
        response.writeHead(302, { location: '/plain' }).end();
      } else if (path === '/empty') {
        response.writeHead(204).end();
      } else {
        response.writeHead(404).end('not found');
      }
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as AddressInfo).port;
  });
  afterEach(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  const pins = new Map([['runtime.partner.test', [{ address: '127.0.0.1', family: 4 }]]]);
  const text = async (path: string): Promise<string> =>
    new TextDecoder().decode(
      await readCapped(await pinnedGet(pins, `http://runtime.partner.test:${port}${path}`, 5_000), 1_000_000)
    );

  test('reads a plain and a compressed body through the pin, with no DNS', async () => {
    for (const path of ['/plain', '/gzip', '/br', '/deflate']) {
      expect(await text(path), path).toBe(body);
    }
    expect(dns.calls).toEqual([]);
  });

  test('keeps the byte cap on the decoded body', async () => {
    const response = await pinnedGet(pins, `http://runtime.partner.test:${port}/bomb`, 5_000);
    await expect(readCapped(response, 1_000_000)).rejects.toThrow('exceeds the byte cap');
  });

  test('does not follow a redirect', async () => {
    const response = await pinnedGet(pins, `http://runtime.partner.test:${port}/redirect`, 5_000);
    expect(response.status).toBe(302);
    expect(requests).toBe(1);
  });

  test('reports the status of an empty or failed response', async () => {
    const empty = await pinnedGet(pins, `http://runtime.partner.test:${port}/empty`, 5_000);
    expect(empty.status).toBe(204);
    const missing = await pinnedGet(pins, `http://runtime.partner.test:${port}/missing`, 5_000);
    expect(missing.ok).toBe(false);
    await missing.body?.cancel();
  });

  test('rejects an encoding that it cannot decode', async () => {
    await expect(
      pinnedGet(pins, `http://runtime.partner.test:${port}/unknown-encoding`, 5_000)
    ).rejects.toThrow('unsupported content encoding');
  });

  test('sends nothing to a host that has no pin', async () => {
    for (const url of [
      `http://other.partner.test:${port}/plain`,
      `http://127.0.0.1:${port}/plain`,
      `ftp://runtime.partner.test:${port}/plain`
    ]) {
      await expect(pinnedGet(pins, url, 5_000), url).rejects.toThrow('no pinned address');
    }
    expect(requests).toBe(0);
    expect(dns.calls).toEqual([]);
  });
});

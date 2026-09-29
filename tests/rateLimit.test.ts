// deno-lint-ignore-file no-explicit-any
import { assertEquals, assertExists } from 'https://deno.land/std@0.133.0/testing/asserts.ts';
import { createRateLimiter } from '../rateLimit.ts';

function fakeContext(ip: string, method = 'POST'): any {
  return {
    request: { ip, method },
    response: { headers: new Headers(), status: undefined, body: undefined, type: undefined },
  };
}

Deno.test('rate limiter allows requests under the limit', async () => {
  const limiter = createRateLimiter({ windowMs: 60 * 1000, max: 2 });
  const ctx1 = fakeContext('10.0.0.1');
  const ctx2 = fakeContext('10.0.0.1');
  let called = 0;
  const next = () => { called++; return Promise.resolve(); };

  await limiter(ctx1, next);
  await limiter(ctx2, next);

  assertEquals(called, 2);
  assertEquals(ctx2.response.headers.get('X-RateLimit-Remaining'), '0');
  assertEquals(ctx2.response.status, undefined);
});

Deno.test('rate limiter blocks requests over the limit with 429', async () => {
  const limiter = createRateLimiter({ windowMs: 60 * 1000, max: 2 });
  const ip = '10.0.0.2';
  let called = 0;
  const next = () => { called++; return Promise.resolve(); };

  await limiter(fakeContext(ip), next);
  await limiter(fakeContext(ip), next);
  const blocked = fakeContext(ip);
  await limiter(blocked, next);

  assertEquals(called, 2);
  assertEquals(blocked.response.status, 429);
  assertEquals((blocked.response.body as { message: string }).message, 'Too many requests, please try again later.');
  assertExists(blocked.response.headers.get('Retry-After'));
});

Deno.test('rate limiter tracks separate clients independently', async () => {
  const limiter = createRateLimiter({ windowMs: 60 * 1000, max: 1 });
  let called = 0;
  const next = () => { called++; return Promise.resolve(); };

  const ctxA = fakeContext('10.0.0.3');
  const ctxB = fakeContext('10.0.0.4');
  await limiter(ctxA, next);
  await limiter(ctxB, next);

  assertEquals(called, 2);
  assertEquals(ctxA.response.status, undefined);
  assertEquals(ctxB.response.status, undefined);
});

Deno.test('rate limiter only applies to configured methods', async () => {
  const limiter = createRateLimiter({ windowMs: 60 * 1000, max: 1, methods: ['POST'] });
  let called = 0;
  const next = () => { called++; return Promise.resolve(); };
  const ip = '10.0.0.5';

  await limiter(fakeContext(ip, 'GET'), next);
  await limiter(fakeContext(ip, 'GET'), next);
  await limiter(fakeContext(ip, 'GET'), next);

  assertEquals(called, 3);
});

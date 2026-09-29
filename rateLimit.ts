import { oak } from './deps.ts';

export interface RateLimitOptions {
  windowMs: number;
  max: number;
  methods?: string[];
}

interface Bucket {
  count: number;
  resetAt: number;
}

const SWEEP_INTERVAL_REQUESTS = 500;

/** Fixed-window, per-IP rate limiter. Keyed by client IP, tracked in-memory. */
export function createRateLimiter({ windowMs, max, methods = ['POST'] }: RateLimitOptions) {
  const buckets: Map<string, Bucket> = new Map();
  let requestsSinceSweep = 0;

  return async (context: oak.Context, next: () => Promise<unknown>) => {
    if (!methods.includes(context.request.method)) {
      await next();
      return;
    }

    const now = Date.now();
    if (++requestsSinceSweep >= SWEEP_INTERVAL_REQUESTS) {
      requestsSinceSweep = 0;
      for (const [key, bucket] of buckets) {
        if (bucket.resetAt <= now) {
          buckets.delete(key);
        }
      }
    }

    const key = context.request.ip;
    let bucket = buckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      bucket = { count: 0, resetAt: now + windowMs };
      buckets.set(key, bucket);
    }
    bucket.count += 1;

    context.response.headers.set('X-RateLimit-Limit', String(max));
    context.response.headers.set('X-RateLimit-Remaining', String(Math.max(0, max - bucket.count)));
    context.response.headers.set('X-RateLimit-Reset', String(Math.ceil(bucket.resetAt / 1000)));

    if (bucket.count > max) {
      context.response.headers.set('Retry-After', String(Math.ceil((bucket.resetAt - now) / 1000)));
      context.response.status = 429;
      context.response.body = { message: 'Too many requests, please try again later.' };
      context.response.type = 'application/json';
      return;
    }

    await next();
  };
}

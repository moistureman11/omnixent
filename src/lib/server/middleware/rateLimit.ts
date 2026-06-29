import { Request, Response, NextFunction } from 'express';

interface Bucket {
  count: number;
  windowStartedAt: number;
}

const bucketStore = new Map<string, Bucket>();

export default function createRateLimit(maxRequests: number, windowMs: number) {
  return function rateLimit(req: Request, res: Response, next: NextFunction) {
    const key = req.ip || 'unknown';
    const now = Date.now();
    const existing = bucketStore.get(key);

    if (!existing || now - existing.windowStartedAt > windowMs) {
      bucketStore.set(key, {
        count: 1,
        windowStartedAt: now,
      });
      next();
      return;
    }

    if (existing.count >= maxRequests) {
      res.status(429).json({
        success: false,
        reason: 'Too many requests',
      });
      return;
    }

    existing.count += 1;
    bucketStore.set(key, existing);
    next();
  };
}

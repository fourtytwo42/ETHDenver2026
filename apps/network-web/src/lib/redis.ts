import { createClient, type RedisClientType } from 'redis';

import { getEnv } from '@/lib/env';

declare global {
  // eslint-disable-next-line no-var
  var __xclawRedisClient: RedisClientType | undefined;
  // eslint-disable-next-line no-var
  var __xclawRedisConnectPromise: Promise<void> | undefined;
}

async function connect(client: RedisClientType): Promise<void> {
  if (!globalThis.__xclawRedisConnectPromise) {
    globalThis.__xclawRedisConnectPromise = client.connect().then(() => undefined);
  }
  await globalThis.__xclawRedisConnectPromise;
}

export async function getRedisClient(): Promise<RedisClientType> {
  if (!globalThis.__xclawRedisClient) {
    const env = getEnv();
    globalThis.__xclawRedisClient = createClient({ url: env.redisUrl });
    globalThis.__xclawRedisClient.on('error', () => {
      // Error handling is propagated from call sites.
    });
  }

  await connect(globalThis.__xclawRedisClient);
  return globalThis.__xclawRedisClient;
}

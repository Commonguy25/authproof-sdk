'use strict';

/**
 * RedisConsumptionStore -- Redis-backed durable consumption store.
 *
 * Provides the global one-time-use guarantee across multiple processes and
 * restarts by using Redis as the source of truth.
 *
 * consume() issues a single atomic SET key value NX command. This is NOT a
 * GET followed by a SET -- that would introduce a race condition between
 * processes. Redis SET NX is atomic at the server level: if two processes
 * race to consume the same key, exactly one receives 'OK' and the other
 * receives null.
 *
 * The Redis client is a constructor dependency (injected, mockable). redis is
 * an optional peer dependency: if you only use InMemoryConsumptionStore you do
 * not need to install redis at all. Use the static createClient() factory to
 * lazily require the redis package only when a Redis connection is needed.
 *
 * @example
 *   import { createClient } from 'redis';
 *   const client = createClient({ url: 'redis://localhost:6379' });
 *   await client.connect();
 *   const store = new RedisConsumptionStore({ client });
 */
class RedisConsumptionStore {
  /**
   * @param {object} opts
   * @param {object} opts.client       - Redis client (ioredis or node-redis v4+).
   *                                     Must support .set(key, value, opts) returning
   *                                     'OK' when a new key is written, null when NX
   *                                     rejects because the key already exists.
   * @param {string} [opts.prefix]     - Key prefix. Default: 'authproof:consumed:'.
   * @param {number} [opts.ttlSeconds] - Optional TTL for consumed keys. Omit for no expiry.
   */
  constructor({ client, prefix = 'authproof:consumed:', ttlSeconds } = {}) {
    if (!client) throw new Error('RedisConsumptionStore: client is required');
    this._client     = client;
    this._prefix     = prefix;
    this._ttlSeconds = ttlSeconds ?? null;
  }

  /**
   * Atomically consume a key using a single Redis SET key value NX command.
   *
   * This is one command, not a GET followed by SET. No application-level lock
   * or Lua script is needed -- Redis serializes commands, so SET NX is
   * inherently atomic across all clients connected to the same server.
   *
   * @param {string} key
   * @returns {Promise<boolean>} true if first consumption (allow), false if already consumed (deny)
   */
  async consume(key) {
    const redisKey = this._prefix + key;
    const setOpts  = this._ttlSeconds !== null
      ? { NX: true, EX: this._ttlSeconds }
      : { NX: true };
    const result = await this._client.set(redisKey, '1', setOpts);
    return result !== null && result !== false;
  }

  /**
   * Check whether a key has been consumed (read-only).
   * @param {string} key
   * @returns {Promise<boolean>}
   */
  async has(key) {
    const redisKey = this._prefix + key;
    const result   = await this._client.get(redisKey);
    return result !== null;
  }

  /**
   * Factory: lazily import redis and create a connected client.
   *
   * Importing redis is deferred until this method is called, so the core SDK
   * stays dependency-free for users who never call createClient().
   *
   * @param {object} [redisOptions] - Options forwarded to redis.createClient().
   * @returns {Promise<RedisConsumptionStore>}
   */
  static async createClient(redisOptions = {}) {
    const redis  = await import('redis');
    const client = redis.createClient(redisOptions);
    await client.connect();
    return new RedisConsumptionStore({ client });
  }
}

export { RedisConsumptionStore };
export default { RedisConsumptionStore };

'use strict';

/**
 * ConsumptionStore -- interface for tracking one-time receipt consumption.
 *
 * consume(key): atomically checks whether key has been seen and records it in
 *   a single operation. Returns true if this is the first time (allow), false
 *   if already consumed (terminal refuse). The atomicity of consume is the
 *   whole point -- it must be a single atomic compare-and-set / insert, not a
 *   separate read-then-write.
 *
 * has(key): read-only check. Returns boolean.
 */
class ConsumptionStore {
  // eslint-disable-next-line no-unused-vars
  async consume(_key) { throw new Error('ConsumptionStore: consume() not implemented'); }
  // eslint-disable-next-line no-unused-vars
  async has(_key)     { throw new Error('ConsumptionStore: has() not implemented'); }
}

/**
 * InMemoryConsumptionStore -- Map-backed default implementation.
 *
 * JavaScript is single-threaded, so a synchronous check-and-set is atomic
 * within a single process instance. Both the Map.has() check and Map.set()
 * write happen in one synchronous turn -- no other code can interleave.
 *
 * SINGLE-INSTANCE ONLY. This does NOT provide the global one-time-use
 * guarantee across:
 *   - Multiple verifier instances (e.g. a load-balanced API fleet)
 *   - Process restarts (state is lost on shutdown)
 *
 * Use for testing and single-process development only. For production
 * deployments where oneTimeUse: true receipts must be globally unique, inject
 * a durable store (e.g. RedisConsumptionStore) via the consumptionStore
 * constructor option. The verifier refuses oneTimeUse receipts unless an
 * explicit consumptionStore is provided at construction time.
 */
class InMemoryConsumptionStore extends ConsumptionStore {
  constructor() {
    super();
    /** @private {Map<string, number>} key -> timestamp of first consumption */
    this._consumed = new Map();
  }

  async consume(key) {
    if (this._consumed.has(key)) return false;
    this._consumed.set(key, Date.now());
    return true;
  }

  async has(key) {
    return this._consumed.has(key);
  }
}

export { ConsumptionStore, InMemoryConsumptionStore };
export default { ConsumptionStore, InMemoryConsumptionStore };

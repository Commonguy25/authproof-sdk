'use strict';

/**
 * CAEPEventAdapter -- translates Continuous Access Evaluation Protocol (CAEP)
 * events into RevocationRegistry revocations.
 *
 * Supported event types:
 *   'session.terminated'  -- revokes the receipt bound to the session
 *   'credential.change'   -- revokes the receipt bound to the credential
 *
 * The handler map is extensible: add new event types at runtime without
 * modifying this class:
 *   adapter._handlers['new.event.type'] = async (event) => { ... };
 */
class CAEPEventAdapter {
  /**
   * @param {object}             opts
   * @param {RevocationRegistry} opts.revocationRegistry - Required. Registry to revoke into.
   */
  constructor({ revocationRegistry }) {
    if (!revocationRegistry) throw new Error('CAEPEventAdapter: revocationRegistry is required');
    this._registry = revocationRegistry;
    this._handlers = {
      'session.terminated': this._handleSessionTerminated.bind(this),
      'credential.change':  this._handleCredentialChange.bind(this),
    };
  }

  /**
   * Dispatch a CAEP event to the appropriate handler.
   *
   * Unknown event types are logged and ignored -- they never throw.
   *
   * @param {object} event          - CAEP event object
   * @param {string} event.type     - Event type string (e.g. 'session.terminated')
   * @param {object} [event.subject] - Subject carrying the receiptId
   * @returns {Promise<{ handled: boolean, type: string, receiptId?: string, reason?: string }>}
   */
  async handleEvent(event) {
    const type    = event?.type;
    const handler = this._handlers[type];
    if (!handler) {
      console.warn('CAEPEventAdapter: unknown event type:', type, '-- ignored');
      return { handled: false, type };
    }
    return handler(event);
  }

  async _handleSessionTerminated(event) {
    const receiptId = this._extractReceiptId(event);
    if (!receiptId) return { handled: false, reason: 'no receiptId in event subject' };
    await this._registry.revoke(receiptId, { reason: 'CAEP:session.terminated' });
    return { handled: true, type: 'session.terminated', receiptId };
  }

  async _handleCredentialChange(event) {
    const receiptId = this._extractReceiptId(event);
    if (!receiptId) return { handled: false, reason: 'no receiptId in event subject' };
    await this._registry.revoke(receiptId, { reason: 'CAEP:credential.change' });
    return { handled: true, type: 'credential.change', receiptId };
  }

  _extractReceiptId(event) {
    // CAEP events carry a subject field. Try common shapes.
    return event?.subject?.receiptId
      ?? event?.subject?.identifier
      ?? event?.receiptId
      ?? null;
  }
}

export { CAEPEventAdapter };
export default CAEPEventAdapter;

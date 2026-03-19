import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createTonApiClient } from '../src/tonapi';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

describe('TonApiClient', () => {
  const client = createTonApiClient('https://tonapi.io', 'test-key');

  beforeEach(() => {
    mockFetch.mockReset();
  });

  it('getAccount returns balance and status', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        address: '0:abc123',
        balance: 5000000000,
        status: 'active',
      }),
    });
    const result = await client.getAccount('0:abc123');
    expect(result.balance).toBe(5000000000);
    expect(result.status).toBe('active');
  });

  it('getJettonBalances returns token list', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        balances: [{
          balance: '1000000',
          jetton: { address: '0:usdt', name: 'Tether USD', symbol: 'USDT', decimals: 6 },
        }],
      }),
    });
    const result = await client.getJettonBalances('0:abc123');
    expect(result.balances).toHaveLength(1);
    expect(result.balances[0].jetton.symbol).toBe('USDT');
  });

  it('getTransactions returns events', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        events: [{ event_id: 'evt1', timestamp: 1700000000, actions: [] }],
      }),
    });
    const result = await client.getTransactions('0:abc123', 10);
    expect(result.events).toHaveLength(1);
  });

  it('getNftItems returns NFT list', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        nft_items: [{
          address: '0:nft1',
          metadata: { name: 'Cool NFT' },
          collection: { name: 'Cool Collection' },
        }],
      }),
    });
    const result = await client.getNftItems('0:abc123');
    expect(result.nft_items).toHaveLength(1);
  });

  it('resolveDns returns address', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        wallet: { address: '0:resolved', name: 'alice.ton' },
      }),
    });
    const result = await client.resolveDns('alice.ton');
    expect(result.wallet.address).toBe('0:resolved');
  });

  it('getRates returns prices', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        rates: { TON: { prices: { USD: 2.45 } } },
      }),
    });
    const result = await client.getRates(['TON'], ['USD']);
    expect(result.rates.TON.prices.USD).toBe(2.45);
  });

  it('throws on API error', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false, status: 404,
      json: async () => ({ error: 'not found' }),
    });
    await expect(client.getAccount('0:bad')).rejects.toThrow('tonapi error 404');
  });

  it('works without API key', async () => {
    const noKeyClient = createTonApiClient('https://tonapi.io');
    mockFetch.mockResolvedValueOnce({
      ok: true, json: async () => ({ rates: {} }),
    });
    await noKeyClient.getRates(['TON'], ['USD']);
    const callHeaders = mockFetch.mock.calls[0][1].headers;
    expect(callHeaders.Authorization).toBeUndefined();
  });
});

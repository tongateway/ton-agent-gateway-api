// src/tonapi.ts — tonapi.io v2 client

export interface TonApiClient {
  getAccount(address: string): Promise<any>;
  getJettonBalances(address: string): Promise<any>;
  getTransactions(address: string, limit?: number): Promise<any>;
  getNftItems(address: string, limit?: number): Promise<any>;
  resolveDns(domain: string): Promise<any>;
  getRates(tokens: string[], currencies: string[]): Promise<any>;
}

export function createTonApiClient(baseUrl: string, apiKey?: string): TonApiClient {
  async function call(path: string): Promise<any> {
    const headers: Record<string, string> = {};
    if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;

    const res = await fetch(`${baseUrl}/v2${path}`, { headers });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(`tonapi error ${res.status}: ${data.error ?? JSON.stringify(data)}`);
    }
    return data;
  }

  return {
    getAccount: (address) => call(`/accounts/${encodeURIComponent(address)}`),
    getJettonBalances: (address) => call(`/accounts/${encodeURIComponent(address)}/jettons`),
    getTransactions: (address, limit = 20) => call(`/accounts/${encodeURIComponent(address)}/events?limit=${limit}`),
    getNftItems: (address, limit = 50) => call(`/accounts/${encodeURIComponent(address)}/nfts?limit=${limit}`),
    resolveDns: (domain) => call(`/dns/${encodeURIComponent(domain)}/resolve`),
    getRates: (tokens, currencies) => call(`/rates?tokens=${tokens.join(',')}&currencies=${currencies.join(',')}`),
  };
}

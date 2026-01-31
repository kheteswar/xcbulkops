import type { Credentials, Namespace, LoadBalancer, WAFPolicy, OriginPool, AppType, AppSetting, VirtualSite } from '../types';

const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL;
const SUPABASE_ANON_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY;

class F5XCApiClient {
  private tenant: string | null = null;
  private apiToken: string | null = null;

  init(tenant: string, apiToken: string) {
    this.tenant = tenant;
    this.apiToken = apiToken;
  }

  clear() {
    this.tenant = null;
    this.apiToken = null;
  }

  isInitialized(): boolean {
    return Boolean(this.tenant && this.apiToken);
  }

  getTenant(): string | null {
    return this.tenant;
  }

  private async proxyRequest<T>(endpoint: string, method = 'GET', body?: unknown): Promise<T> {
    if (!this.tenant || !this.apiToken) {
      throw new Error('API client not initialized');
    }

    const proxyUrl = `${SUPABASE_URL}/functions/v1/f5xc-proxy`;

    const response = await fetch(proxyUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${SUPABASE_ANON_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        tenant: this.tenant,
        token: this.apiToken,
        endpoint,
        method,
        body,
      }),
    });

    const data = await response.json();

    if (!response.ok || data.error) {
      throw new Error(data.error || data.message || `API Error: ${response.status}`);
    }

    return data as T;
  }

  async get<T>(path: string): Promise<T> {
    return this.proxyRequest<T>(path, 'GET');
  }

  async getNamespaces(): Promise<{ items: Namespace[] }> {
    return this.get('/api/web/namespaces');
  }

  async getLoadBalancers(namespace: string): Promise<{ items: LoadBalancer[] }> {
    return this.get(`/api/config/namespaces/${namespace}/http_loadbalancers`);
  }

  async getLoadBalancer(namespace: string, name: string): Promise<LoadBalancer> {
    return this.get(`/api/config/namespaces/${namespace}/http_loadbalancers/${name}`);
  }

  async getWAFPolicy(namespace: string, name: string): Promise<WAFPolicy> {
    return this.get(`/api/config/namespaces/${namespace}/app_firewalls/${name}`);
  }

  async getOriginPool(namespace: string, name: string): Promise<OriginPool> {
    return this.get(`/api/config/namespaces/${namespace}/origin_pools/${name}`);
  }

  async getHealthCheck(namespace: string, name: string): Promise<unknown> {
    return this.get(`/api/config/namespaces/${namespace}/healthchecks/${name}`);
  }

  async getAppTypes(): Promise<{ items: AppType[] }> {
    return this.get('/api/config/namespaces/shared/app_types');
  }

  async getAppType(name: string): Promise<AppType> {
    return this.get(`/api/config/namespaces/shared/app_types/${name}`);
  }

  async getAppSettings(namespace: string): Promise<{ items: AppSetting[] }> {
    return this.get(`/api/config/namespaces/${namespace}/app_settings`);
  }

  async getAppSetting(namespace: string, name: string): Promise<AppSetting> {
    return this.get(`/api/config/namespaces/${namespace}/app_settings/${name}`);
  }

  async getVirtualSite(namespace: string, name: string): Promise<VirtualSite> {
    return this.get(`/api/config/namespaces/${namespace}/virtual_sites/${name}`);
  }
}

export const apiClient = new F5XCApiClient();

const STORAGE_KEY = 'xc_bulkops_credentials';

export const storageManager = {
  saveCredentials(credentials: Credentials) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(credentials));
  },

  loadCredentials(): Credentials | null {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  },

  clearCredentials() {
    localStorage.removeItem(STORAGE_KEY);
  },
};

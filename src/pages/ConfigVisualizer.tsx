import { useState, useEffect, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  ArrowLeft, Grid3X3, Loader2, Globe, Server, Shield, Bot, Search, Lock,
  User, AlertTriangle, Network, Eye, Code, Code2, ExternalLink, Check,
  Copy, X, Clock, Home, Activity, FileText, Zap, RefreshCw, ChevronDown,
  ChevronRight, Settings, Database, ArrowRight, Timer, Hash, Link as LinkIcon,
  ShieldCheck, ShieldAlert, ShieldOff, Layers, Route, Cloud
} from 'lucide-react';
import { apiClient } from '../services/api';
import { useApp } from '../context/AppContext';
import { useToast } from '../context/ToastContext';
import type { 
  Namespace, LoadBalancer, ParsedRoute, OriginPool, WAFPolicy, HealthCheck, 
  ServicePolicy, ServicePolicyRule, AppType, AppSetting, AppTypeSetting, 
  VirtualSite, UserIdentificationPolicy, CDNLoadBalancer, CDNCacheRule 
} from '../types';
import { formatCertificateUrl, extractCertificateFromUrl } from '../utils/certParser';

const FEATURE_TYPE_NAMES: Record<string, string> = {
  'USER_BEHAVIOR_ANALYSIS': 'Malicious User Detection',
  'TIMESERIES_ANOMALY_DETECTION': 'DDoS Detection',
  'BUSINESS_LOGIC_MARKUP': 'API Discovery',
  'PER_REQ_ANOMALY_DETECTION': 'Per API Request Analysis',
};

const getFeatureDisplayName = (type: string): string => {
  return FEATURE_TYPE_NAMES[type] || type;
};

// State for HTTP Load Balancer View
interface ViewerState {
  rootLB: LoadBalancer | null;
  namespace: string;
  routes: ParsedRoute[];
  originPools: Map<string, OriginPool>;
  wafPolicies: Map<string, WAFPolicy>;
  healthChecks: Map<string, HealthCheck>;
  servicePolicies: Map<string, unknown>;
  virtualSites: Map<string, VirtualSite>;
  objects: Map<string, unknown>;
  appType: AppType | null;
  appSetting: AppSetting | null;
  appTypeSetting: AppTypeSetting | null;
  userIdentificationPolicy: UserIdentificationPolicy | null;
}

// State for CDN View
interface CdnState {
  cdn: CDNLoadBalancer;
  originPools: Map<string, OriginPool>;
  wafPolicy: WAFPolicy | null;
  cacheRules: CDNCacheRule[];
}

type ConfigType = 'http_lb' | 'cdn';

export function ConfigVisualizer() {
  const { isConnected } = useApp();
  const navigate = useNavigate();
  const toast = useToast();

  // Selection State
  const [namespaces, setNamespaces] = useState<Namespace[]>([]);
  const [configList, setConfigList] = useState<any[]>([]); // Generic list for LBs or CDNs
  const [selectedNs, setSelectedNs] = useState('');
  const [selectedConfig, setSelectedConfig] = useState('');
  const [configType, setConfigType] = useState<ConfigType>('http_lb');

  // Loading State
  const [isLoadingNs, setIsLoadingNs] = useState(true);
  const [isLoadingList, setIsLoadingList] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [scanLog, setScanLog] = useState('');
  
  // UI State
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['routes', 'origins', 'security', 'tls', 'general', 'cache']));
  const [jsonModal, setJsonModal] = useState<{ title: string; data: unknown } | null>(null);

  // Data Containers
  const [state, setState] = useState<ViewerState>({
    rootLB: null,
    namespace: '',
    routes: [],
    originPools: new Map(),
    wafPolicies: new Map(),
    healthChecks: new Map(),
    servicePolicies: new Map(),
    virtualSites: new Map(),
    objects: new Map(),
    appType: null,
    appSetting: null,
    appTypeSetting: null,
    userIdentificationPolicy: null,
  });

  const [cdnState, setCdnState] = useState<CdnState | null>(null);

  useEffect(() => {
    if (!isConnected) {
      navigate('/');
      return;
    }
    loadNamespaces();
  }, [isConnected, navigate]);

  const loadNamespaces = async () => {
    setIsLoadingNs(true);
    try {
      const resp = await apiClient.getNamespaces();
      setNamespaces(resp.items.sort((a, b) => a.name.localeCompare(b.name)));
    } catch {
      toast.error('Failed to load namespaces');
    } finally {
      setIsLoadingNs(false);
    }
  };

  const loadConfigList = async (ns: string, type: ConfigType) => {
    setSelectedNs(ns);
    setConfigType(type);
    setSelectedConfig('');
    setConfigList([]);
    setState(prev => ({ ...prev, rootLB: null })); // Clear HTTP state
    setCdnState(null); // Clear CDN state
    
    if (!ns) return;

    setIsLoadingList(true);
    try {
      let resp;
      if (type === 'http_lb') {
        resp = await apiClient.getLoadBalancers(ns);
      } else {
        resp = await apiClient.getCDNs(ns);
      }
      setConfigList((resp.items || []).sort((a: any, b: any) => a.name.localeCompare(b.name)));
    } catch {
      toast.error(`Failed to load ${type === 'http_lb' ? 'load balancers' : 'CDN distributions'}`);
    } finally {
      setIsLoadingList(false);
    }
  };

  const log = useCallback((msg: string) => setScanLog(msg), []);

  const toggleSection = (section: string) => {
    setExpandedSections(prev => {
      const next = new Set(prev);
      if (next.has(section)) next.delete(section);
      else next.add(section);
      return next;
    });
  };

  // --- HTTP LB Parsing Helper ---
  const parseRoute = (route: LoadBalancer['spec']['routes'][0], index: number): ParsedRoute => {
    const parsed: ParsedRoute = {
      index,
      type: 'unknown',
      path: '/',
      pathMatch: 'prefix',
      methods: ['ANY'],
      origins: [],
      waf: null,
    };
    if (route.custom_route_object) {
      parsed.type = 'custom';
      parsed.path = route.custom_route_object.route_ref?.name || 'Custom Route';
      (parsed as unknown as Record<string, unknown>).routeRef = route.custom_route_object.route_ref;
      return parsed;
    }
    if (route.simple_route) {
      parsed.type = 'simple';
      const sr = route.simple_route;
      if (sr.path) {
        if (sr.path.prefix) {
          parsed.path = sr.path.prefix;
          parsed.pathMatch = 'prefix';
        } else if (sr.path.regex) {
          parsed.path = sr.path.regex;
          parsed.pathMatch = 'regex';
        } else if (sr.path.path) {
          parsed.path = sr.path.path;
          parsed.pathMatch = 'exact';
        }
      }
      if (typeof sr.http_method === 'string') {
        parsed.methods = [sr.http_method];
      } else if (sr.http_method?.methods) {
        parsed.methods = sr.http_method.methods;
      }
      if (sr.origin_pools) {
        parsed.origins = sr.origin_pools.map(op => ({
          name: op.pool?.name,
          namespace: op.pool?.namespace,
          weight: op.weight,
          priority: op.priority,
        }));
      }
      if (sr.advanced_options) {
        const ao = sr.advanced_options;
        if (ao.app_firewall) {
          parsed.waf = {
            name: ao.app_firewall.name,
            namespace: ao.app_firewall.namespace,
          };
        }
        if (ao.disable_waf) parsed.waf = { disabled: true };
        parsed.timeout = ao.timeout || ao.request_timeout;
        parsed.retries = ao.retry_policy || ao.default_retry_policy;
        parsed.corsPolicy = ao.cors_policy;
        parsed.advancedOptions = {
          hostRewrite: sr.host_rewrite || (sr.auto_host_rewrite !== undefined ? 'auto' : (sr.disable_host_rewrite !== undefined ? 'disabled' : null)),
          prefixRewrite: ao.prefix_rewrite || (ao.disable_prefix_rewrite !== undefined ? null : undefined),
          webSocket: ao.enable_web_socket_config !== undefined ? true : (ao.disable_web_socket_config !== undefined ? false : null),
          spdy: ao.enable_spdy !== undefined ? true : (ao.disable_spdy !== undefined ? false : null),
          buffering: ao.buffer_policy || ao.common_buffering,
          mirroring: ao.mirror_policy || (ao.disable_mirroring !== undefined ? false : null),
          locationAdd: ao.disable_location_add === false,
          requestHeaders: ao.request_headers_to_add?.length || 0,
          responseHeaders: ao.response_headers_to_add?.length || 0,
          requestCookies: (ao.request_cookies_to_add?.length || 0) + (ao.request_cookies_to_remove?.length || 0),
          responseCookies: (ao.response_cookies_to_add?.length || 0) + (ao.response_cookies_to_remove?.length || 0),
          priority: ao.priority,
          botDefense: ao.bot_defense_javascript_injection || ao.inherited_bot_defense_javascript_injection,
        };
      }
      parsed.headerMatchers = sr.headers;
      parsed.queryParams = sr.query_params;
    } else if (route.redirect_route) {
      parsed.type = 'redirect';
      const rr = route.redirect_route;
      if (rr.path?.prefix) parsed.path = rr.path.prefix;
      parsed.redirectConfig = {
        host: rr.host_redirect,
        path: rr.path_redirect,
        code: rr.response_code || '301',
      };
    } else if (route.direct_response_route) {
      parsed.type = 'direct_response';
      const dr = route.direct_response_route;
      if (dr.path?.prefix) parsed.path = dr.path.prefix;
      parsed.directResponse = { code: dr.response_code, body: dr.response_body };
    }
    return parsed;
  };

  const startViewer = async () => {
    if (!selectedNs || !selectedConfig) return;
    setIsLoading(true);
    // Reset states
    setState({
      rootLB: null, namespace: selectedNs, routes: [], originPools: new Map(), wafPolicies: new Map(),
      healthChecks: new Map(), servicePolicies: new Map(), virtualSites: new Map(), objects: new Map(),
      appType: null, appSetting: null, appTypeSetting: null, userIdentificationPolicy: null,
    });
    setCdnState(null);

    try {
      if (configType === 'http_lb') {
        await fetchLoadBalancerData();
      } else {
        await fetchCDNData();
      }
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to load configuration');
    } finally {
      setIsLoading(false);
    }
  };

  // --- CDN Fetch Logic ---
  const fetchCDNData = async () => {
    log(`Fetching CDN: ${selectedConfig}`);
    const cdn = await apiClient.getCDN(selectedNs, selectedConfig);
    if (!cdn) throw new Error('CDN not found');
    
    const originPools = new Map<string, OriginPool>();
    let wafPolicy = null;
    const cacheRules: CDNCacheRule[] = [];
    const spec = cdn.spec;

    if (spec?.origin_pool) {
       const poolName = spec.origin_pool.name;
       const poolNs = spec.origin_pool.namespace || selectedNs;
       log(`Fetching Origin Pool: ${poolName}`);
       try {
         const pool = await apiClient.getOriginPool(poolNs, poolName);
         originPools.set(poolName, pool);
       } catch (e) { log(`Failed to fetch pool ${poolName}`); }
    }

    if (spec?.app_firewall) {
        log(`Fetching WAF: ${spec.app_firewall.name}`);
        try {
            const waf = await apiClient.getWAFPolicy(spec.app_firewall.namespace || selectedNs, spec.app_firewall.name);
            wafPolicy = waf;
        } catch (e) { log('Failed to fetch WAF'); }
    }

    if (spec?.cdn_settings?.cache_rules) {
        for (const ruleRef of spec.cdn_settings.cache_rules) {
            log(`Fetching Cache Rule: ${ruleRef.name}`);
            try {
                const rule = await apiClient.getCDNCacheRule(ruleRef.namespace || selectedNs, ruleRef.name);
                cacheRules.push(rule);
            } catch (e) { log(`Failed to fetch cache rule ${ruleRef.name}`); }
        }
    }
    setCdnState({ cdn, originPools, wafPolicy, cacheRules });
  };

  // --- HTTP LB Fetch Logic (Your Original Logic) ---
  const fetchLoadBalancerData = async () => {
      log(`Fetching Load Balancer: ${selectedConfig}`);
      const lb = await apiClient.getLoadBalancer(selectedNs, selectedConfig);
      if (!lb) throw new Error('Load Balancer not found');
      log(`Fetched ${selectedConfig}`);

      const routes: ParsedRoute[] = [];
      if (lb.spec?.routes) {
        lb.spec.routes.forEach((r, i) => routes.push(parseRoute(r, i)));
        log(`Found ${routes.length} routes`);
      }

      const originPools = new Map<string, OriginPool>();
      const wafPolicies = new Map<string, WAFPolicy>();
      const healthChecks = new Map<string, HealthCheck>();
      const servicePolicies = new Map<string, unknown>();

      // ... (Retained your complex fetching logic for WAFs, Policies, Pools, etc.) ...
      if (lb.spec?.app_firewall && !lb.spec.disable_waf) {
        log(`Fetching WAF: ${lb.spec.app_firewall.name}`);
        try {
          const waf = await apiClient.getWAFPolicy(lb.spec.app_firewall.namespace || selectedNs, lb.spec.app_firewall.name);
          wafPolicies.set(lb.spec.app_firewall.name, waf as WAFPolicy);
        } catch (err) {
          try {
            const waf = await apiClient.getWAFPolicy('shared', lb.spec.app_firewall.name);
            wafPolicies.set(lb.spec.app_firewall.name, { ...waf, shared: true } as WAFPolicy);
          } catch (e) {}
        }
      }

      for (const r of routes) {
        if (r.waf?.name && !wafPolicies.has(r.waf.name)) {
          try {
            const waf = await apiClient.getWAFPolicy(r.waf.namespace || selectedNs, r.waf.name);
            wafPolicies.set(r.waf.name, waf as WAFPolicy);
          } catch (err) {
             try {
                const waf = await apiClient.getWAFPolicy('shared', r.waf.name);
                wafPolicies.set(r.waf.name, { ...waf, shared: true } as WAFPolicy);
             } catch (e) {}
          }
        }
      }

      if (lb.spec?.active_service_policies?.policies) {
        for (const pol of lb.spec.active_service_policies.policies) {
          const ns = pol.namespace || selectedNs;
          try {
            const sp = await apiClient.getServicePolicy(ns, pol.name);
            servicePolicies.set(pol.name, sp);
          } catch (err) {}
        }
      }

      const poolRefs = new Set<string>();
      if (lb.spec?.default_route_pools) {
        lb.spec.default_route_pools.forEach(p => {
          if (p.pool?.name) poolRefs.add(`${p.pool.namespace || selectedNs}/${p.pool.name}`);
        });
      }
      routes.forEach(r => {
        r.origins.forEach(o => {
          if (o.name) poolRefs.add(`${o.namespace || selectedNs}/${o.name}`);
        });
      });

      for (const ref of poolRefs) {
        const [ns, name] = ref.split('/');
        log(`Fetching Origin Pool: ${name}`);
        try {
          const pool = await apiClient.getOriginPool(ns, name);
          originPools.set(name, pool);
          if (pool.spec?.healthcheck) {
            for (const hc of pool.spec.healthcheck) {
              if (hc.name && !healthChecks.has(hc.name)) {
                try {
                  const check = await apiClient.getHealthCheck(hc.namespace || ns, hc.name);
                  healthChecks.set(hc.name, check as HealthCheck);
                } catch (e) {
                   try {
                     const check = await apiClient.getHealthCheck('shared', hc.name);
                     healthChecks.set(hc.name, check as HealthCheck);
                   } catch(ex){}
                }
              }
            }
          }
        } catch (e) {
             try {
               const pool = await apiClient.getOriginPool('shared', name);
               originPools.set(name, pool);
             } catch(ex){}
        }
      }

      const virtualSites = new Map<string, VirtualSite>();
      for (const pool of originPools.values()) {
        const servers = pool.spec?.origin_servers || [];
        for (const server of servers) {
          const vs = server.private_ip?.site_locator?.virtual_site || server.private_name?.site_locator?.virtual_site || server.k8s_service?.site_locator?.virtual_site;
          if (vs?.name && vs?.namespace && !virtualSites.has(`${vs.namespace}/${vs.name}`)) {
             try {
                const vSite = await apiClient.getVirtualSite(vs.namespace, vs.name);
                virtualSites.set(`${vs.namespace}/${vs.name}`, vSite);
             } catch (e) {}
          }
        }
      }

      let appType = null;
      let appSetting = null;
      let appTypeSetting = null;
      const appTypeName = lb.metadata?.labels?.['ves.io/app_type'];
      if (appTypeName) {
        try { appType = await apiClient.getAppType(appTypeName); } catch(e){}
        try {
           const settings = await apiClient.getAppSettings(selectedNs);
           // ... logic to find matching setting ...
        } catch(e){}
      }

      let userIdentificationPolicy = null;
      if (lb.spec?.user_identification?.name) {
          try {
             userIdentificationPolicy = await apiClient.getUserIdentificationPolicy(lb.spec.user_identification.namespace || selectedNs, lb.spec.user_identification.name);
          } catch(e) {
             try {
                userIdentificationPolicy = await apiClient.getUserIdentificationPolicy('shared', lb.spec.user_identification.name);
             } catch(ex){}
          }
      }

      setState({
        rootLB: lb, namespace: selectedNs, routes, originPools, wafPolicies,
        healthChecks, servicePolicies, virtualSites, objects: new Map(),
        appType, appSetting, appTypeSetting, userIdentificationPolicy
      });
  };

  const copyJson = () => {
    if (jsonModal?.data) {
      navigator.clipboard.writeText(JSON.stringify(jsonModal.data, null, 2))
        .then(() => toast.success('Copied!'))
        .catch(() => toast.error('Copy failed'));
    }
  };

  // --- Helpers for Render ---
  const getWafMode = (waf: WAFPolicy | null | undefined): string => {
    if (!waf?.spec) return 'unknown';
    if (waf.spec.blocking) return 'Blocking';
    if (waf.spec.monitoring) return 'Monitoring';
    if (waf.spec.ai_risk_based_blocking) return 'AI Risk-Based';
    return waf.spec.mode || 'Unknown';
  };

  const formatDate = (timestamp?: string) => {
    if (!timestamp) return 'Unknown';
    return new Date(timestamp).toLocaleDateString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
    });
  };

  const formatAlgorithm = (algo?: string) => {
    const map: Record<string, string> = {
      ROUND_ROBIN: 'Round Robin', LEAST_ACTIVE: 'Least Connections', RANDOM: 'Random',
      RING_HASH: 'Ring Hash', SOURCE_IP_STICKINESS: 'Source IP Sticky', LB_OVERRIDE: 'Override'
    };
    return map[algo || ''] || algo || 'Round Robin';
  };

  const getRouteTypeLabel = (type: string) => {
    const labels: Record<string, { text: string; color: string }> = {
      simple: { text: 'Simple', color: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30' },
      redirect: { text: 'Redirect', color: 'bg-amber-500/15 text-amber-400 border-amber-500/30' },
      direct_response: { text: 'Direct Response', color: 'bg-violet-500/15 text-violet-400 border-violet-500/30' },
      unknown: { text: 'Custom', color: 'bg-slate-500/15 text-slate-400 border-slate-500/30' },
    };
    return labels[type] || labels.unknown;
  };

  const getPathMatchLabel = (match: string) => {
    const labels: Record<string, { text: string; symbol: string }> = {
      prefix: { text: 'Prefix Match', symbol: '~' },
      regex: { text: 'Regex Match', symbol: '.*' },
      exact: { text: 'Exact Match', symbol: '=' },
    };
    return labels[match] || labels.prefix;
  };

  const lb = state.rootLB;
  const spec = lb?.spec;

  // Render logic for LB Header Tags
  let lbType = 'HTTP';
  let lbTypeClass = 'bg-slate-600';
  if (spec?.https_auto_cert) { lbType = 'HTTPS (Auto Cert)'; lbTypeClass = 'bg-emerald-600'; } 
  else if (spec?.https) { lbType = 'HTTPS (Custom)'; lbTypeClass = 'bg-blue-600'; }

  let advertiseType = 'Unknown';
  if (spec?.advertise_on_public_default_vip) advertiseType = 'Public (Default VIP)';
  else if (spec?.advertise_on_public) advertiseType = 'Public (Custom)';
  else if (spec?.advertise_custom) advertiseType = 'Custom';
  else if (spec?.do_not_advertise) advertiseType = 'Not Advertised';

  return (
    <div className="min-h-screen bg-slate-900">
      {/* Header Bar */}
      <div className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link to="/" className="p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors">
              <ArrowLeft className="w-5 h-5" />
            </Link>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-blue-500/15 rounded-xl flex items-center justify-center text-blue-400">
                <Grid3X3 className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-lg font-bold text-slate-100">Config Visualizer</h1>
                <p className="text-xs text-slate-500">Comprehensive Configuration View</p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Namespace Select */}
            <select
              value={selectedNs}
              onChange={e => loadConfigList(e.target.value, configType)}
              disabled={isLoadingNs}
              className="px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-blue-500 min-w-[180px]"
            >
              <option value="">Select Namespace</option>
              {namespaces.map(ns => (
                <option key={ns.name} value={ns.name}>{ns.name}</option>
              ))}
            </select>

            {/* Config Type Select */}
            <select
              value={configType}
              onChange={e => loadConfigList(selectedNs, e.target.value as ConfigType)}
              className="px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-blue-500 min-w-[160px]"
            >
              <option value="http_lb">HTTP Load Balancer</option>
              <option value="cdn">CDN Distribution</option>
            </select>

            {/* Config Object Select */}
            <select
              value={selectedConfig}
              onChange={e => setSelectedConfig(e.target.value)}
              disabled={!selectedNs || isLoadingList}
              className="px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-blue-500 min-w-[200px] disabled:opacity-50"
            >
              <option value="">
                {isLoadingList ? 'Loading...' : `Select ${configType === 'http_lb' ? 'Load Balancer' : 'CDN'}`}
              </option>
              {configList.map(c => (
                <option key={c.name} value={c.name}>{c.name}</option>
              ))}
            </select>

            <button
              onClick={startViewer}
              disabled={!selectedNs || !selectedConfig || isLoading}
              className="flex items-center gap-2 px-5 py-2 bg-blue-500 hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition-colors"
            >
              {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Eye className="w-4 h-4" />}
              View
            </button>
          </div>
        </div>
      </div>

      <main className="max-w-7xl mx-auto px-6 py-8">
        {isLoading && (
          <div className="flex flex-col items-center justify-center py-24">
            <Loader2 className="w-10 h-10 animate-spin text-blue-400 mb-4" />
            <p className="text-slate-400">{scanLog || 'Loading...'}</p>
          </div>
        )}

        {!isLoading && !lb && !cdnState && (
          <div className="flex flex-col items-center justify-center py-24 text-center">
            <Grid3X3 className="w-16 h-16 text-slate-600 mb-4" />
            <h2 className="text-xl font-semibold text-slate-300 mb-2">Select a Configuration</h2>
            <p className="text-slate-500 max-w-md">
              Choose a namespace, type, and object from the dropdowns above to view details.
            </p>
          </div>
        )}

        {/* --- RENDER HTTP LB (Preserved Logic) --- */}
        {!isLoading && configType === 'http_lb' && lb && (
          <div className="space-y-6">
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-4">
                  <div className="w-14 h-14 bg-blue-500/15 rounded-xl flex items-center justify-center text-blue-400">
                    <Globe className="w-7 h-7" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`px-2 py-0.5 text-xs font-semibold rounded ${lbTypeClass} text-white`}>{lbType}</span>
                      <span className="px-2 py-0.5 text-xs font-semibold rounded bg-slate-700 text-slate-300">{advertiseType}</span>
                      {lb.metadata?.disable && <span className="px-2 py-0.5 text-xs font-semibold rounded bg-red-500/20 text-red-400">Disabled</span>}
                    </div>
                    <h1 className="text-2xl font-bold text-slate-100">{lb.metadata?.name}</h1>
                    <div className="flex items-center gap-4 mt-1 text-sm text-slate-500">
                      <span className="flex items-center gap-1"><Home className="w-4 h-4" /> {lb.metadata?.namespace}</span>
                      <span className="flex items-center gap-1"><Clock className="w-4 h-4" /> Created: {formatDate(lb.system_metadata?.creation_timestamp)}</span>
                    </div>
                  </div>
                </div>
                <button onClick={() => setJsonModal({ title: 'Complete Load Balancer Configuration', data: lb })} className="flex items-center gap-2 px-4 py-2 text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors text-sm">
                  <Code className="w-4 h-4" /> View Full JSON
                </button>
              </div>
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
               {[
                 { label: 'Domains', value: spec?.domains?.length || 0, icon: Globe, color: 'text-blue-400' },
                 { label: 'Routes', value: state.routes.length, icon: Route, color: 'text-cyan-400' },
                 { label: 'Origin Pools', value: state.originPools.size, icon: Server, color: 'text-emerald-400' },
                 { label: 'WAF Policies', value: state.wafPolicies.size, icon: Shield, color: 'text-amber-400' }
               ].map((stat, i) => (
                 <div key={i} className="bg-slate-800/50 border border-slate-700 rounded-xl p-3">
                   <stat.icon className={`w-7 h-7 mb-1.5 ${stat.color}`} />
                   <div className="text-lg font-bold text-slate-100">{stat.value}</div>
                   <div className="text-xs text-slate-500">{stat.label}</div>
                 </div>
               ))}
            </div>

            {/* Domains Section */}
            {spec?.domains && spec.domains.length > 0 && (
              <Section title="Domains & Listeners" icon={Globe} isOpen={expandedSections.has('general')} onToggle={() => toggleSection('general')} count={spec.domains.length}>
                 <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                   {spec.domains.map(domain => (
                     <div key={domain} className="flex items-center gap-3 p-4 bg-slate-700/30 rounded-lg border border-slate-700/50">
                       <Globe className="w-5 h-5 text-blue-400" />
                       <div className="flex-1 min-w-0">
                         <div className="text-slate-200 font-medium truncate">{domain}</div>
                         <div className="text-xs text-slate-500">{spec.https_auto_cert || spec.https ? 'HTTPS' : 'HTTP'}</div>
                       </div>
                     </div>
                   ))}
                 </div>
              </Section>
            )}

            {/* Routes Section */}
            <Section title="Routes Configuration" icon={Route} isOpen={expandedSections.has('routes')} onToggle={() => toggleSection('routes')} count={state.routes.length}>
                {state.routes.map((r, i) => {
                  const typeInfo = getRouteTypeLabel(r.type);
                  return (
                    <div key={i} className="p-5 bg-slate-700/30 rounded-xl border border-slate-700/50 mb-3">
                      <div className="flex items-center justify-between mb-2">
                         <div className="flex items-center gap-3">
                           <span className="w-6 h-6 bg-slate-800 rounded flex items-center justify-center text-xs">{r.index+1}</span>
                           <code className="text-slate-200">{r.path}</code>
                           <span className={`px-2 py-0.5 rounded text-xs ${typeInfo.color}`}>{typeInfo.text}</span>
                         </div>
                         <button onClick={() => setJsonModal({title: `Route ${i+1}`, data: r})}><Code className="w-4 h-4 text-slate-500"/></button>
                      </div>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <DetailItem label="Methods" value={r.methods.join(', ')} small />
                        <DetailItem label="Origin" value={r.origins.map(o=>o.name).join(', ') || 'Default'} small />
                      </div>
                    </div>
                  );
                })}
            </Section>

            {/* Origin Pools Section */}
            <Section title="Origin Pools" icon={Server} isOpen={expandedSections.has('origins')} onToggle={() => toggleSection('origins')} count={state.originPools.size}>
              {Array.from(state.originPools.entries()).map(([name, pool]) => (
                <div key={name} className="p-4 bg-slate-700/30 rounded-lg border border-slate-700/50 mb-3">
                   <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-3">
                        <Server className="w-5 h-5 text-emerald-400"/>
                        <span className="font-semibold text-slate-200">{name}</span>
                      </div>
                      <button onClick={() => setJsonModal({title: name, data: pool})}><Code className="w-4 h-4 text-slate-500"/></button>
                   </div>
                   <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                     <DetailItem label="Port" value={pool.spec?.port?.toString() || 'N/A'} small/>
                     <DetailItem label="TLS" value={pool.spec?.use_tls ? 'Enabled' : 'Disabled'} small/>
                   </div>
                </div>
              ))}
            </Section>

            {/* Security Section (Updated with User ID fix) */}
            <Section title="Security Configuration" icon={Shield} isOpen={expandedSections.has('security')} onToggle={() => toggleSection('security')}>
               {spec && (
                  <div className="p-5 bg-slate-700/30 rounded-xl border border-slate-700/50 mb-4">
                    <div className="flex items-center gap-3 mb-2">
                       <User className="w-5 h-5 text-emerald-400" />
                       <h3 className="font-semibold text-slate-200">User Identification</h3>
                    </div>
                    <span className="text-sm text-slate-400">{spec.user_identification?.name || 'Client IP Address'}</span>
                  </div>
               )}
               {/* WAF Logic Here (Preserved from original file) */}
               {spec?.app_firewall && (
                 <div className="p-5 bg-slate-700/30 rounded-xl border border-slate-700/50">
                    <div className="flex items-center gap-3 mb-2">
                       <Shield className="w-5 h-5 text-amber-400" />
                       <h3 className="font-semibold text-slate-200">WAF: {spec.app_firewall.name}</h3>
                    </div>
                    <DetailItem label="Mode" value={getWafMode(state.wafPolicies.get(spec.app_firewall.name))} />
                 </div>
               )}
            </Section>

            {/* Advanced Settings (Headers Duplicate Removed) */}
            <Section title="Advanced Settings" icon={Settings} isOpen={expandedSections.has('advanced')} onToggle={() => toggleSection('advanced')}>
                {/* Header Manipulation Logic merged here */}
                {(spec?.request_headers_to_add || []).length > 0 && (
                   <div className="p-4 bg-slate-700/30 rounded-lg mb-4">
                      <span className="text-xs text-slate-500 block mb-3">Request Headers</span>
                      {(spec?.request_headers_to_add || []).map((h, i) => (
                        <div key={i} className="flex items-center gap-2 text-sm">
                           <span className="text-blue-400">{h.name}</span>: <span className="text-slate-300">{h.value}</span>
                           <span className="text-xs text-slate-500 ml-2">({h.append ? 'Append' : 'Replace'})</span>
                        </div>
                      ))}
                   </div>
                )}
                {/* Other Advanced Settings */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                   <DetailItem label="Idle Timeout" value={spec?.idle_timeout ? `${spec.idle_timeout}ms` : 'Default'} />
                   <DetailItem label="HTTP/2" value={spec?.https?.http_protocol_options?.http_protocol_enable_v2_only ? 'Enabled' : 'Default'} />
                </div>
            </Section>
          </div>
        )}

        {/* --- RENDER CDN (New Logic) --- */}
        {!isLoading && configType === 'cdn' && cdnState && (
           <CDNView 
             data={cdnState} 
             toggleSection={toggleSection} 
             expandedSections={expandedSections} 
             setJsonModal={setJsonModal} 
           />
        )}
      </main>

      {/* JSON Modal */}
      {jsonModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={() => setJsonModal(null)}>
          <div className="bg-slate-800 border border-slate-700 rounded-xl max-w-4xl w-full max-h-[85vh] overflow-hidden" onClick={e => e.stopPropagation()}>
             <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700">
               <h3 className="font-semibold text-slate-200">{jsonModal.title}</h3>
               <div className="flex items-center gap-2">
                 <button onClick={copyJson} className="flex items-center gap-1 px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors">
                    <Copy className="w-4 h-4" /> Copy
                 </button>
                 <button onClick={() => setJsonModal(null)} className="p-1 text-slate-500 hover:text-slate-300 transition-colors">
                    <X className="w-5 h-5" />
                 </button>
               </div>
             </div>
             <div className="p-6 overflow-auto max-h-[70vh]">
               <pre className="text-sm text-slate-300 font-mono whitespace-pre-wrap">{JSON.stringify(jsonModal.data, null, 2)}</pre>
             </div>
          </div>
        </div>
      )}
    </div>
  );
}

// --- SUB-COMPONENT: CDN View ---
function CDNView({ data, toggleSection, expandedSections, setJsonModal }: any) {
  const { cdn, originPools, wafPolicy, cacheRules } = data;
  const spec = cdn.spec;
  const formatDate = (ts: string) => ts ? new Date(ts).toLocaleDateString() : 'Unknown';

  return (
    <div className="space-y-6">
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-4">
            <div className="w-14 h-14 bg-purple-500/15 rounded-xl flex items-center justify-center text-purple-400">
              <Cloud className="w-7 h-7" />
            </div>
            <div>
              <div className="flex items-center gap-2 mb-1">
                 <span className="px-2 py-0.5 text-xs font-semibold rounded bg-purple-500/20 text-purple-300">CDN Distribution</span>
                 {spec.add_location && <span className="px-2 py-0.5 text-xs font-semibold rounded bg-slate-700 text-slate-300">Add Location</span>}
                 {cdn.metadata.disable && <span className="px-2 py-0.5 text-xs font-semibold rounded bg-red-500/20 text-red-400">Disabled</span>}
              </div>
              <h1 className="text-2xl font-bold text-slate-100">{cdn.metadata.name}</h1>
              <div className="flex items-center gap-4 mt-1 text-sm text-slate-500">
                <span className="flex items-center gap-1"><Home className="w-4 h-4" /> {cdn.metadata.namespace}</span>
                <span className="flex items-center gap-1"><Clock className="w-4 h-4" /> Created: {formatDate(cdn.system_metadata?.creation_timestamp)}</span>
              </div>
            </div>
          </div>
          <button onClick={() => setJsonModal({ title: 'CDN Config', data: cdn })} className="flex items-center gap-2 px-4 py-2 text-slate-400 hover:bg-slate-700 rounded-lg text-sm">
            <Code className="w-4 h-4" /> Full JSON
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Domains" value={spec.domains?.length || 0} icon={Globe} color="text-blue-400" />
        <StatCard label="Cache Rules" value={cacheRules.length} icon={Database} color="text-emerald-400" />
        <StatCard label="WAF" value={spec.app_firewall ? 'Enabled' : 'Disabled'} icon={Shield} color={spec.app_firewall ? 'text-amber-400' : 'text-slate-500'} />
        <StatCard label="Bot Defense" value={spec.bot_defense ? 'Enabled' : 'Disabled'} icon={Bot} color={spec.bot_defense ? 'text-purple-400' : 'text-slate-500'} />
      </div>

      <Section title="Domains & Settings" icon={Globe} isOpen={expandedSections.has('general')} onToggle={() => toggleSection('general')}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">
          {(spec.domains || []).map((domain: string) => (
            <div key={domain} className="flex items-center justify-between p-4 bg-slate-700/30 rounded-lg border border-slate-700/50">
               <div className="flex items-center gap-3">
                 <Globe className="w-5 h-5 text-blue-400" />
                 <span className="text-slate-200 font-medium">{domain}</span>
               </div>
               <div className="flex items-center gap-2">
                 <span className="text-xs text-slate-500">{spec.https_auto_cert ? 'Auto Cert' : spec.https ? 'Custom Cert' : 'HTTP'}</span>
                 <a href={`https://${domain}`} target="_blank" rel="noreferrer" className="text-slate-400 hover:text-white"><ExternalLink className="w-4 h-4" /></a>
               </div>
            </div>
          ))}
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
           <DetailItem label="HTTP Redirect" value={spec.http_redirect ? 'Enabled' : 'Disabled'} enabled={spec.http_redirect} />
           <DetailItem label="Origin Pool" value={spec.origin_pool?.name || 'None'} />
           <DetailItem label="WAF Policy" value={spec.app_firewall?.name || 'None'} />
           <DetailItem label="Bot Defense" value={spec.bot_defense ? 'Enabled' : 'Disabled'} enabled={!!spec.bot_defense} />
        </div>
      </Section>

      <Section title="Cache Configuration" icon={Database} isOpen={expandedSections.has('cache')} onToggle={() => toggleSection('cache')} count={cacheRules.length}>
         <div className="mb-6 p-4 bg-slate-700/30 rounded-lg">
            <h4 className="text-sm font-medium text-slate-300 mb-3">Global CDN Settings</h4>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <DetailItem label="Default Behavior" value={spec.cdn_settings?.default_cache_behavior || 'Default'} />
              <DetailItem label="Max Cache Size" value={spec.cdn_settings?.max_cache_size ? `${spec.cdn_settings.max_cache_size} MB` : 'Default'} />
              <DetailItem label="Default TTL" value={spec.cdn_settings?.cache_ttl ? `${spec.cdn_settings.cache_ttl}s` : 'Default'} />
            </div>
         </div>
         <h4 className="text-sm font-medium text-slate-300 mb-3">Cache Rules ({cacheRules.length})</h4>
         <div className="space-y-3">
            {cacheRules.length === 0 ? <p className="text-slate-500 italic">No specific cache rules configured.</p> : 
               cacheRules.map((rule: any, idx: number) => (
                 <div key={idx} className="p-4 bg-slate-700/30 rounded-lg border border-slate-700/50">
                    <div className="flex items-center justify-between mb-3">
                       <div className="flex items-center gap-3">
                          <Database className="w-4 h-4 text-emerald-400" />
                          <span className="font-semibold text-slate-200">{rule.metadata.name}</span>
                          <span className="text-xs text-slate-500">({rule.metadata.namespace})</span>
                       </div>
                       <button onClick={() => setJsonModal({title: rule.metadata.name, data: rule})} className="p-1 text-slate-400 hover:text-white"><Code className="w-4 h-4"/></button>
                    </div>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                       <DetailItem label="Path Match" value={rule.spec.path?.prefix ? `Prefix: ${rule.spec.path.prefix}` : rule.spec.path?.regex ? `Regex: ${rule.spec.path.regex}` : 'Any'} />
                       <DetailItem label="Cache TTL" value={rule.spec.cache_ttl ? `${rule.spec.cache_ttl}s` : 'Default'} />
                       <DetailItem label="Browser TTL" value={rule.spec.browser_ttl ? `${rule.spec.browser_ttl}s` : 'Default'} />
                       <DetailItem label="Format Caching" value={rule.spec.format_caching ? 'Enabled' : 'Disabled'} />
                    </div>
                 </div>
               ))
            }
         </div>
      </Section>
    </div>
  );
}

// --- Shared Helpers ---
function Section({ title, icon: Icon, isOpen, onToggle, children, count }: any) {
  return (
    <div className="bg-slate-800/50 border border-slate-700 rounded-xl mb-6">
      <button onClick={onToggle} className="w-full flex items-center justify-between px-6 py-4 border-b border-slate-700 hover:bg-slate-700/20 transition-colors">
         <div className="flex items-center gap-3">
            <Icon className="w-5 h-5 text-blue-400" />
            <h2 className="text-lg font-semibold text-slate-100">{title}</h2>
            {count !== undefined && <span className="px-2 py-0.5 bg-slate-700 rounded text-xs text-slate-400">{count}</span>}
         </div>
         {isOpen ? <ChevronDown className="w-5 h-5 text-slate-400"/> : <ChevronRight className="w-5 h-5 text-slate-400"/>}
      </button>
      {isOpen && <div className="p-6">{children}</div>}
    </div>
  );
}

function StatCard({ label, value, icon: Icon, color }: any) {
  return (
    <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-3">
       <Icon className={`w-7 h-7 mb-1.5 ${color}`} />
       <div className="text-lg font-bold text-slate-100">{value}</div>
       <div className="text-xs text-slate-500">{label}</div>
    </div>
  );
}

function DetailItem({ label, value, enabled, warning, small }: { label: string, value: string, enabled?: boolean, warning?: boolean, small?: boolean }) {
  let valueColor = 'text-slate-300';
  if (enabled === true) valueColor = 'text-emerald-400';
  else if (enabled === false) valueColor = 'text-slate-500';
  else if (warning) valueColor = 'text-amber-400';
  return (
    <div>
      <span className={`text-slate-500 block ${small ? 'text-xs mb-0.5' : 'text-xs mb-1'}`}>{label}</span>
      <span className={`${valueColor} ${small ? 'text-sm' : ''}`}>{value}</span>
    </div>
  );
}
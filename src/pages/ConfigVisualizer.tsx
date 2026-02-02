import { useState, useEffect, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  Grid3X3,
  Loader2,
  Globe,
  Server,
  Shield,
  Bot,
  Search,
  Lock,
  User,
  AlertTriangle,
  Network,
  Eye,
  Code,
  Code2,
  ExternalLink,
  Check,
  Copy,
  X,
  Clock,
  Home,
  Activity,
  FileText,
  Zap,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  Settings,
  Database,
  ArrowRight,
  Timer,
  Hash,
  Link as LinkIcon,
  ShieldCheck,
  ShieldAlert,
  ShieldOff,
  Layers,
  Route,
  Cloud,
  HardDrive,
} from 'lucide-react';
import { apiClient } from '../services/api';
import { useApp } from '../context/AppContext';
import { useToast } from '../context/ToastContext';
import type { Namespace, LoadBalancer, CDNLoadBalancer, CDNCacheRule, ParsedRoute, OriginPool, WAFPolicy, HealthCheck, ServicePolicy, ServicePolicyRule, AppType, AppSetting, AppTypeSetting, VirtualSite, UserIdentificationPolicy } from '../types';
import { formatCertificateUrl, extractCertificateFromUrl } from '../utils/certParser';


function isDefined<T>(v: T | null | undefined): v is T {
  return v !== undefined && v !== null;
}

const FEATURE_TYPE_NAMES: Record<string, string> = {
  'USER_BEHAVIOR_ANALYSIS': 'Malicious User Detection',
  'TIMESERIES_ANOMALY_DETECTION': 'DDoS Detection',
  'BUSINESS_LOGIC_MARKUP': 'API Discovery',
  'PER_REQ_ANOMALY_DETECTION': 'Per API Request Analysis',
};

const getFeatureDisplayName = (type: string): string => {
  return FEATURE_TYPE_NAMES[type] || type;
};

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
  rootCDN: CDNLoadBalancer | null;
  cacheRules: Map<string, CDNCacheRule>;
}

export function ConfigVisualizer() {
  const { isConnected } = useApp();
  const navigate = useNavigate();
  const toast = useToast();

  const [selectedType, setSelectedType] = useState<'http' | 'cdn'>('http');

  const [namespaces, setNamespaces] = useState<Namespace[]>([]);
  const [resourceList, setResourceList] = useState<Array<{ name: string }>>([]);
  const [selectedNs, setSelectedNs] = useState('');
  const [selectedResource, setSelectedResource] = useState(''); 
  const [isLoadingNs, setIsLoadingNs] = useState(true);
  const [isLoadingResources, setIsLoadingResources] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [scanLog, setScanLog] = useState('');
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['routes', 'origins', 'security', 'tls', 'caching', 'apptype']));

  const [state, setState] = useState<ViewerState>({
    rootLB: null,
    rootCDN: null,
    cacheRules: new Map(),
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

  const [jsonModal, setJsonModal] = useState<{ title: string; data: unknown } | null>(null);

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

  const loadResources = async (ns: string, type: 'http' | 'cdn') => {
    setSelectedNs(ns);
    setSelectedResource(''); // Reset selection
    setResourceList([]);
    
    if (!ns) return;

    setIsLoadingResources(true); // You can keep using isLoadingLbs or rename it to isLoadingResources
    try {
      if (type === 'http') {
        const resp = await apiClient.getLoadBalancers(ns);
        setResourceList((resp.items || []).sort((a, b) => a.name.localeCompare(b.name)));
      } else {
        const resp = await apiClient.getCDNs(ns);
        setResourceList((resp.items || []).sort((a, b) => a.name.localeCompare(b.name)));
      }
    } catch {
      toast.error(`Failed to load ${type.toUpperCase()} resources`);
    } finally {
      setIsLoadingResources(false);
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
    if (!selectedNs || !selectedResource) return;
    setIsLoading(true);

    // NEW: Force all sections to expand when loading a new resource
    setExpandedSections(new Set([
      'routes', 
      'origins', 
      'security', 
      'tls', 
      'caching', 
      'apptype'
    ]));
    
    // Reset state
    const newState: ViewerState = {
      rootLB: null,
      rootCDN: null,
      namespace: selectedNs,
      routes: [],
      originPools: new Map(),
      wafPolicies: new Map(),
      healthChecks: new Map(),
      servicePolicies: new Map(),
      virtualSites: new Map(),
      objects: new Map(),
      cacheRules: new Map(),
      appType: null,
      appSetting: null,
      appTypeSetting: null,
      userIdentificationPolicy: null,
    };

    try {
      if (selectedType === 'http') {
        // --- HTTP Load Balancer Logic ---
        log(`Fetching HTTP LB: ${selectedResource}`);
        const lb = await apiClient.getLoadBalancer(selectedNs, selectedResource);
        if (!lb) throw new Error('Load Balancer not found');
        newState.rootLB = lb;

        // Parse Routes
        if (lb.spec?.routes) {
            lb.spec.routes.forEach((r, i) => newState.routes.push(parseRoute(r, i)));
            log(`Found ${newState.routes.length} routes`);
        }
        
        // Fetch Dependencies (WAF, Pools, etc)
        await fetchDependencies(lb, newState, selectedNs);

      } else {
        // --- CDN Load Balancer Logic ---
        log(`Fetching CDN: ${selectedResource}`);
        const cdn = await apiClient.getCDN(selectedNs, selectedResource);
        if (!cdn) throw new Error('CDN not found');
        newState.rootCDN = cdn;
        
        // Fetch Dependencies for CDN
        await fetchCDNDependencies(cdn, newState, selectedNs);
      }

      setState(newState);
      log('Report generated.');

    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to load');
      console.error(e);
    } finally {
      setIsLoading(false);
    }
  };

  // --- HELPER FUNCTIONS ---

  const fetchDependencies = async (lb: LoadBalancer, state: ViewerState, ns: string) => {
    // 1. WAF
    if (lb.spec?.app_firewall && !lb.spec.disable_waf) {
        await fetchWAF(lb.spec.app_firewall.name, lb.spec.app_firewall.namespace || ns, state);
    }
    // Route WAFs
    for (const r of state.routes) {
        if (r.waf?.name && !state.wafPolicies.has(r.waf.name)) {
            await fetchWAF(r.waf.name, r.waf.namespace || ns, state);
        }
    }

    // 2. Origin Pools (HTTP LB uses references)
    const poolRefs = new Set<string>();
    if (lb.spec?.default_route_pools) {
        lb.spec.default_route_pools.forEach(p => {
          if (p.pool?.name) poolRefs.add(`${p.pool.namespace || ns}/${p.pool.name}`);
        });
    }
    state.routes.forEach(r => {
        r.origins.forEach(o => {
          if (o.name) poolRefs.add(`${o.namespace || ns}/${o.name}`);
        });
    });
    
    await fetchOriginPools(poolRefs, state, ns);

    // 3. Service Policies
    if (lb.spec?.active_service_policies?.policies) {
        for (const pol of lb.spec.active_service_policies.policies) {
             try {
                const sp = await apiClient.getServicePolicy(pol.namespace || ns, pol.name);
                state.servicePolicies.set(pol.name, sp);
             } catch(e) { console.warn(e); }
        }
    }

    // 4. App Type / User ID
    await fetchAppTypesAndSecurity(lb, state, ns);
  };

  const fetchCDNDependencies = async (cdn: CDNLoadBalancer, state: ViewerState, ns: string) => {
      const spec = cdn.spec as any;
      
      // 1. Origin Pool: 
      // Skip fetching external pools unless explicitly referenced. 
      // Most CDNs use inline definitions which we handle in Render.

      // 2. WAF
      if (spec?.app_firewall) {
          await fetchWAF(spec.app_firewall.name, spec.app_firewall.namespace || ns, state);
      }

      // 3. Cache Rules (Look in both cdn_settings and custom_cache_rule)
      const cacheRulesList = spec?.cdn_settings?.cache_rules || spec?.custom_cache_rule?.cdn_cache_rules || [];
      for (const ruleRef of cacheRulesList) {
          if (ruleRef.name) {
              log(`Fetching Cache Rule: ${ruleRef.name}`);
              try {
                  const rule = await apiClient.getCDNCacheRule(ruleRef.namespace || ns, ruleRef.name);
                  state.cacheRules.set(ruleRef.name, rule);
              } catch (e) {
                  log(`Failed to fetch cache rule ${ruleRef.name}`);
              }
          }
      }
      
      // 4. User Identification
      if (spec?.user_identification) {
          try {
             const uid = await apiClient.getUserIdentificationPolicy(
                 spec.user_identification.namespace || ns, 
                 spec.user_identification.name
             );
             state.userIdentificationPolicy = uid;
          } catch (e) { console.log('Failed to fetch User ID policy'); }
      }
  };

  const fetchWAF = async (name: string, ns: string, state: ViewerState) => {
    log(`Fetching WAF: ${name}`);
    try {
        const waf = await apiClient.getWAFPolicy(ns, name);
        state.wafPolicies.set(name, waf);
    } catch {
        try {
            const waf = await apiClient.getWAFPolicy('shared', name);
            state.wafPolicies.set(name, { ...waf, shared: true } as WAFPolicy);
        } catch { log(`Failed to fetch WAF ${name}`); }
    }
  };

  const fetchOriginPools = async (refs: Set<string>, state: ViewerState, currentNs: string) => {
      for (const ref of refs) {
          const [ns, name] = ref.split('/');
          if (state.originPools.has(name)) continue;
          
          log(`Fetching Pool: ${name}`);
          try {
              const pool = await apiClient.getOriginPool(ns, name);
              state.originPools.set(name, pool);
              
              if (pool.spec?.healthcheck) {
                  for (const hc of pool.spec.healthcheck) {
                      if (hc.name && !state.healthChecks.has(hc.name)) {
                          try {
                              const check = await apiClient.getHealthCheck(hc.namespace || ns, hc.name);
                              state.healthChecks.set(hc.name, check as HealthCheck);
                          } catch { /* Try shared */ }
                      }
                  }
              }
          } catch {
              try {
                  const pool = await apiClient.getOriginPool('shared', name);
                  state.originPools.set(name, pool);
              } catch { log(`Failed to fetch pool ${name}`); }
          }
      }
      
      // Populate Virtual Sites from Pools
      for (const pool of state.originPools.values()) {
        const servers = pool.spec?.origin_servers || [];
        for (const server of servers) {
          const vs = server.private_ip?.site_locator?.virtual_site ||
                     server.private_name?.site_locator?.virtual_site ||
                     server.k8s_service?.site_locator?.virtual_site;
          if (vs?.name && vs?.namespace && !state.virtualSites.has(`${vs.namespace}/${vs.name}`)) {
             try {
                 const vSite = await apiClient.getVirtualSite(vs.namespace, vs.name);
                 state.virtualSites.set(`${vs.namespace}/${vs.name}`, vSite);
             } catch {}
          }
        }
      }
  };

  const fetchAppTypesAndSecurity = async (lb: LoadBalancer, state: ViewerState, ns: string) => {
      const appTypeName = lb.metadata?.labels?.['ves.io/app_type'];
      if (appTypeName) {
        try {
            state.appType = await apiClient.getAppType(appTypeName);
            const appSettingsResp = await apiClient.getAppSettings(ns);
            if (appSettingsResp.items?.length > 0) {
                for (const setting of appSettingsResp.items) {
                  const spec = setting.spec || setting.get_spec;
                  const matching = spec?.app_type_settings?.find((ats: AppTypeSetting) => ats.app_type_ref?.name === appTypeName);
                  if (matching) {
                    state.appSetting = setting;
                    state.appTypeSetting = matching;
                    break;
                  }
                }
            }
        } catch {}
      }
      if (lb.spec?.user_identification?.name) {
          try {
              state.userIdentificationPolicy = await apiClient.getUserIdentificationPolicy(
                  lb.spec.user_identification.namespace || ns, 
                  lb.spec.user_identification.name
              );
          } catch {}
      }
  };

  const getWafMode = (waf: WAFPolicy | null | undefined): string => {
    if (!waf?.spec) return 'unknown';
    if (waf.spec.blocking) return 'Blocking';
    if (waf.spec.monitoring) return 'Monitoring';
    if (waf.spec.ai_risk_based_blocking) return 'AI Risk-Based';
    if (waf.spec.mode) return waf.spec.mode;
    return 'Unknown';
  };

  const formatDate = (timestamp?: string) => {
    if (!timestamp) return 'Unknown';
    return new Date(timestamp).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const formatAlgorithm = (algo?: string) => {
    const map: Record<string, string> = {
      ROUND_ROBIN: 'Round Robin',
      LEAST_ACTIVE: 'Least Connections',
      RANDOM: 'Random',
      RING_HASH: 'Ring Hash',
      SOURCE_IP_STICKINESS: 'Source IP Sticky',
      LB_OVERRIDE: 'Override',
    };
    return map[algo || ''] || algo || 'Round Robin';
  };

  const copyJson = () => {
    if (jsonModal?.data) {
      navigator.clipboard
        .writeText(JSON.stringify(jsonModal.data, null, 2))
        .then(() => toast.success('Copied!'))
        .catch(() => toast.error('Copy failed'));
    }
  };

  const lb = state.rootLB;
  const spec = lb?.spec;

  let lbType = 'HTTP';
  let lbTypeClass = 'bg-slate-600';
  if (spec?.https_auto_cert) {
    lbType = 'HTTPS (Auto Cert)';
    lbTypeClass = 'bg-emerald-600';
  } else if (spec?.https) {
    lbType = 'HTTPS (Custom)';
    lbTypeClass = 'bg-blue-600';
  }

  let advertiseType = 'Unknown';
  if (spec?.advertise_on_public_default_vip) advertiseType = 'Public (Default VIP)';
  else if (spec?.advertise_on_public) advertiseType = 'Public (Custom)';
  else if (spec?.advertise_custom) advertiseType = 'Custom';
  else if (spec?.do_not_advertise) advertiseType = 'Not Advertised';

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

  const renderHTTPLBContent = () => {
    const lb = state.rootLB!;
    const spec = lb.spec as any;
    const sysMeta = lb.system_metadata as any;

    // Helper to calculate stats
    const routeCount = state.routes.length;
    const poolCount = state.originPools.size;
    const wafEnabled = spec.app_firewall && !spec.disable_waf;
    const botEnabled = !spec.disable_bot_defense;
    const ipRepEnabled = !spec.disable_ip_reputation;
    
    // Determine advertise type
    const advertiseType = spec.advertise_on_public_default_vip
      ? 'Public Default VIP'
      : spec.advertise_on_public
      ? 'Public Custom'
      : 'Custom/Internal';

    return (
      <div className="space-y-6">
        {/* 1. Header & Meta */}
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-4">
              <div className="w-14 h-14 bg-blue-500/15 rounded-xl flex items-center justify-center text-blue-400">
                <Globe className="w-7 h-7" />
              </div>
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="px-2 py-0.5 text-xs font-semibold rounded bg-blue-600 text-white">HTTP Load Balancer</span>
                  <span className="px-2 py-0.5 text-xs font-semibold rounded bg-slate-700 text-slate-300">{advertiseType}</span>
                  {lb.metadata?.disable && (
                    <span className="px-2 py-0.5 text-xs font-semibold rounded bg-red-500/20 text-red-400">Disabled</span>
                  )}
                </div>
                <h1 className="text-2xl font-bold text-slate-100">{lb.metadata?.name}</h1>
                <div className="flex flex-wrap items-center gap-4 mt-2 text-sm text-slate-500">
                  <span className="flex items-center gap-1"><Home className="w-4 h-4" /> {lb.metadata?.namespace}</span>
                  <span className="flex items-center gap-1"><Clock className="w-4 h-4" /> Created: {formatDate(sysMeta?.creation_timestamp)}</span>
                  {sysMeta?.modification_timestamp && (
                    <span className="flex items-center gap-1"><RefreshCw className="w-3.5 h-3.5" /> Modified: {formatDate(sysMeta.modification_timestamp)}</span>
                  )}
                  {sysMeta?.creator_id && (
                    <span className="flex items-center gap-1"><User className="w-3.5 h-3.5" /> Creator: {sysMeta.creator_id}</span>
                  )}
                </div>
              </div>
            </div>
            <button
              onClick={() => setJsonModal({ title: 'Complete Load Balancer Configuration', data: lb })}
              className="flex items-center gap-2 px-4 py-2 text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors text-sm"
            >
              <Code className="w-4 h-4" /> JSON
            </button>
          </div>
        </div>

        {/* 2. Stats Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
          {[
            { label: 'Domains', value: spec.domains?.length || 0, icon: Globe, color: 'text-blue-400' },
            { label: 'Routes', value: routeCount, icon: Route, color: 'text-cyan-400' },
            { label: 'Pools', value: poolCount, icon: Server, color: 'text-emerald-400' },
            { label: 'WAF', value: wafEnabled ? 'Enabled' : 'Disabled', icon: Shield, color: wafEnabled ? 'text-emerald-400' : 'text-slate-500' },
            { label: 'Bot Defense', value: botEnabled ? 'Enabled' : 'Disabled', icon: Bot, color: botEnabled ? 'text-purple-400' : 'text-slate-500' },
            { label: 'IP Reputation', value: ipRepEnabled ? 'Enabled' : 'Disabled', icon: ShieldAlert, color: ipRepEnabled ? 'text-rose-400' : 'text-slate-500' },
          ].map(stat => (
            <div key={stat.label} className="bg-slate-800/50 border border-slate-700 rounded-xl p-3">
              <div className={`w-7 h-7 mb-1.5 ${stat.color}`}><stat.icon className="w-full h-full" /></div>
              <div className="text-lg font-bold text-slate-100">{stat.value}</div>
              <div className="text-xs text-slate-500">{stat.label}</div>
            </div>
          ))}
        </div>

        {/* 3. Domains & DNS Info (Updated) */}
        <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
            <div className="flex items-center gap-3 px-6 py-4 border-b border-slate-700">
            <Globe className="w-5 h-5 text-blue-400" />
            <h2 className="text-lg font-semibold text-slate-100">Domains & Listeners</h2>
            </div>
            <div className="p-6 space-y-4">
                <div className="flex flex-wrap gap-2">
                    {spec.domains?.map((d: string) => (
                    <div key={d} className="px-3 py-2 bg-slate-700/30 rounded border border-slate-700/50 text-slate-200 font-mono text-sm flex items-center gap-2">
                        {d}
                        <a href={`https://${d}`} target="_blank" rel="noreferrer" className="text-blue-400 hover:text-blue-300"><ExternalLink className="w-3 h-3"/></a>
                    </div>
                    ))}
                </div>
                
                {/* VIP and CNAME Details */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4 mt-2 border-t border-slate-700/50">
                    <div className="p-3 bg-slate-900/40 rounded border border-slate-700/50 flex flex-col justify-center">
                         <span className="text-xs text-slate-500 block mb-1 flex items-center gap-1"><Network className="w-3 h-3" /> CNAME Record</span>
                         <code className="text-cyan-400 text-sm break-all select-all">{spec.host_name || 'N/A'}</code>
                    </div>
                    <div className="p-3 bg-slate-900/40 rounded border border-slate-700/50 flex flex-col justify-center">
                         <span className="text-xs text-slate-500 block mb-1 flex items-center gap-1"><Globe className="w-3 h-3" /> DNS VIP (IP)</span>
                         <code className="text-emerald-400 text-sm select-all">{spec.dns_info?.[0]?.ip_address || 'Pending'}</code>
                    </div>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-2">
                    <DetailItem label="HTTPS Port" value={spec.https?.port || spec.https_auto_cert?.port || 'N/A'} />
                    <DetailItem label="HTTP Redirect" value={spec.https_auto_cert?.http_redirect || spec.https?.http_redirect ? 'Enabled' : 'Disabled'} enabled={spec.https_auto_cert?.http_redirect || spec.https?.http_redirect} />
                    <DetailItem label="HSTS" value={spec.https_auto_cert?.add_hsts || spec.https?.add_hsts ? 'Enabled' : 'Disabled'} enabled={spec.https_auto_cert?.add_hsts || spec.https?.add_hsts} />
                    <DetailItem label="HTTP/2" value={!spec.disable_http2 ? 'Enabled' : 'Disabled'} />
                </div>
            </div>
        </section>

        {/* 4. TLS & Certificates (Updated) */}
        <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
             <button onClick={() => toggleSection('tls')} className="w-full flex items-center justify-between gap-3 px-6 py-4 border-b border-slate-700 hover:bg-slate-700/20">
                 <div className="flex items-center gap-3">
                     <Lock className="w-5 h-5 text-amber-400" />
                     <h2 className="text-lg font-semibold text-slate-100">TLS & Certificates</h2>
                 </div>
                 {expandedSections.has('tls') ? <ChevronDown className="w-5 h-5 text-slate-400" /> : <ChevronRight className="w-5 h-5 text-slate-400" />}
             </button>
             
             {expandedSections.has('tls') && (
                 <div className="p-6 space-y-6">
                     {/* Auto Cert Details */}
                     {spec.https_auto_cert && (
                         <div className="p-4 bg-slate-700/30 rounded-lg border border-slate-700/50">
                             <div className="flex items-center justify-between mb-3">
                                 <span className="text-sm font-medium text-slate-200">Auto Certificate (Let's Encrypt)</span>
                                 <span className={`px-2 py-0.5 rounded text-xs ${spec.cert_state === 'CertificateValid' || spec.auto_cert_info?.auto_cert_state === 'CertificateValid' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'}`}>
                                    {spec.cert_state || spec.auto_cert_info?.auto_cert_state || 'Unknown'}
                                 </span>
                             </div>
                             
                             <div className="grid grid-cols-2 gap-4 mb-4">
                                <DetailItem 
                                    label="Expiry Date" 
                                    value={spec.auto_cert_info?.auto_cert_expiry ? new Date(spec.auto_cert_info.auto_cert_expiry).toLocaleString() : 'N/A'} 
                                />
                                <DetailItem label="Subject" value={spec.auto_cert_info?.auto_cert_subject || 'N/A'} small />
                             </div>

                             {/* ACME DNS Records */}
                             {spec.auto_cert_info?.dns_records && spec.auto_cert_info.dns_records.length > 0 && (
                                 <div className="mt-3 pt-3 border-t border-slate-700/50">
                                     <span className="text-xs text-amber-400 block mb-2 flex items-center gap-2">
                                        <AlertTriangle className="w-3 h-3" /> ACME Challenge DNS Records
                                     </span>
                                     <div className="space-y-2">
                                         {spec.auto_cert_info.dns_records.map((rec: any, idx: number) => (
                                             <div key={idx} className="bg-slate-800/50 p-2 rounded text-xs font-mono flex flex-col md:flex-row gap-2">
                                                 <span className="text-slate-400 font-bold">{rec.type}</span>
                                                 <span className="text-slate-300">{rec.name}</span>
                                                 <span className="text-slate-500">→</span>
                                                 <span className="text-cyan-300 select-all">{rec.value}</span>
                                             </div>
                                         ))}
                                     </div>
                                 </div>
                             )}
                         </div>
                     )}

                     {/* Custom Cert Details */}
                     {spec.https?.tls_cert_params?.certificates?.map((cert: any, idx: number) => (
                        <div key={idx} className="p-4 bg-slate-700/30 rounded-lg border border-slate-700/50 flex justify-between items-center">
                            <div>
                                <span className="text-xs text-slate-500 block">Custom Certificate</span>
                                <span className="text-slate-200">{cert.name}</span>
                            </div>
                            <span className="px-2 py-1 bg-slate-800 rounded text-xs text-slate-400">Namespace: {cert.namespace || 'shared'}</span>
                        </div>
                     ))}
                 </div>
             )}
        </section>

        {/* 5. Access Control (Updated with Actions) */}
        {(spec.trusted_clients?.length > 0 || spec.blocked_clients?.length > 0) && (
            <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
                 <button onClick={() => toggleSection('security')} className="w-full flex items-center justify-between gap-3 px-6 py-4 border-b border-slate-700 hover:bg-slate-700/20">
                     <div className="flex items-center gap-3">
                         <ShieldAlert className="w-5 h-5 text-rose-400" />
                         <h2 className="text-lg font-semibold text-slate-100">Access Control Lists</h2>
                     </div>
                     {expandedSections.has('security') ? <ChevronDown className="w-5 h-5 text-slate-400" /> : <ChevronRight className="w-5 h-5 text-slate-400" />}
                 </button>

                 {expandedSections.has('security') && (
                    <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
                        {/* Trusted Clients */}
                        <div>
                            <h4 className="text-sm font-medium text-emerald-400 mb-3 flex items-center gap-2">
                                <User className="w-4 h-4" /> Trusted Clients (Allow)
                            </h4>
                            <div className="space-y-2">
                                {spec.trusted_clients?.length > 0 ? spec.trusted_clients.map((c: any, i: number) => (
                                    <div key={i} className="p-3 bg-emerald-500/5 border border-emerald-500/20 rounded">
                                        <div className="flex justify-between items-start">
                                            <span className="text-emerald-300 font-mono text-sm">{c.ip_prefix}</span>
                                            {c.metadata?.name && <span className="text-xs text-slate-500">{c.metadata.name}</span>}
                                        </div>
                                        {/* Display Skip Actions */}
                                        {c.actions && c.actions.length > 0 && (
                                            <div className="mt-2 flex flex-wrap gap-1">
                                                {c.actions.map((act: string) => (
                                                    <span key={act} className="px-1.5 py-0.5 bg-slate-800 rounded text-[10px] text-slate-400 border border-slate-700" title={act}>
                                                        {act.replace('SKIP_PROCESSING_', '').replace(/_/g, ' ')}
                                                    </span>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                )) : <span className="text-sm text-slate-500">None configured</span>}
                            </div>
                        </div>

                        {/* Blocked Clients */}
                        <div>
                            <h4 className="text-sm font-medium text-rose-400 mb-3 flex items-center gap-2">
                                <ShieldOff className="w-4 h-4" /> Blocked Clients (Deny)
                            </h4>
                            <div className="space-y-2">
                                {spec.blocked_clients?.length > 0 ? spec.blocked_clients.map((c: any, i: number) => (
                                    <div key={i} className="p-3 bg-rose-500/5 border border-rose-500/20 rounded flex justify-between items-center">
                                        <span className="text-rose-300 font-mono text-sm">{c.ip_prefix}</span>
                                        {c.metadata?.name && <span className="text-xs text-slate-500">{c.metadata.name}</span>}
                                    </div>
                                )) : <span className="text-sm text-slate-500">None configured</span>}
                            </div>
                        </div>
                    </div>
                 )}
            </section>
        )}

        {/* 6. Routes Configuration (Existing logic, simplified wrapper) */}
        <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
            <button onClick={() => toggleSection('routes')} className="w-full flex items-center justify-between gap-3 px-6 py-4 border-b border-slate-700 hover:bg-slate-700/20">
                <div className="flex items-center gap-3">
                    <Route className="w-5 h-5 text-cyan-400" />
                    <h2 className="text-lg font-semibold text-slate-100">Routes Configuration</h2>
                </div>
                {expandedSections.has('routes') ? <ChevronDown className="w-5 h-5 text-slate-400" /> : <ChevronRight className="w-5 h-5 text-slate-400" />}
            </button>
            
            {expandedSections.has('routes') && (
                <div className="p-6">
                    <div className="space-y-4">
                    {state.routes.map((route, idx) => (
                        <div key={idx} className="bg-slate-700/30 rounded-lg border border-slate-700/50 overflow-hidden">
                           {/* Route Header */}
                           <div className="px-4 py-3 bg-slate-800/50 border-b border-slate-700/50 flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <span className="px-2 py-0.5 bg-slate-700 rounded text-xs font-mono text-slate-300">#{idx + 1}</span>
                                    <div className="flex items-center gap-2">
                                        <span className={`px-2 py-0.5 rounded text-xs font-bold ${getMethodColor(route.method)}`}>{route.method}</span>
                                        <code className="text-slate-200 text-sm">{route.pathType}: {route.pathValue}</code>
                                    </div>
                                </div>
                                {route.waf && (
                                    <span className="flex items-center gap-1 text-xs text-amber-400 px-2 py-0.5 bg-amber-500/10 rounded border border-amber-500/20">
                                        <Shield className="w-3 h-3" /> WAF: {route.waf.name}
                                    </span>
                                )}
                           </div>
                           
                           {/* Route Details */}
                           <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div>
                                    <span className="text-xs text-slate-500 uppercase tracking-wider font-semibold">Origin Pools</span>
                                    <div className="mt-2 space-y-2">
                                        {route.origins.map((p, pIdx) => (
                                            <div key={pIdx} className="flex items-center justify-between p-2 bg-slate-800 rounded border border-slate-700">
                                                <div className="flex items-center gap-2">
                                                    <Server className="w-3.5 h-3.5 text-emerald-400" />
                                                    <span className="text-sm text-slate-200">{p.name}</span>
                                                </div>
                                                <span className="text-xs text-slate-500">Weight: {p.weight}</span>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                                <div className="space-y-2">
                                    {/* Route Options */}
                                    <div className="grid grid-cols-2 gap-2">
                                        <DetailItem label="Timeout" value={`${route.timeout}ms`} small />
                                        <DetailItem label="Host Rewrite" value={route.hostRewrite || 'None'} small />
                                        <DetailItem label="Prefix Rewrite" value={route.prefixRewrite || 'None'} small />
                                        <DetailItem label="Rate Limit" value={route.disableRateLimit ? 'Disabled' : 'Inherited'} small />
                                    </div>
                                </div>
                           </div>
                        </div>
                    ))}
                    </div>
                </div>
            )}
        </section>
      </div>
    );
  };

  const renderCDNContent = () => {
      const cdn = state.rootCDN!;
      const spec = cdn.spec as any; 
      const sysMeta = cdn.system_metadata as any;

      // Helper to safely get nested logging options
      const loggingOpts = spec.other_settings?.logging_options || spec.logging_options;
      const otherSettings = spec.other_settings || {};

      // Calculate counts for stats
      const spCount = spec.active_service_policies?.policies?.length ?? (spec.service_policies_from_namespace ? 'Namespace' : 0);
      const clientListCount = (spec.trusted_clients?.length || 0) + (spec.blocked_clients?.length || 0);
      const ddosRuleCount = spec.ddos_mitigation_rules?.length || 0;

      return (
        <div className="space-y-6">
            {/* 1. Header & Meta */}
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-4">
                  <div className="w-14 h-14 bg-purple-500/15 rounded-xl flex items-center justify-center text-purple-400">
                    <Cloud className="w-7 h-7" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="px-2 py-0.5 text-xs font-semibold rounded bg-purple-600 text-white">CDN Distribution</span>
                      <span className={`px-2 py-0.5 text-xs font-semibold rounded ${!spec.disable ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'}`}>
                        {spec.disable ? 'Disabled' : 'Active'}
                      </span>
                      {spec.state && (
                        <span className="px-2 py-0.5 text-xs font-semibold rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">
                          {spec.state}
                        </span>
                      )}
                    </div>
                    <h1 className="text-2xl font-bold text-slate-100">{cdn.metadata?.name}</h1>
                    <div className="flex flex-wrap items-center gap-4 mt-2 text-sm text-slate-500">
                      <span className="flex items-center gap-1"><Home className="w-4 h-4" /> {cdn.metadata?.namespace}</span>
                      <span className="flex items-center gap-1"><Clock className="w-4 h-4" /> Created: {formatDate(sysMeta?.creation_timestamp)}</span>
                      {sysMeta?.modification_timestamp && (
                        <span className="flex items-center gap-1"><RefreshCw className="w-3.5 h-3.5" /> Modified: {formatDate(sysMeta.modification_timestamp)}</span>
                      )}
                      {sysMeta?.creator_id && (
                        <span className="flex items-center gap-1"><User className="w-3.5 h-3.5" /> Creator: {sysMeta.creator_id}</span>
                      )}
                    </div>
                  </div>
                </div>
                <button
                  onClick={() => setJsonModal({ title: 'Complete CDN Configuration', data: cdn })}
                  className="flex items-center gap-2 px-4 py-2 text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors text-sm"
                >
                  <Code className="w-4 h-4" /> JSON
                </button>
              </div>
            </div>

            {/* 2. Stats Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
                 {[
                     { label: 'Domains', value: spec?.domains?.length || 0, icon: Globe, color: 'text-blue-400' },
                     { label: 'Cache Rules', value: (spec?.cdn_settings?.cache_rules?.length || 0) + (spec?.custom_cache_rule?.cdn_cache_rules?.length || 0), icon: HardDrive, color: 'text-amber-400' },
                     { label: 'Service Policies', value: spCount, icon: FileText, color: 'text-teal-400' },
                     { label: 'WAF', value: spec?.app_firewall ? 'Enabled' : 'Disabled', icon: Shield, color: spec?.app_firewall ? 'text-emerald-400' : 'text-slate-500' },
                     { label: 'User ID', value: spec?.user_identification ? 'Enabled' : 'Disabled', icon: User, color: spec?.user_identification ? 'text-cyan-400' : 'text-slate-500' },
                     { label: 'Bot Defense', value: !spec?.disable_bot_defense ? 'Enabled' : 'Disabled', icon: Bot, color: !spec?.disable_bot_defense ? 'text-purple-400' : 'text-slate-500' },
                     { label: 'Client Lists', value: clientListCount, icon: User, color: clientListCount > 0 ? 'text-indigo-400' : 'text-slate-500' },
                     { label: 'DDoS Rules', value: ddosRuleCount, icon: ShieldAlert, color: ddosRuleCount > 0 ? 'text-rose-400' : 'text-slate-500' },
                 ].map(stat => (
                    <div key={stat.label} className="bg-slate-800/50 border border-slate-700 rounded-xl p-3">
                        <div className={`w-7 h-7 mb-1.5 ${stat.color}`}><stat.icon className="w-full h-full" /></div>
                        <div className={`text-lg font-bold ${typeof stat.value === 'string' && (stat.value === 'Enabled' || stat.value === 'Namespace') ? 'text-emerald-400 text-base' : 'text-slate-100'}`}>{stat.value}</div>
                        <div className="text-xs text-slate-500">{stat.label}</div>
                    </div>
                 ))}
            </div>

            {/* 3. Service Domains */}
            {spec.service_domains && spec.service_domains.length > 0 && (
                <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
                    <div className="flex items-center gap-3 px-6 py-4 border-b border-slate-700">
                        <Network className="w-5 h-5 text-indigo-400" />
                        <h2 className="text-lg font-semibold text-slate-100">Service Domains</h2>
                    </div>
                    <div className="p-6 grid grid-cols-1 gap-3">
                        {spec.service_domains.map((sd: any, idx: number) => (
                            <div key={idx} className="p-4 bg-slate-700/30 rounded border border-slate-700/50 grid grid-cols-1 md:grid-cols-2 gap-4 items-center">
                                <div>
                                    <span className="text-xs text-slate-500 block mb-1">User Domain</span>
                                    <code className="text-slate-200 text-lg">{sd.domain}</code>
                                </div>
                                <div className="md:text-right">
                                    <span className="text-xs text-slate-500 block mb-1">CNAME Target</span>
                                    <code className="text-cyan-400 select-all">{sd.service_domain}</code>
                                </div>
                            </div>
                        ))}
                    </div>
                </section>
            )}

            {/* 4. TLS & Certificate Details */}
            <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
                 <button onClick={() => toggleSection('tls')} className="w-full flex items-center justify-between gap-3 px-6 py-4 border-b border-slate-700 hover:bg-slate-700/20">
                     <div className="flex items-center gap-3">
                         <Lock className="w-5 h-5 text-amber-400" />
                         <h2 className="text-lg font-semibold text-slate-100">TLS & Certificates</h2>
                     </div>
                     {expandedSections.has('tls') ? <ChevronDown className="w-5 h-5 text-slate-400" /> : <ChevronRight className="w-5 h-5 text-slate-400" />}
                 </button>
                 
                 {expandedSections.has('tls') && (
                     <div className="p-6 space-y-6">
                         <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                             <DetailItem 
                                label="HTTPS Auto Cert" 
                                value={spec.https_auto_cert ? 'Enabled' : 'Disabled'} 
                                enabled={!!spec.https_auto_cert} 
                             />
                             <DetailItem 
                                label="HSTS Header" 
                                value={spec.https_auto_cert?.add_hsts ? 'Enabled' : 'Disabled'} 
                                enabled={spec.https_auto_cert?.add_hsts}
                             />
                             <DetailItem 
                                label="HTTP Redirect" 
                                value={spec.https_auto_cert?.http_redirect ? 'Enabled' : 'Disabled'} 
                                enabled={spec.https_auto_cert?.http_redirect}
                             />
                             <DetailItem 
                                label="Cert State" 
                                value={spec.cert_state || spec.auto_cert_info?.auto_cert_state || 'Unknown'} 
                                warning={spec.cert_state !== 'AutoCertReady'}
                             />
                         </div>

                         {/* Certificate Info */}
                         {spec.auto_cert_info && (
                             <div className="p-4 bg-slate-700/30 rounded-lg border border-slate-700/50">
                                 <span className="text-xs text-slate-500 block mb-3">Auto Certificate Details</span>
                                 <div className="grid grid-cols-2 gap-4">
                                     <DetailItem 
                                        label="Expiry Date" 
                                        value={spec.auto_cert_info.auto_cert_expiry ? new Date(spec.auto_cert_info.auto_cert_expiry).toLocaleString() : 'N/A'} 
                                     />
                                     <DetailItem label="Subject" value={spec.auto_cert_info.auto_cert_subject || 'N/A'} small />
                                     <DetailItem label="Issuer" value={spec.auto_cert_info.auto_cert_issuer || 'N/A'} small />
                                 </div>
                                 
                                 {/* DNS Records for ACME */}
                                 {spec.auto_cert_info.dns_records && spec.auto_cert_info.dns_records.length > 0 && (
                                     <div className="mt-4 pt-3 border-t border-slate-700/50">
                                         <span className="text-xs text-amber-400 block mb-2 flex items-center gap-2">
                                            <AlertTriangle className="w-3 h-3" /> DNS Records for Challenge
                                         </span>
                                         <div className="space-y-2">
                                             {spec.auto_cert_info.dns_records.map((rec: any, idx: number) => (
                                                 <div key={idx} className="bg-slate-800/50 p-2 rounded text-xs font-mono flex flex-col md:flex-row gap-2">
                                                     <span className="text-slate-400 font-bold">{rec.type}</span>
                                                     <span className="text-slate-300">{rec.name}</span>
                                                     <span className="text-slate-500">→</span>
                                                     <span className="text-cyan-300 select-all">{rec.value}</span>
                                                 </div>
                                             ))}
                                         </div>
                                     </div>
                                 )}
                             </div>
                         )}
                     </div>
                 )}
            </section>

            {/* 5. Origin Configuration */}
            <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
                 <button onClick={() => toggleSection('origins')} className="w-full flex items-center justify-between gap-3 px-6 py-4 border-b border-slate-700 hover:bg-slate-700/20">
                     <div className="flex items-center gap-3">
                         <Server className="w-5 h-5 text-emerald-400" />
                         <h2 className="text-lg font-semibold text-slate-100">Origin Configuration</h2>
                     </div>
                     {expandedSections.has('origins') ? <ChevronDown className="w-5 h-5 text-slate-400" /> : <ChevronRight className="w-5 h-5 text-slate-400" />}
                 </button>
                 
                 {expandedSections.has('origins') && spec.origin_pool && (
                     <div className="p-6">
                         <div className="p-5 bg-slate-700/30 rounded-xl border border-slate-700/50">
                             {/* Basic Origin Info */}
                             <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4 border-b border-slate-700/50 pb-4">
                                <DetailItem label="Public Name" value={spec.origin_pool.public_name?.dns_name || 'N/A'} />
                                <DetailItem label="Refresh Interval" value={spec.origin_pool.public_name?.refresh_interval ? `${spec.origin_pool.public_name.refresh_interval}s` : 'N/A'} />
                                <DetailItem label="Protocol" value={spec.origin_pool.no_tls ? 'HTTP (No TLS)' : 'HTTPS (TLS)'} warning={!!spec.origin_pool.no_tls} />
                                <DetailItem label="Timeout" value={spec.origin_pool.origin_request_timeout || 'Default'} />
                                <DetailItem 
                                    label="Follow Redirect" 
                                    value={spec.origin_pool.follow_origin_redirect ? 'Enabled' : 'Disabled'} 
                                    enabled={spec.origin_pool.follow_origin_redirect}
                                />
                             </div>

                             {/* Advanced Origin Options */}
                             {spec.origin_pool.more_origin_options && (
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4 border-b border-slate-700/50 pb-4">
                                   <DetailItem 
                                     label="Byte Range Requests" 
                                     value={spec.origin_pool.more_origin_options.enable_byte_range_request ? 'Enabled' : 'Disabled'} 
                                     enabled={spec.origin_pool.more_origin_options.enable_byte_range_request}
                                   />
                                   <DetailItem 
                                     label="Websocket Proxy" 
                                     value={spec.origin_pool.more_origin_options.websocket_proxy ? 'Enabled' : 'Disabled'} 
                                     enabled={spec.origin_pool.more_origin_options.websocket_proxy}
                                   />
                                </div>
                             )}

                             <span className="text-xs text-slate-500 block mb-3">Origin Servers</span>
                             <div className="space-y-2">
                                {spec.origin_pool.origin_servers?.map((os: any, idx: number) => (
                                    <div key={idx} className="flex items-center gap-3 p-3 bg-slate-800/50 rounded-lg">
                                        <Server className="w-4 h-4 text-emerald-400" />
                                        <code className="text-slate-200">{os.public_name?.dns_name || os.ip?.ip || 'Unknown'}</code>
                                        <span className="text-xs text-slate-500">Port: {os.port}</span>
                                    </div>
                                ))}
                             </div>
                         </div>
                     </div>
                 )}
            </section>

            {/* 6. Caching Policies */}
            <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
                 <button onClick={() => toggleSection('caching')} className="w-full flex items-center justify-between gap-3 px-6 py-4 border-b border-slate-700 hover:bg-slate-700/20">
                     <div className="flex items-center gap-3">
                         <HardDrive className="w-5 h-5 text-amber-400" />
                         <h2 className="text-lg font-semibold text-slate-100">Caching Policies</h2>
                     </div>
                     {expandedSections.has('caching') ? <ChevronDown className="w-5 h-5 text-slate-400" /> : <ChevronRight className="w-5 h-5 text-slate-400" />}
                 </button>

                 {expandedSections.has('caching') && (
                     <div className="p-6 space-y-6">
                         {/* Default Policy */}
                         <div className="p-4 bg-slate-700/30 rounded-lg border border-slate-700/50">
                             <div className="flex items-center gap-2 mb-3">
                                 <Settings className="w-4 h-4 text-amber-400" />
                                 <span className="text-slate-200 font-medium">Default Caching Behavior</span>
                             </div>
                             <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                                 <DetailItem label="TTL Override" value={spec.default_cache_action?.cache_ttl_override || 'N/A'} />
                                 <DetailItem label="Max Cache Size" value={spec.cdn_settings?.max_cache_size ? `${spec.cdn_settings.max_cache_size} MB` : 'Default'} />
                             </div>
                         </div>

                         {/* Custom Rules */}
                         {(spec.custom_cache_rule?.cdn_cache_rules || spec.cdn_settings?.cache_rules) && (
                             <div>
                                 <span className="text-xs text-slate-500 block mb-3">Custom Cache Rules</span>
                                 <div className="space-y-4">
                                    {[...(spec.custom_cache_rule?.cdn_cache_rules || []), ...(spec.cdn_settings?.cache_rules || [])].map((ref: any, idx: number) => {
                                        const ruleDetail = state.cacheRules.get(ref.name);
                                        const ruleSpec = ruleDetail?.spec?.cache_rules; 
                                        
                                        // 1. Determine Action
                                        const isBypass = ruleSpec?.cache_bypass;
                                        const eligible = ruleSpec?.eligible_for_cache;
                                        
                                        // 2. Determine Cache Key Type & Config
                                        let cacheKeyLabel = 'Default';
                                        let cacheConfig = null;

                                        if (eligible?.scheme_proxy_host_uri) {
                                            cacheKeyLabel = 'Scheme + Host + URI (Ignores Query)';
                                            cacheConfig = eligible.scheme_proxy_host_uri;
                                        } else if (eligible?.scheme_proxy_host_request_uri) {
                                            cacheKeyLabel = 'Scheme + Host + Request URI (Includes Query)';
                                            cacheConfig = eligible.scheme_proxy_host_request_uri;
                                        }

                                        return (
                                            <div key={idx} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                                                <div className="flex items-center justify-between mb-3">
                                                    <div className="flex items-center gap-2">
                                                        <span className="px-2 py-0.5 bg-slate-700 rounded text-xs text-slate-400">Rule {idx + 1}</span>
                                                        <span className="text-slate-200 font-medium">{ref.name}</span>
                                                    </div>
                                                    {ruleDetail && (
                                                        <button onClick={() => setJsonModal({title: `Cache Rule: ${ref.name}`, data: ruleDetail})} className="p-1 text-slate-500 hover:text-slate-300">
                                                            <Code className="w-4 h-4" />
                                                        </button>
                                                    )}
                                                </div>
                                                
                                                {ruleDetail ? (
                                                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                                                        <DetailItem 
                                                            label="Action" 
                                                            value={isBypass ? 'Bypass Cache' : 'Cache'} 
                                                            warning={!!isBypass}
                                                            enabled={!isBypass}
                                                        />
                                                        
                                                        {!isBypass && (
                                                            <div className="col-span-2 md:col-span-1">
                                                                <span className="text-xs text-slate-500 block mb-0.5">Cache Key</span>
                                                                <span className="text-sm text-cyan-400" title={cacheKeyLabel}>{cacheKeyLabel}</span>
                                                            </div>
                                                        )}

                                                        {!isBypass && cacheConfig && (
                                                            <>
                                                                <DetailItem 
                                                                    label="Cache TTL" 
                                                                    value={cacheConfig.cache_ttl || 'Default'} 
                                                                />
                                                                <DetailItem 
                                                                    label="Ignore Cookies" 
                                                                    value={cacheConfig.ignore_response_cookie ? 'Yes' : 'No'} 
                                                                    enabled={cacheConfig.ignore_response_cookie}
                                                                />
                                                                <DetailItem 
                                                                    label="Override Control" 
                                                                    value={cacheConfig.cache_override ? 'Active' : 'Passive'} 
                                                                    warning={cacheConfig.cache_override}
                                                                />
                                                            </>
                                                        )}
                                                        {ruleSpec?.browser_ttl && (
                                                            <DetailItem label="Browser TTL" value={`${ruleSpec.browser_ttl}s`} />
                                                        )}
                                                    </div>
                                                ) : <span className="text-sm text-slate-500 italic">Details not fetched</span>}
                                            </div>
                                        );
                                    })}
                                 </div>
                             </div>
                         )}
                     </div>
                 )}
            </section>

            {/* 7. Header Modifications */}
            {(spec.request_headers_to_add || spec.response_headers_to_add) && (
                <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
                    <div className="flex items-center gap-3 px-6 py-4 border-b border-slate-700">
                        <Settings className="w-5 h-5 text-blue-400" />
                        <h2 className="text-lg font-semibold text-slate-100">Header Modifications</h2>
                    </div>
                    <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
                        {spec.request_headers_to_add && spec.request_headers_to_add.length > 0 && (
                            <div>
                                <span className="text-xs text-slate-500 block mb-2">Request Headers (Add)</span>
                                <div className="space-y-2">
                                    {spec.request_headers_to_add.map((h: any, i: number) => (
                                        <div key={i} className="flex items-center gap-2 px-3 py-2 bg-slate-700/30 rounded text-sm">
                                            <span className="text-blue-300 font-mono">{h.name}</span>
                                            <span className="text-slate-500">:</span>
                                            <span className="text-slate-300">{h.value}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                        {spec.response_headers_to_add && spec.response_headers_to_add.length > 0 && (
                            <div>
                                <span className="text-xs text-slate-500 block mb-2">Response Headers (Add)</span>
                                <div className="space-y-2">
                                    {spec.response_headers_to_add.map((h: any, i: number) => (
                                        <div key={i} className="flex items-center gap-2 px-3 py-2 bg-slate-700/30 rounded text-sm">
                                            <span className="text-emerald-300 font-mono">{h.name}</span>
                                            <span className="text-slate-500">:</span>
                                            <span className="text-slate-300">{h.value}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </section>
            )}

            {/* 8. Security Configuration */}
            <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
                <button onClick={() => toggleSection('security')} className="w-full flex items-center justify-between gap-3 px-6 py-4 border-b border-slate-700 hover:bg-slate-700/20">
                    <div className="flex items-center gap-3">
                        <Shield className="w-5 h-5 text-red-400" />
                        <h2 className="text-lg font-semibold text-slate-100">Security Configuration</h2>
                    </div>
                    {expandedSections.has('security') ? <ChevronDown className="w-5 h-5 text-slate-400" /> : <ChevronRight className="w-5 h-5 text-slate-400" />}
                </button>
                
                {expandedSections.has('security') && (
                    <div className="p-6 space-y-6">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            {/* WAF Card */}
                            <div className={`p-4 rounded-lg border ${spec.app_firewall ? 'bg-emerald-500/5 border-emerald-500/20' : 'bg-slate-700/30 border-slate-700/50'}`}>
                                <div className="flex items-center justify-between mb-2">
                                    <div className="flex items-center gap-2">
                                        <Shield className={`w-5 h-5 ${spec.app_firewall ? 'text-emerald-400' : 'text-slate-500'}`} />
                                        <span className="font-medium text-slate-200">Web App Firewall</span>
                                    </div>
                                    {spec.app_firewall && <span className="px-2 py-0.5 bg-emerald-500/20 text-emerald-400 rounded text-xs">Active</span>}
                                </div>
                                {spec.app_firewall ? (
                                    <div className="text-sm">
                                        <div className="text-slate-400">Policy: <span className="text-slate-200">{spec.app_firewall.name}</span></div>
                                        {state.wafPolicies.get(spec.app_firewall.name) && (
                                            <div className="text-slate-400 mt-1">
                                                Mode: <span className="text-slate-200">{getWafMode(state.wafPolicies.get(spec.app_firewall.name))}</span>
                                            </div>
                                        )}
                                        <button onClick={() => setJsonModal({title:'WAF Policy', data: state.wafPolicies.get(spec.app_firewall.name)})} className="text-xs text-blue-400 hover:underline mt-2 flex items-center gap-1">View Config <Code className="w-3 h-3"/></button>
                                    </div>
                                ) : <span className="text-sm text-slate-500">Not configured</span>}
                            </div>

                            {/* User ID Card */}
                            <div className={`p-4 rounded-lg border ${spec.user_identification ? 'bg-cyan-500/5 border-cyan-500/20' : 'bg-slate-700/30 border-slate-700/50'}`}>
                                <div className="flex items-center justify-between mb-2">
                                    <div className="flex items-center gap-2">
                                        <User className={`w-5 h-5 ${spec.user_identification ? 'text-cyan-400' : 'text-slate-500'}`} />
                                        <span className="font-medium text-slate-200">User Identification</span>
                                    </div>
                                    {spec.user_identification && <span className="px-2 py-0.5 bg-cyan-500/20 text-cyan-400 rounded text-xs">Active</span>}
                                </div>
                                {spec.user_identification ? (
                                    <div className="text-sm">
                                        <div className="text-slate-400">Policy: <span className="text-slate-200">{spec.user_identification.name}</span></div>
                                        <button onClick={() => setJsonModal({title:'User ID Policy', data: state.userIdentificationPolicy})} className="text-xs text-blue-400 hover:underline mt-2 flex items-center gap-1">View Config <Code className="w-3 h-3"/></button>
                                    </div>
                                ) : <span className="text-sm text-slate-500">Not configured</span>}
                            </div>
                        </div>

                        {/* Other Security Flags */}
                        <div className="pt-4 border-t border-slate-700/50 grid grid-cols-2 md:grid-cols-3 gap-3">
                             <DetailItem label="Bot Defense" value={!spec.disable_bot_defense ? 'Enabled' : 'Disabled'} small />
                             <DetailItem label="Rate Limiting" value={!spec.disable_rate_limit ? 'Enabled' : 'Disabled'} small />
                             <DetailItem label="Malicious User Detection" value={!spec.disable_malicious_user_detection ? 'Enabled' : 'Disabled'} small />
                        </div>
                    </div>
                )}
            </section>

            {/* 9. Access Control & DDoS */}
            {(clientListCount > 0 || ddosRuleCount > 0) && (
                <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
                    <div className="flex items-center gap-3 px-6 py-4 border-b border-slate-700">
                        <ShieldAlert className="w-5 h-5 text-rose-400" />
                        <h2 className="text-lg font-semibold text-slate-100">Access Control & DDoS</h2>
                    </div>
                    <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
                        {/* Client Lists */}
                        {clientListCount > 0 && (
                            <div>
                                <h4 className="text-sm font-medium text-slate-300 mb-3 flex items-center gap-2">
                                    <User className="w-4 h-4 text-indigo-400" /> Client Lists
                                </h4>
                                <div className="space-y-2">
                                    {spec.blocked_clients?.map((c: any, i: number) => (
                                        <div key={`blk-${i}`} className="px-3 py-2 bg-red-500/10 border border-red-500/20 rounded flex justify-between items-center text-sm">
                                            <span className="text-red-300">{c.ip_prefix || `ASN ${c.as_number}`}</span>
                                            <span className="text-xs bg-red-500/20 text-red-300 px-2 py-0.5 rounded">Blocked</span>
                                        </div>
                                    ))}
                                    {spec.trusted_clients?.map((c: any, i: number) => (
                                        <div key={`trst-${i}`} className="px-3 py-2 bg-emerald-500/10 border border-emerald-500/20 rounded flex justify-between items-center text-sm">
                                            <span className="text-emerald-300">{c.ip_prefix || `ASN ${c.as_number}`}</span>
                                            <span className="text-xs bg-emerald-500/20 text-emerald-300 px-2 py-0.5 rounded">Trusted</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                        
                        {/* DDoS Rules */}
                        {ddosRuleCount > 0 && (
                            <div>
                                <h4 className="text-sm font-medium text-slate-300 mb-3 flex items-center gap-2">
                                    <ShieldAlert className="w-4 h-4 text-rose-400" /> DDoS Rules
                                </h4>
                                <div className="space-y-2">
                                    {spec.ddos_mitigation_rules.map((rule: any, i: number) => (
                                        <div key={i} className="p-3 bg-slate-700/30 rounded border border-slate-700/50 text-sm">
                                            <div className="flex justify-between mb-1">
                                                <span className="text-slate-300 font-medium">{rule.metadata?.name}</span>
                                                <span className="text-xs text-slate-500">Rule {i+1}</span>
                                            </div>
                                            <div className="text-xs text-slate-400">
                                                Action: <span className="text-amber-400">{Object.keys(rule.mitigation_action || {}).join(', ') || 'None'}</span>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </section>
            )}

            {/* 10. Observability & Logging (Fixed Check) */}
            {(loggingOpts || spec.more_option?.custom_errors || otherSettings.add_location) && (
                <section className="bg-slate-800/50 border border-slate-700 rounded-xl">
                    <div className="flex items-center gap-3 px-6 py-4 border-b border-slate-700">
                        <Activity className="w-5 h-5 text-blue-400" />
                        <h2 className="text-lg font-semibold text-slate-100">Observability & Logging</h2>
                    </div>
                    <div className="p-6 space-y-4">
                        {/* Header List */}
                        {loggingOpts?.client_log_options?.header_list && (
                            <div>
                                <span className="text-xs text-slate-500 block mb-2">Log Headers (Captured in Logs)</span>
                                <div className="flex flex-wrap gap-2">
                                    {loggingOpts.client_log_options.header_list.map((h: string, i: number) => (
                                        <span key={i} className="px-3 py-1 bg-blue-500/10 text-blue-300 border border-blue-500/20 rounded text-sm font-mono">
                                            {h}
                                        </span>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* Add Location */}
                        {otherSettings.add_location !== undefined && (
                            <div className="pt-2">
                                <DetailItem 
                                    label="Add Location Data" 
                                    value={otherSettings.add_location ? 'Enabled' : 'Disabled'}
                                    enabled={otherSettings.add_location}
                                />
                            </div>
                        )}
                        
                        {/* Error Pages */}
                        {spec.more_option?.custom_errors && (
                            <div className="pt-4 border-t border-slate-700/50">
                                <span className="text-xs text-slate-500 block mb-2">Custom Error Pages</span>
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                                    {Object.keys(spec.more_option.custom_errors).map((code) => (
                                        <div key={code} className="px-3 py-2 bg-slate-700/30 rounded text-sm flex justify-between">
                                            <span className="text-amber-400 font-mono">{code}</span>
                                            <span className="text-slate-400">Custom</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </section>
            )}
        </div>
      );
  };
  
  return (
    <div className="min-h-screen bg-slate-900">
      <div className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link
              to="/"
              className="p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
            >
              <ArrowLeft className="w-5 h-5" />
            </Link>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-blue-500/15 rounded-xl flex items-center justify-center text-blue-400">
                <Grid3X3 className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-lg font-bold text-slate-100">Config Visualizer</h1>
                <p className="text-xs text-slate-500">
                  Comprehensive Load Balancer Configuration View
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            
            {/* 2. NEW: Type Selector */}
            <select
              value={selectedType}
              onChange={e => {
                const newType = e.target.value as 'http' | 'cdn';
                setSelectedType(newType);
                loadResources(selectedNs, newType);
              }}
              className="px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-blue-500 min-w-[120px]"
            >
              <option value="http">HTTP LB</option>
              <option value="cdn">CDN</option>
            </select>

            {/* 1. Namespace Selector */}
            <select
              value={selectedNs}
              onChange={e => loadResources(e.target.value, selectedType)} // Updated handler
              disabled={isLoadingNs}
              className="px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-blue-500 min-w-[180px]"
            >
              <option value="">Select Namespace</option>
              {namespaces.map(ns => (
                <option key={ns.name} value={ns.name}>
                  {ns.name}
                </option>
              ))}
            </select>

            {/* 3. Resource Selector (Updated) */}
            <select
              value={selectedResource} // Updated variable
              onChange={e => setSelectedResource(e.target.value)} // Updated setter
              disabled={!selectedNs || isLoadingResources}
              className="px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-blue-500 min-w-[200px] disabled:opacity-50"
            >
              <option value="">
                {isLoadingResources ? 'Loading...' : `Select ${selectedType === 'http' ? 'Load Balancer' : 'Distribution'}`}
              </option>
              {resourceList.map(r => (
                <option key={r.name} value={r.name}>
                  {r.name}
                </option>
              ))}
            </select>

            <button
              onClick={startViewer}
              disabled={!selectedNs || !selectedResource || isLoading} // Updated check
              className={`flex items-center gap-2 px-5 py-2 font-semibold rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed text-white ${selectedType === 'http' ? 'bg-blue-500 hover:bg-blue-600' : 'bg-purple-500 hover:bg-purple-600'}`}
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

        {!isLoading && !lb && !state.rootCDN && (
          <div className="flex flex-col items-center justify-center py-24 text-center">
            <Grid3X3 className="w-16 h-16 text-slate-600 mb-4" />
            <h2 className="text-xl font-semibold text-slate-300 mb-2">
              Select a Load Balancer to visualize
            </h2>
            <p className="text-slate-500 max-w-md">
              Choose a namespace and load balancer from the dropdowns above to view its
              complete configuration details.
            </p>
          </div>
        )}

        {!isLoading && state.rootLB && renderHTTPLBContent()}

        {!isLoading && state.rootCDN && renderCDNContent()}
        
      </main>

      {jsonModal && (
        <div
          className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4"
          onClick={() => setJsonModal(null)}
        >
          <div
            className="bg-slate-800 border border-slate-700 rounded-xl max-w-4xl w-full max-h-[85vh] overflow-hidden"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700">
              <h3 className="font-semibold text-slate-200">{jsonModal.title}</h3>
              <div className="flex items-center gap-2">
                <button
                  onClick={copyJson}
                  className="flex items-center gap-1 px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors"
                >
                  <Copy className="w-4 h-4" /> Copy
                </button>
                <button
                  onClick={() => setJsonModal(null)}
                  className="p-1 text-slate-500 hover:text-slate-300 transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>
            <div className="p-6 overflow-auto max-h-[70vh]">
              <pre className="text-sm text-slate-300 font-mono whitespace-pre-wrap">
                {JSON.stringify(jsonModal.data, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function DetailItem({
  label,
  value,
  enabled,
  warning,
  small
}: {
  label: string;
  value: string;
  enabled?: boolean;
  warning?: boolean;
  small?: boolean;
}) {
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

function SecurityFeatureCard({
  icon: Icon,
  name,
  enabled,
  value,
  details,
}: {
  icon: typeof Shield;
  name: string;
  enabled: boolean;
  value: string;
  details?: string;
}) {
  return (
    <div className={`p-4 rounded-xl border ${enabled ? 'bg-emerald-500/5 border-emerald-500/20' : 'bg-slate-700/30 border-slate-700'}`}>
      <div className="flex items-start gap-3 mb-2">
        <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${enabled ? 'bg-emerald-500/15 text-emerald-400' : 'bg-slate-700 text-slate-500'}`}>
          <Icon className="w-4 h-4" />
        </div>
        <div className="flex-1 min-w-0">
          <h3 className="text-sm font-medium text-slate-300">{name}</h3>
          <div className="flex items-center gap-2 mt-1">
            <span className={`w-2 h-2 rounded-full ${enabled ? 'bg-emerald-400' : 'bg-slate-600'}`} />
            <span className={`text-sm truncate ${enabled ? 'text-slate-200' : 'text-slate-500'}`}>{value}</span>
          </div>
          {details && (
            <span className="text-xs text-slate-500 mt-1 block">{details}</span>
          )}
        </div>
      </div>
    </div>
  );
}

function FeatureStatusItem({ label, enabled, disabled, fromAppType }: { label: string; enabled: boolean; disabled: boolean; fromAppType?: boolean }) {
  const status = disabled ? 'disabled' : (enabled ? 'enabled' : 'not-configured');
  return (
    <div className={`p-3 rounded-lg border ${
      status === 'enabled' ? 'bg-emerald-500/5 border-emerald-500/20' :
      status === 'disabled' ? 'bg-red-500/5 border-red-500/20' :
      'bg-slate-700/30 border-slate-700'
    }`}>
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-1.5 min-w-0">
          <span className="text-sm text-slate-300 truncate">{label}</span>
          {fromAppType && (
            <span className="flex-shrink-0 w-1.5 h-1.5 bg-violet-400 rounded-full" title="From App Type" />
          )}
        </div>
        <span className={`flex-shrink-0 px-2 py-0.5 rounded text-xs font-medium ${
          status === 'enabled' ? 'bg-emerald-500/15 text-emerald-400' :
          status === 'disabled' ? 'bg-red-500/15 text-red-400' :
          'bg-slate-700 text-slate-500'
        }`}>
          {status === 'enabled' ? 'Enabled' : status === 'disabled' ? 'Disabled' : 'Off'}
        </span>
      </div>
    </div>
  );
}

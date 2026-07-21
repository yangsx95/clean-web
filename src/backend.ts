import { invoke } from "@tauri-apps/api/core";

export type Settings = {
  protectionEnabled: boolean;
  proxyEnabled: boolean;
  automaticNodeSelection: boolean;
  accessLoggingEnabled: boolean;
  safeSearchEnabled: boolean;
  strictModeEnabled: boolean;
  logRetention: string;
  categories: Record<string, boolean>;
};
export type Subscription = { id:string; kind:"rule"|"proxy"; name:string; url:string; format?:string; category?:string; updateIntervalHours?:number; enabled:boolean; lastUpdatedAt?:string; lastError?:string };
export type NewSubscription = Omit<Subscription, "id"|"enabled"|"lastUpdatedAt"|"lastError">;
export type ManualProxyImport = { name:string; content:string };
export type RefreshReport = { detectedFormat:string; importedCount:number; ignoredCount:number; proxyCount:number; groupCount:number };
export type CoreStatus = { running:boolean; pid?:number; controller:string; configPath:string };
export type AccessLog={id:string;observedAt:string;domain?:string;targetIp?:string;targetPort?:number;decision:"allow"|"block"|"warning";rule?:string;category?:string;processName?:string;operatingSystem:string;systemUser:string;sourceIp?:string;route?:string;proxyGroup?:string;error?:string};
export type AccessLogStats={block:number;allow:number;warning:number;total:number};
export type ParentRule={id:string;action:"allow"|"block"|"proxy";kind:string;pattern:string;category:string;enabled:boolean};
export type NewParentRule=Pick<ParentRule,"action"|"kind"|"pattern"|"category">;
const previewSettingsKey = "cleanweb.preview.settings";
const previewCoreStatusKey = "cleanweb.preview.coreStatus";
const previewParentRulesKey = "cleanweb.preview.parentRules";
const previewSubscriptionsKey = "cleanweb.preview.subscriptions";
const sessionTokenKey = "cleanweb.sessionToken";
let previewParentRules:ParentRule[] = loadPreviewParentRules();
let previewSubscriptions: Subscription[] = loadPreviewSubscriptions();

const defaultSettings: Settings = {
  protectionEnabled: false,
  proxyEnabled: false,
  automaticNodeSelection: true,
  accessLoggingEnabled: true,
  safeSearchEnabled: true,
  strictModeEnabled: false,
  logRetention: "30d",
  categories: { pornography: true, gambling: true, drugs: true, violence: true, self_harm: true, hate_extremism: true, fraud: true, phishing: true, malware: true, ads: true, tracking: true },
};
const defaultCoreStatus: CoreStatus = { running: false, controller: "127.0.0.1:19090", configPath: "preview" };

let defaults: Settings = loadPreviewSettings();
let previewCoreStatus: CoreStatus = loadPreviewCoreStatus();

const isTauri = () => "__TAURI_INTERNALS__" in window;
function loadPreviewSettings(): Settings {
  try {
    const raw = window.localStorage.getItem(previewSettingsKey);
    return raw ? { ...structuredClone(defaultSettings), ...JSON.parse(raw) } : structuredClone(defaultSettings);
  } catch {
    return structuredClone(defaultSettings);
  }
}
function savePreviewSettings() {
  try { window.localStorage.setItem(previewSettingsKey, JSON.stringify(defaults)); } catch {}
}
function loadPreviewCoreStatus(): CoreStatus {
  try {
    const raw = window.localStorage.getItem(previewCoreStatusKey);
    return raw ? { ...defaultCoreStatus, ...JSON.parse(raw) } : structuredClone(defaultCoreStatus);
  } catch {
    return structuredClone(defaultCoreStatus);
  }
}
function savePreviewCoreStatus() {
  try { window.localStorage.setItem(previewCoreStatusKey, JSON.stringify(previewCoreStatus)); } catch {}
}
function loadPreviewParentRules(): ParentRule[] {
  try {
    const raw = window.localStorage.getItem(previewParentRulesKey);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}
function savePreviewParentRules() {
  try { window.localStorage.setItem(previewParentRulesKey, JSON.stringify(previewParentRules)); } catch {}
}
function loadPreviewSubscriptions(): Subscription[] {
  try {
    const raw = window.localStorage.getItem(previewSubscriptionsKey);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}
function savePreviewSubscriptions() {
  try { window.localStorage.setItem(previewSubscriptionsKey, JSON.stringify(previewSubscriptions)); } catch {}
}
export function getStoredSessionToken(): string | null {
  try { return window.localStorage.getItem(sessionTokenKey) ?? window.sessionStorage.getItem(sessionTokenKey); } catch { return null; }
}
export function storeSessionToken(sessionToken: string) {
  try { window.sessionStorage.setItem(sessionTokenKey, sessionToken); } catch {}
  try { window.localStorage.setItem(sessionTokenKey, sessionToken); } catch {}
}
export function clearStoredSessionToken() {
  try { window.sessionStorage.removeItem(sessionTokenKey); } catch {}
  try { window.localStorage.removeItem(sessionTokenKey); } catch {}
}

export async function getBootstrapState() {
  return isTauri() ? invoke<{ passwordConfigured: boolean }>("get_bootstrap_state") : { passwordConfigured: true };
}

export async function initializePassword(password: string) {
  if (isTauri()) await invoke("initialize_password", { password });
}

export async function unlock(password: string) {
  const result = isTauri()
    ? await invoke<{ sessionToken: string; expiresInSeconds: number }>("unlock", { password })
    : password.length < 8
      ? (() => { throw new Error("管理密码错误"); })()
      : { sessionToken: "browser-preview", expiresInSeconds: 900 };
  storeSessionToken(result.sessionToken);
  return result;
}

export async function lock(sessionToken: string) {
  if (isTauri()) await invoke("lock", { sessionToken });
  clearStoredSessionToken();
}

export async function validateSession(sessionToken: string) {
  if (isTauri()) return invoke<{ sessionToken: string; expiresInSeconds: number }>("validate_session", { sessionToken });
  if (sessionToken !== "browser-preview") throw new Error("管理会话已过期，请重新解锁");
  return { sessionToken, expiresInSeconds: 900 };
}

export async function getSettings(): Promise<Settings> {
  if (isTauri()) return invoke<Settings>("get_settings");
  defaults = loadPreviewSettings();
  return structuredClone(defaults);
}

export async function updateSetting(sessionToken: string, key: string, value: string): Promise<Settings> {
  if (isTauri()) return invoke<Settings>("update_setting", { sessionToken, key, value });
  if (key === "protection_enabled") defaults.protectionEnabled = value === "true";
  if (key === "proxy_enabled") defaults.proxyEnabled = value === "true";
  if (key === "automatic_node_selection") defaults.automaticNodeSelection = value === "true";
  if (key === "access_logging_enabled") defaults.accessLoggingEnabled = value === "true";
  if (key === "safe_search_enabled") defaults.safeSearchEnabled = value === "true";
  if (key === "strict_mode_enabled") defaults.strictModeEnabled = value === "true";
  if (key === "log_retention") defaults.logRetention = value;
  if (key.startsWith("category.")) defaults.categories[key.slice(9)] = value === "true";
  savePreviewSettings();
  return structuredClone(defaults);
}

export async function listSubscriptions(sessionToken:string,kind?: "rule"|"proxy"): Promise<Subscription[]> {
  if (!isTauri()) previewSubscriptions = loadPreviewSubscriptions();
  return isTauri() ? invoke("list_subscriptions", { sessionToken,kind }) : previewSubscriptions.filter((item) => !kind || item.kind === kind);
}
export async function createSubscription(sessionToken: string, input: NewSubscription): Promise<Subscription> {
  if (isTauri()) return invoke("create_subscription", { sessionToken, input });
  const item: Subscription = { ...input, id: crypto.randomUUID(), enabled: true }; previewSubscriptions.unshift(item); savePreviewSubscriptions(); return item;
}
export async function importProxyPayload(sessionToken: string, input: ManualProxyImport): Promise<Subscription> {
  if (isTauri()) return invoke("import_proxy_payload", { sessionToken, input });
  const item: Subscription = { id: crypto.randomUUID(), kind: "proxy", name: input.name, url: "manual://preview", format: "clash", enabled: true, lastUpdatedAt: new Date().toISOString() };
  previewSubscriptions.unshift(item);
  savePreviewSubscriptions();
  return item;
}
export async function setSubscriptionEnabled(sessionToken:string,id:string,enabled:boolean) {
  if (isTauri()) return invoke("set_subscription_enabled", { sessionToken,id,enabled });
  const item=previewSubscriptions.find((value)=>value.id===id); if(item){item.enabled=enabled;savePreviewSubscriptions();}
}
export async function deleteSubscription(sessionToken:string,id:string) {
  if (isTauri()) return invoke("delete_subscription", { sessionToken,id });
  const index=previewSubscriptions.findIndex((value)=>value.id===id); if(index>=0){previewSubscriptions.splice(index,1);savePreviewSubscriptions();}
}
export type RecommendedSource={name:string;url:string;format:string;category:string;description:string};
const previewRecommendedSources:RecommendedSource[]=[
  // hosts
  {name:"综合广告与恶意软件",url:"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",format:"hosts",category:"ads",description:"Steven Black 维护的合并去重 hosts 列表，覆盖广告、恶意软件与跟踪域名"},
  {name:"AdAway 广告拦截",url:"https://adaway.org/hosts.txt",format:"hosts",category:"ads",description:"AdAway 官方 hosts 列表，专注移动广告拦截"},
  {name:"Dan Pollock hosts",url:"https://someonewhocares.org/hosts/zero/hosts",format:"hosts",category:"ads",description:"Dan Pollock 维护的经典 hosts 列表，拦截广告与跟踪域名"},
  {name:"赌博网站拦截",url:"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts",format:"hosts",category:"gambling",description:"Steven Black 赌博分类 hosts 列表"},
  {name:"色情内容拦截",url:"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts",format:"hosts",category:"pornography",description:"Steven Black 色情分类 hosts 列表"},
  {name:"恶意软件域名",url:"https://urlhaus.abuse.ch/downloads/hostfile/",format:"hosts",category:"malware",description:"URLhaus 实时恶意软件分发域名列表"},
  // adblock
  {name:"EasyList 广告过滤",url:"https://easylist.to/easylist/easylist.txt",format:"adblock",category:"ads",description:"Adblock 生态中最广泛使用的英文广告过滤列表"},
  {name:"EasyList China",url:"https://easylist-downloads.adblockplus.org/easylistchina.txt",format:"adblock",category:"ads",description:"EasyList 中文补充规则，覆盖国内网站广告"},
  {name:"AdGuard 中文过滤",url:"https://filters.adtidy.org/extension/chromium/filters/224.txt",format:"adblock",category:"ads",description:"AdGuard 维护的中文广告过滤规则"},
  {name:"uBlock 隐私保护",url:"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt",format:"adblock",category:"ads",description:"uBlock Origin 隐私保护规则，拦截跟踪器和指纹收集"},
  // domain-list
  {name:"Loyalsoldier 直连域名",url:"https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt",format:"domain-list",category:"custom",description:"国内常用域名直连列表，避免不必要的代理"},
  {name:"GFW 域名列表",url:"https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt",format:"domain-list",category:"custom",description:"常见被封锁域名列表，用于精确代理"},
  {name:"广告域名列表",url:"https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/reject-list.txt",format:"domain-list",category:"ads",description:"广告与跟踪域名列表，纯域名格式"},
  // ip-list
  {name:"中国 IP 地址段",url:"https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/cncidr.txt",format:"clash",category:"direct",description:"中国大陆 IP 地址段，用于直连或分流策略"},
  {name:"恶意 IP 地址段",url:"https://www.spamhaus.org/drop/drop.txt",format:"ip-list",category:"malware",description:"Spamhaus DROP 列表，已知恶意网络地址段"},
  {name:"私有 IP 地址段",url:"https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/private.txt",format:"ip-list",category:"custom",description:"私有与保留 IP 地址段，确保内网流量直连"},
  // clash
  {name:"Loyalsoldier Clash 规则",url:"https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt",format:"clash",category:"ads",description:"Loyalsoldier 维护的 Clash 广告拦截规则集"},
  {name:"Clash 域名直连规则",url:"https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt",format:"clash",category:"custom",description:"Clash 格式的国内直连域名规则"},
];
export async function getRecommendedSources():Promise<RecommendedSource[]>{return isTauri()?invoke<RecommendedSource[]>("get_recommended_sources"):previewRecommendedSources;}
export async function refreshSubscription(sessionToken:string,id:string):Promise<RefreshReport>{
  if(isTauri())return invoke("refresh_subscription",{sessionToken,id});
  return {detectedFormat:"preview",importedCount:0,ignoredCount:0,proxyCount:0,groupCount:0};
}
export async function refreshDueSubscriptions():Promise<number>{return isTauri()?invoke("refresh_due_subscriptions"):0;}
export async function getCoreStatus():Promise<CoreStatus>{if(isTauri())return invoke("get_core_status");previewCoreStatus=loadPreviewCoreStatus();return structuredClone(previewCoreStatus);}
export async function startProtection(sessionToken:string):Promise<CoreStatus>{if(isTauri())return invoke("start_protection",{sessionToken});previewCoreStatus={running:true,pid:1234,controller:"127.0.0.1:19090",configPath:"preview"};savePreviewCoreStatus();return structuredClone(previewCoreStatus);}
export async function autoStartProtection():Promise<CoreStatus>{return isTauri()?invoke("auto_start_protection"):getCoreStatus();}
export async function stopProtection(sessionToken:string):Promise<CoreStatus>{if(isTauri())return invoke("stop_protection",{sessionToken});previewCoreStatus={running:false,controller:"127.0.0.1:19090",configPath:"preview"};savePreviewCoreStatus();return structuredClone(previewCoreStatus);}
export async function reloadProtection(sessionToken:string):Promise<CoreStatus>{return isTauri()?invoke("reload_protection",{sessionToken}):getCoreStatus();}
export async function testProxyGroup(sessionToken:string,group="CleanWeb"):Promise<number>{const value=await invoke<{delay:number}>("test_proxy_group",{sessionToken,group});return value.delay;}
export type ProxyNode={name:string;nodeType:string;delay?:number|null};
export type ProxyGroup={name:string;groupType:string;now:string;nodes:ProxyNode[]};
export type SubscriptionProxyNode={name:string;nodeType:string};
export type SubscriptionProxyGroup={name:string;groupType:string;members:string[]};
export type SubscriptionProxyInfo={proxies:SubscriptionProxyNode[];groups:SubscriptionProxyGroup[]};
export type ProxyDelayResult={delays:Record<string,number>};
export type ProxySelectionResult={requiresReload:boolean};
export async function getProxies(sessionToken:string):Promise<ProxyGroup[]>{return isTauri()?invoke<ProxyGroup[]>("get_proxies",{sessionToken}):[];}
export async function getSavedProxySelection(sessionToken:string):Promise<string|undefined>{return isTauri()?invoke<string|null>("get_saved_proxy_selection",{sessionToken}).then(value=>value??undefined):undefined;}
export async function getSubscriptionProxies(sessionToken:string,subscriptionId:string):Promise<SubscriptionProxyInfo>{if(isTauri())return invoke<SubscriptionProxyInfo>("get_subscription_proxies",{sessionToken,subscriptionId});return{proxies:[],groups:[]};}
export async function selectProxy(sessionToken:string,group:string,name:string):Promise<ProxySelectionResult>{
  if(!isTauri())return{requiresReload:false};
  const result=await invoke<ProxySelectionResult|null>("select_proxy",{sessionToken,group,name});
  return result??{requiresReload:false};
}
export async function testAllProxyDelays(sessionToken:string,group="CleanWeb"):Promise<ProxyDelayResult>{if(isTauri())return invoke<ProxyDelayResult>("test_all_proxy_delays",{sessionToken,group});return{delays:{}};}
export async function syncAccessLogs():Promise<number>{return isTauri()?invoke("sync_access_logs"):0;}
export async function listAccessLogs(sessionToken:string,decision?:string,search?:string,limit=500):Promise<AccessLog[]>{return isTauri()?invoke("list_access_logs",{sessionToken,decision,search,limit}):[];}
export async function getAccessLogStats(sessionToken:string):Promise<AccessLogStats>{
  if(isTauri())return invoke("access_log_stats",{sessionToken});
  const logs=await listAccessLogs(sessionToken,undefined,undefined,5000);
  return {
    block: logs.filter(log=>log.decision==="block").length,
    allow: logs.filter(log=>log.decision==="allow").length,
    warning: logs.filter(log=>log.decision==="warning").length,
    total: logs.length,
  };
}
export async function getPublicAccessLogStats():Promise<AccessLogStats>{
  if(isTauri())return invoke("public_access_log_stats");
  return getAccessLogStats("browser-preview");
}
export async function clearAccessLogs(sessionToken:string):Promise<number>{return isTauri()?invoke("clear_access_logs",{sessionToken}):0;}
export async function exportAccessLogsCsv(sessionToken:string):Promise<string>{return isTauri()?invoke("export_access_logs_csv",{sessionToken}):"time,domain\n";}
export async function onAccessLogsUpdated(callback:()=>void):Promise<()=>void>{
  if(!isTauri())return()=>{};
  const { listen } = await import("@tauri-apps/api/event");
  return listen("access-logs-updated", callback);
}
export async function listParentRules(sessionToken:string):Promise<ParentRule[]>{if(isTauri())return invoke("list_parent_rules",{sessionToken});previewParentRules=loadPreviewParentRules();return structuredClone(previewParentRules);}
export async function createParentRule(sessionToken:string,input:NewParentRule):Promise<ParentRule>{if(isTauri())return invoke("create_parent_rule",{sessionToken,input});const item={...input,id:crypto.randomUUID(),enabled:true};previewParentRules.unshift(item);savePreviewParentRules();return item;}
export async function setParentRuleEnabled(sessionToken:string,id:string,enabled:boolean):Promise<void>{if(isTauri())return invoke("set_parent_rule_enabled",{sessionToken,id,enabled});const item=previewParentRules.find(value=>value.id===id);if(item){item.enabled=enabled;savePreviewParentRules();}}
export async function deleteParentRule(sessionToken:string,id:string):Promise<void>{if(isTauri())return invoke("delete_parent_rule",{sessionToken,id});const index=previewParentRules.findIndex(value=>value.id===id);if(index>=0){previewParentRules.splice(index,1);savePreviewParentRules();}}

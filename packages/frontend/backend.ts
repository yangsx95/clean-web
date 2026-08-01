import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";

export type Settings = {
  protectionEnabled: boolean;
  proxyEnabled: boolean;
  automaticNodeSelection: boolean;
  accessLoggingEnabled: boolean;
  safeSearchEnabled: boolean;
  strictModeEnabled: boolean;
  logRetention: string;
  categories: Record<string, boolean>;
  browserPolicy: Record<string, boolean>;
};
export type Subscription = { id:string; kind:"rule"|"proxy"; name:string; url:string; format?:string; category?:string; updateIntervalHours?:number; enabled:boolean; lastUpdatedAt?:string; lastError?:string; importedRuleCount?:number; activeRuleCount?:number };
export type NewSubscription = Omit<Subscription, "id"|"enabled"|"lastUpdatedAt"|"lastError"|"importedRuleCount">;
export type UpdateSubscription = Omit<NewSubscription, "kind">;
export type ManualProxyImport = { name:string; content:string };
export type RefreshReport = { detectedFormat:string; importedCount:number; ignoredCount:number; proxyCount:number; groupCount:number };
export type SubscriptionRefreshProgress = {
  id:string;
  phase:"queued"|"downloading"|"importing"|"applying"|"complete"|"failed";
  downloadedBytes:number;
  totalBytes?:number|null;
  percent?:number|null;
  message:string;
};
export type CoreStatus = { running:boolean; pid?:number; controller:string; configPath:string };
export type AccessLog={id:string;observedAt:string;domain?:string;targetIp?:string;targetPort?:number;decision:"allow"|"block"|"warning";rule?:string;category?:string;processName?:string;operatingSystem:string;systemUser:string;sourceIp?:string;route?:string;proxyGroup?:string;error?:string;repeatCount?:number};
export type AccessLogStats={block:number;allow:number;warning:number;total:number;todayBlock:number;todayAllow:number;todayWarning:number;todayTotal:number};
export type ParentRule={id:string;action:"allow"|"block"|"proxy"|"system_route";kind:string;pattern:string;category:string;enabled:boolean};
export type NewParentRule=Pick<ParentRule,"action"|"kind"|"pattern"|"category">;
export type RuleDiagnosticMatch={id:string;source:string;action:"allow"|"block"|"proxy"|"system_route"|string;kind:string;pattern:string;category:string;priority:number};
export type RuleDiagnosticResult={query:string;normalizedDomain?:string|null;targetIp?:string|null;matched?:RuleDiagnosticMatch|null;candidates:RuleDiagnosticMatch[]};
export type BrowserPolicyDetail={key:string;label:string;enabled:boolean;configured:boolean;currentValue?:string|null;expectedValue:string};
export type BrowserPolicyBrowserStatus={id:string;name:string;installed:boolean;configured:boolean;needsRestart:boolean;details:BrowserPolicyDetail[]};
export type BrowserPolicyStatus={browsers:BrowserPolicyBrowserStatus[]};
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
  categories: { pornography: true, gambling: true, drugs: true, violence: true, self_harm: true, hate_extremism: true, fraud: true, phishing: true, malware: true, ads: true, tracking: true, entertainment: false },
  browserPolicy: { force_google_safe_search: true, force_youtube_restrict: true, disable_doh: true, use_system_dns_client: true },
};
const defaultCoreStatus: CoreStatus = { running: false, controller: "127.0.0.1:19090", configPath: "preview" };

let defaults: Settings = loadPreviewSettings();
let previewCoreStatus: CoreStatus = loadPreviewCoreStatus();

const isTauri = () => "__TAURI_INTERNALS__" in window;
const isBuiltinSubscription = (item: Pick<Subscription, "id" | "name" | "url">) =>
  item.id.startsWith("default:") ||
  item.id.startsWith("local:cleanweb:") ||
  item.url.startsWith("builtin://") ||
  item.name.startsWith("内置规则") ||
  item.name.startsWith("内置路由");
function loadPreviewSettings(): Settings {
  try {
    const raw = window.localStorage.getItem(previewSettingsKey);
    if(!raw)return structuredClone(defaultSettings);
    const parsed=JSON.parse(raw);
    return { ...structuredClone(defaultSettings), ...parsed, categories:{...defaultSettings.categories,...parsed.categories}, browserPolicy:{...defaultSettings.browserPolicy,...parsed.browserPolicy} };
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

export async function verifyPassword(password: string) {
  if (isTauri()) await invoke("verify_password", { password });
  else if (password.length < 8) throw new Error("管理密码错误");
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
  if (key.startsWith("browser_policy.")) defaults.browserPolicy[key.slice(15)] = value === "true";
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
export async function updateSubscription(sessionToken: string, id: string, input: UpdateSubscription): Promise<Subscription> {
  if (isTauri()) return invoke("update_subscription", { sessionToken, id, input });
  const item=previewSubscriptions.find((value)=>value.id===id);
  if(!item)throw new Error("订阅不存在");
  if(isBuiltinSubscription(item))throw new Error("内置规则不能修改");
  Object.assign(item, input, { lastError: undefined });
  savePreviewSubscriptions();
  return structuredClone(item);
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
  const item=previewSubscriptions.find((value)=>value.id===id);
  if(item&&isBuiltinSubscription(item)&&!enabled)throw new Error("内置规则必须保持启用");
  if(item){item.enabled=enabled;savePreviewSubscriptions();}
}
export async function deleteSubscription(sessionToken:string,id:string) {
  if (isTauri()) return invoke("delete_subscription", { sessionToken,id });
  const item=previewSubscriptions.find((value)=>value.id===id);
  if(item&&isBuiltinSubscription(item))throw new Error("内置规则不能删除");
  const index=previewSubscriptions.findIndex((value)=>value.id===id); if(index>=0){previewSubscriptions.splice(index,1);savePreviewSubscriptions();}
}
export type RecommendedSource={name:string;url:string;format:string;category:string;description:string};
const previewRecommendedSources:RecommendedSource[]=[];
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
export type ProxyConnectivityResult={url:string;group:string;delay:number};
export async function getProxies(sessionToken:string):Promise<ProxyGroup[]>{return isTauri()?invoke<ProxyGroup[]>("get_proxies",{sessionToken}):[];}
export async function getSavedProxySelection(sessionToken:string):Promise<string|undefined>{return isTauri()?invoke<string|null>("get_saved_proxy_selection",{sessionToken}).then(value=>value??undefined):undefined;}
export async function getSubscriptionProxies(sessionToken:string,subscriptionId:string):Promise<SubscriptionProxyInfo>{if(isTauri())return invoke<SubscriptionProxyInfo>("get_subscription_proxies",{sessionToken,subscriptionId});return{proxies:[],groups:[]};}
export async function selectProxy(sessionToken:string,group:string,name:string):Promise<ProxySelectionResult>{
  if(!isTauri())return{requiresReload:false};
  const result=await invoke<ProxySelectionResult|null>("select_proxy",{sessionToken,group,name});
  return result??{requiresReload:false};
}
export async function testAllProxyDelays(sessionToken:string,group="CleanWeb"):Promise<ProxyDelayResult>{if(isTauri())return invoke<ProxyDelayResult>("test_all_proxy_delays",{sessionToken,group});return{delays:{}};}
export async function testProxyConnectivity(sessionToken:string,target:string,group="CleanWeb"):Promise<ProxyConnectivityResult>{
  if(isTauri())return invoke<ProxyConnectivityResult>("test_proxy_connectivity",{sessionToken,target,group});
  const url=target.includes("://")?target:`https://${target}`;
  return{url,group,delay:128};
}
export async function syncAccessLogs():Promise<number>{return isTauri()?invoke("sync_access_logs"):0;}
export async function listAccessLogs(sessionToken:string,decision?:string,search?:string,limit=500):Promise<AccessLog[]>{return isTauri()?invoke("list_access_logs",{sessionToken,decision,search,limit}):[];}
export async function getAccessLogStats(sessionToken:string):Promise<AccessLogStats>{
  if(isTauri())return invoke("access_log_stats",{sessionToken});
  const logs=await listAccessLogs(sessionToken,undefined,undefined,5000);
  const count=(log:AccessLog)=>log.repeatCount??1;
  return {
    block: logs.filter(log=>log.decision==="block").reduce((sum,log)=>sum+count(log),0),
    allow: logs.filter(log=>log.decision==="allow").reduce((sum,log)=>sum+count(log),0),
    warning: logs.filter(log=>log.decision==="warning").reduce((sum,log)=>sum+count(log),0),
    total: logs.reduce((sum,log)=>sum+count(log),0),
    todayBlock: logs.filter(log=>log.decision==="block"&&isToday(log.observedAt)).reduce((sum,log)=>sum+count(log),0),
    todayAllow: logs.filter(log=>log.decision==="allow"&&isToday(log.observedAt)).reduce((sum,log)=>sum+count(log),0),
    todayWarning: logs.filter(log=>log.decision==="warning"&&isToday(log.observedAt)).reduce((sum,log)=>sum+count(log),0),
    todayTotal: logs.filter(log=>isToday(log.observedAt)).reduce((sum,log)=>sum+count(log),0),
  };
}
export async function getPublicAccessLogStats():Promise<AccessLogStats>{
  if(isTauri())return invoke("public_access_log_stats");
  return getAccessLogStats("browser-preview");
}
export async function clearAccessLogs(sessionToken:string):Promise<number>{return isTauri()?invoke("clear_access_logs",{sessionToken}):0;}
export async function exportAccessLogsCsv(sessionToken:string):Promise<string>{return isTauri()?invoke("export_access_logs_csv",{sessionToken}):"\ufefftime,domain\n";}
export async function saveAccessLogsCsv(sessionToken:string):Promise<string|null>{
  if(!isTauri()){
    const csv=await exportAccessLogsCsv(sessionToken);
    const url=URL.createObjectURL(new Blob([csv],{type:"text/csv;charset=utf-8"}));
    const link=document.createElement("a");
    link.href=url;
    link.download="cleanweb-access-logs.csv";
    link.click();
    URL.revokeObjectURL(url);
    return "cleanweb-access-logs.csv";
  }
  const path=await save({
    title:"导出访问日志",
    defaultPath:"cleanweb-access-logs.csv",
    filters:[{name:"CSV",extensions:["csv"]}],
  });
  if(!path)return null;
  await invoke("export_access_logs_csv_to_path",{sessionToken,path});
  return path;
}

function isToday(value:string):boolean{
  const date=new Date(value);
  const today=new Date();
  return !Number.isNaN(date.getTime())&&date.toDateString()===today.toDateString();
}
export async function onAccessLogsUpdated(callback:()=>void):Promise<()=>void>{
  if(!isTauri())return()=>{};
  const { listen } = await import("@tauri-apps/api/event");
  return listen("access-logs-updated", callback);
}
export async function onSubscriptionRefreshProgress(callback:(progress:SubscriptionRefreshProgress)=>void):Promise<()=>void>{
  if(!isTauri())return()=>{};
  const { listen } = await import("@tauri-apps/api/event");
  return listen<SubscriptionRefreshProgress>("subscription-refresh-progress", event=>callback(event.payload));
}
export async function onQuitRequested(callback:()=>void):Promise<()=>void>{
  if(!isTauri())return()=>{};
  const { listen } = await import("@tauri-apps/api/event");
  return listen("cleanweb-quit-requested", callback);
}
export async function takePendingQuitRequest():Promise<boolean>{return isTauri()?invoke("take_pending_quit_request"):false;}
export async function hideMainWindow():Promise<void>{if(isTauri())await invoke("hide_main_window");}
export async function confirmedQuit(password:string):Promise<void>{
  if(isTauri())await invoke("confirmed_quit",{password});
  else await verifyPassword(password);
}
export async function listParentRules(sessionToken:string):Promise<ParentRule[]>{if(isTauri())return invoke("list_parent_rules",{sessionToken});previewParentRules=loadPreviewParentRules();return structuredClone(previewParentRules);}
export async function createParentRule(sessionToken:string,input:NewParentRule):Promise<ParentRule>{if(isTauri())return invoke("create_parent_rule",{sessionToken,input});const item={...input,id:crypto.randomUUID(),enabled:true};previewParentRules.unshift(item);savePreviewParentRules();return item;}
export async function setParentRuleEnabled(sessionToken:string,id:string,enabled:boolean):Promise<void>{if(isTauri())return invoke("set_parent_rule_enabled",{sessionToken,id,enabled});const item=previewParentRules.find(value=>value.id===id);if(item){item.enabled=enabled;savePreviewParentRules();}}
export async function deleteParentRule(sessionToken:string,id:string):Promise<void>{if(isTauri())return invoke("delete_parent_rule",{sessionToken,id});const index=previewParentRules.findIndex(value=>value.id===id);if(index>=0){previewParentRules.splice(index,1);savePreviewParentRules();}}
export async function diagnoseRuleMatch(sessionToken:string,query:string):Promise<RuleDiagnosticResult>{
  if(isTauri())return invoke("diagnose_rule_match",{sessionToken,query});
  const normalized=query.trim().replace(/^https?:\/\//,"").split(/[/:]/)[0].toLowerCase();
  const candidates=previewParentRules.filter(rule=>rule.enabled&&previewRuleMatches(rule,normalized)).map(rule=>({id:rule.id,source:"手动规则",action:rule.action,kind:rule.kind,pattern:rule.pattern,category:rule.category,priority:rule.action==="block"?20:rule.action==="allow"?30:80}));
  candidates.sort((a,b)=>a.priority-b.priority);
  return{query,normalizedDomain:normalized,targetIp:undefined,matched:candidates[0]??null,candidates};
}
function previewRuleMatches(rule:ParentRule,target:string):boolean{
  const pattern=rule.pattern.toLowerCase();
  if(rule.kind==="exact")return target===pattern;
  if(rule.kind==="suffix")return target===pattern||target.endsWith(`.${pattern}`);
  if(rule.kind==="contains")return target.includes(pattern);
  if(rule.kind==="wildcard")return new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g,"\\$&").replace(/\*/g,".*").replace(/\?/g,".")}$`,"i").test(target);
  if(rule.kind==="regex")try{return new RegExp(pattern,"i").test(target);}catch{return false;}
  return target===pattern;
}
function previewBrowserPolicyDetails():BrowserPolicyDetail[]{return [
    {key:"browser_policy.force_google_safe_search",label:"强制 Google SafeSearch",enabled:true,configured:false,expectedValue:"true"},
    {key:"browser_policy.force_youtube_restrict",label:"YouTube 受限模式",enabled:true,configured:false,expectedValue:"2"},
    {key:"browser_policy.disable_doh",label:"关闭浏览器 DoH",enabled:true,configured:false,expectedValue:"off"},
    {key:"browser_policy.use_system_dns_client",label:"使用系统 DNS 客户端",enabled:true,configured:false,expectedValue:"false"},
  ];}
const previewBrowserPolicyStatus:BrowserPolicyStatus={browsers:[
  {id:"chrome",name:"Chrome",installed:true,configured:false,needsRestart:false,details:previewBrowserPolicyDetails()},
  {id:"edge",name:"Edge",installed:true,configured:false,needsRestart:false,details:previewBrowserPolicyDetails()},
  {id:"brave",name:"Brave",installed:false,configured:false,needsRestart:false,details:previewBrowserPolicyDetails()},
  {id:"vivaldi",name:"Vivaldi",installed:false,configured:false,needsRestart:false,details:previewBrowserPolicyDetails()},
  {id:"chromium",name:"Chromium",installed:false,configured:false,needsRestart:false,details:previewBrowserPolicyDetails()},
]};
export async function getBrowserPolicyStatus():Promise<BrowserPolicyStatus>{return isTauri()?invoke("get_browser_policy_status"):structuredClone(previewBrowserPolicyStatus);}
export async function applyBrowserPolicies(sessionToken:string):Promise<BrowserPolicyStatus>{
  if(isTauri())return invoke("apply_browser_policies",{sessionToken});
  const applied=structuredClone(previewBrowserPolicyStatus);
  applied.browsers=applied.browsers.map(browser=>({...browser,configured:true,needsRestart:true,details:browser.details.map(detail=>{const settingKey=detail.key.replace("browser_policy.","");const enabled=defaults.browserPolicy[settingKey]??true;return {...detail,enabled,configured:true,currentValue:enabled?detail.expectedValue:null};})}));
  return applied;
}

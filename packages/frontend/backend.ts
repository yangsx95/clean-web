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
export type Subscription = { id:string; kind:"rule"|"proxy"; name:string; url:string; format?:string; category?:string; updateIntervalHours?:number; enabled:boolean; lastUpdatedAt?:string; lastError?:string; importedRuleCount?:number; activeRuleCount?:number; uiGroup?:string; uiOrder?:number; toggleable?:boolean; description?:string };
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
export type CoreComponentStatus = { id:string; label:string; status:"ready"|"warning"|"stopped"; detail:string };
export type CoreStatus = { running:boolean; pid?:number; controller:string; configPath:string; components?:CoreComponentStatus[] };
export type RuntimeProgress = { operation:string; phase:string; percent:number; message:string; components:CoreComponentStatus[] };
export type MobileVpnStatus = { supported:boolean; prepared:boolean; running:boolean; stage:string; dataPlaneReady:boolean; lastError?:string|null };
export type AccessLog={id:string;observedAt:string;domain?:string;targetIp?:string;targetPort?:number;decision:"allow"|"block"|"warning";rule?:string;category?:string;processName?:string;operatingSystem:string;systemUser:string;sourceIp?:string;route?:string;proxyGroup?:string;error?:string;repeatCount?:number};
export type AccessLogStats={block:number;allow:number;warning:number;total:number;todayBlock:number;todayAllow:number;todayWarning:number;todayTotal:number};
export type AccessLogDailyStats={date:string;label:string;block:number;allow:number;warning:number;total:number};
export type ParentRule={id:string;action:"allow"|"block"|"proxy"|"system_route";kind:string;pattern:string;category:string;enabled:boolean};
export type NewParentRule=Pick<ParentRule,"action"|"kind"|"pattern"|"category">;
export type RuleDiagnosticMatch={id:string;source:string;action:"allow"|"block"|"proxy"|"system_route"|string;kind:string;pattern:string;category:string;priority:number;matched?:boolean};
export type RuleDiagnosticResult={query:string;normalizedDomain?:string|null;targetIp?:string|null;summaryAction?:string;summaryLabel?:string;matched?:RuleDiagnosticMatch|null;candidates:RuleDiagnosticMatch[]};
export type BrowserPolicyDetail={key:string;label:string;enabled:boolean;configured:boolean;currentValue?:string|null;expectedValue:string};
export type BrowserPolicyBrowserStatus={id:string;name:string;engineId:string;engineName:string;installed:boolean;configured:boolean;needsRestart:boolean;details:BrowserPolicyDetail[]};
export type BrowserPolicyStatus={browsers:BrowserPolicyBrowserStatus[]};
const previewSettingsKey = "cleanweb.preview.settings";
const previewCoreStatusKey = "cleanweb.preview.coreStatus";
const previewParentRulesKey = "cleanweb.preview.parentRules";
const previewSubscriptionsKey = "cleanweb.preview.subscriptions";
const sessionTokenKey = "cleanweb.sessionToken";
let previewParentRules:ParentRule[] = loadPreviewParentRules();
let previewSubscriptions: Subscription[] = [];

export const defaultSettings: Settings = {
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
const defaultCoreStatus: CoreStatus = { running: false, controller: "127.0.0.1:19090", configPath: "preview", components: previewCoreComponents(false) };

let defaults: Settings = loadPreviewSettings();
let previewCoreStatus: CoreStatus = loadPreviewCoreStatus();

const isTauri = () => "__TAURI_INTERNALS__" in window;
const isMobileTauri = () => isTauri() && /Android|iPhone|iPad|iPod/i.test(window.navigator.userAgent);
const usesDesktopBackend = () => isTauri() && !isMobileTauri();
const previewSession = (password: string) => password.length < 8
  ? (() => { throw new Error("管理密码错误"); })()
  : { sessionToken: "browser-preview", expiresInSeconds: 900 };
const mobileCoreStatus = (status: MobileVpnStatus): CoreStatus => ({
  running: status.running,
  controller: status.supported ? `android-vpn:${status.stage}` : "android-vpn:unsupported",
  configPath: status.dataPlaneReady ? "android-vpn" : "android-vpn-shell",
  components: [
    { id:"mobile-vpn", label:"移动 VPN", status:status.running?"ready":status.supported?"stopped":"warning", detail:status.supported ? status.stage : "当前平台暂不支持" },
    { id:"mobile-policy", label:"策略载入", status:status.prepared?"ready":"stopped", detail:status.prepared ? "VPN 权限已准备" : "等待系统授权" },
    { id:"mobile-data-plane", label:"数据通道", status:status.dataPlaneReady?"ready":"stopped", detail:status.dataPlaneReady ? "VPN 数据面正常" : "数据面未就绪" },
  ],
});
const mobileVpnStatus = async () => invoke<MobileVpnStatus>("mobile_vpn_status");
const mobilePrepareVpn = async () => invoke<MobileVpnStatus>("mobile_prepare_vpn");
const mobileStartVpn = async () => invoke<MobileVpnStatus>("mobile_start_vpn");
const mobileStopVpn = async () => invoke<MobileVpnStatus>("mobile_stop_vpn");
const mobileUpdatePolicy = async (policyJson: string) => invoke<MobileVpnStatus>("mobile_update_policy", { payload:{ policyJson } });
const mobileRefreshSubscription = async (payload: { id:string; url:string; format?:string; category?:string }) => invoke<RefreshReport>("mobile_refresh_subscription", { payload });
async function mobilePolicyPayload(){
  defaults=loadPreviewSettings();
  previewParentRules=loadPreviewParentRules();
  previewSubscriptions=loadPreviewSubscriptions();
  return {
    settings: defaults,
    parentRules: previewParentRules,
    subscriptions: previewSubscriptions.filter(item=>item.kind==="rule").map(item=>({id:item.id,url:item.url,category:item.category,format:item.format,enabled:item.enabled})),
    updatedAt: new Date().toISOString(),
  };
}
const isBuiltinSubscription = (item: Pick<Subscription, "id" | "name" | "url">) =>
  item.id.startsWith("default:") ||
  item.id.startsWith("local:cleanweb:") ||
  item.url.startsWith("builtin://") ||
  item.name.startsWith("内置规则") ||
  item.name.startsWith("内置路由");
const previewBuiltinSubscriptions: Subscription[] = [
  {id:"default:stevenblack:porn",kind:"rule",name:"StevenBlack · Porn-only Hosts",url:"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",format:"hosts",category:"pornography",updateIntervalHours:24,enabled:true,lastUpdatedAt:"2026-08-01 08:00:00",importedRuleCount:128,activeRuleCount:128,uiGroup:"色情内容",uiOrder:10,description:"StevenBlack 成人内容基础 hosts 列表"},
  {id:"default:blocklistproject:porn",kind:"rule",name:"The Block List Project · Porn (NL)",url:"https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/porn-nl.txt",format:"domain-list",category:"pornography",updateIntervalHours:24,enabled:true,lastUpdatedAt:"2026-08-01 08:02:00",importedRuleCount:953393,activeRuleCount:953393,uiGroup:"色情内容",uiOrder:11,description:"Block List Project 成人内容域名列表"},
  {id:"default:cleanweb:adult-supplement",kind:"rule",name:"CleanWeb · Adult Supplement",url:"https://raw.githubusercontent.com/yangsx95/clean-web/main/resources/rules/cleanweb-adult-supplement.clash",format:"clash",category:"pornography",updateIntervalHours:24,enabled:true,lastUpdatedAt:"2026-08-01 08:03:00",importedRuleCount:72,activeRuleCount:72,uiGroup:"色情内容",uiOrder:12,description:"CleanWeb 成人内容补充规则"},
  {id:"default:cleanweb:strict-adult-keywords",kind:"rule",name:"CleanWeb · 严格成人关键词",url:"https://raw.githubusercontent.com/yangsx95/clean-web/main/resources/rules/cleanweb-strict-adult-keywords.clash",format:"clash",category:"strict",updateIntervalHours:24,enabled:false,lastUpdatedAt:"2026-08-01 08:13:00",importedRuleCount:19,activeRuleCount:0,uiGroup:"高风险域名与平台",uiOrder:80,toggleable:true,description:"严格模式成人内容关键词规则"},
  {id:"default:stevenblack:gambling",kind:"rule",name:"StevenBlack · Gambling-only Hosts",url:"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts",format:"hosts",category:"gambling",updateIntervalHours:24,enabled:true,lastUpdatedAt:"2026-08-01 08:04:00",importedRuleCount:24736,activeRuleCount:24736,uiGroup:"赌博内容",uiOrder:20,description:"StevenBlack 赌博站点基础 hosts 列表"},
  {id:"default:cleanweb:strict-gambling-keywords",kind:"rule",name:"CleanWeb · 严格赌博关键词",url:"https://raw.githubusercontent.com/yangsx95/clean-web/main/resources/rules/cleanweb-strict-gambling-keywords.clash",format:"clash",category:"strict",updateIntervalHours:24,enabled:false,lastUpdatedAt:"2026-08-01 08:14:00",importedRuleCount:6,activeRuleCount:0,uiGroup:"高风险域名与平台",uiOrder:81,toggleable:true,description:"严格模式赌博关键词规则"},
  {id:"default:cleanweb:strict-restricted-platforms",kind:"rule",name:"CleanWeb · 受限平台",url:"https://raw.githubusercontent.com/yangsx95/clean-web/main/resources/rules/cleanweb-strict-restricted-platforms.clash",format:"clash",category:"strict",updateIntervalHours:24,enabled:false,importedRuleCount:7,activeRuleCount:0,uiGroup:"高风险域名与平台",uiOrder:82,toggleable:true,description:"严格模式下限制 Yandex 等指定平台"},
  {id:"default:cleanweb:strict-risky-tlds",kind:"rule",name:"CleanWeb · 高风险域名后缀",url:"https://raw.githubusercontent.com/yangsx95/clean-web/main/resources/rules/cleanweb-strict-risky-tlds.clash",format:"clash",category:"strict",updateIntervalHours:24,enabled:false,importedRuleCount:12,activeRuleCount:0,uiGroup:"高风险域名与平台",uiOrder:83,toggleable:true,description:"激进拦截 .cc、.top、.xyz 等高滥用风险后缀，可能误伤正规网站"},
  {id:"default:blocklistproject:drugs",kind:"rule",name:"The Block List Project · Drugs (NL)",url:"https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/drugs-nl.txt",format:"domain-list",category:"drugs",updateIntervalHours:24,enabled:true,lastUpdatedAt:"2026-08-01 08:05:00",importedRuleCount:6231,activeRuleCount:6231,uiGroup:"毒品内容",uiOrder:30,description:"Block List Project 毒品相关域名列表"},
  {id:"default:blocklistproject:fraud",kind:"rule",name:"The Block List Project · Fraud (NL)",url:"https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/fraud-nl.txt",format:"domain-list",category:"fraud",updateIntervalHours:24,enabled:true,lastUpdatedAt:"2026-08-01 08:06:00",importedRuleCount:18341,activeRuleCount:18341,uiGroup:"安全风险",uiOrder:40,description:"Block List Project 诈骗域名列表"},
  {id:"default:blocklistproject:phishing",kind:"rule",name:"The Block List Project · Phishing (NL)",url:"https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/phishing-nl.txt",format:"domain-list",category:"phishing",updateIntervalHours:24,enabled:true,lastUpdatedAt:"2026-08-01 08:07:00",importedRuleCount:98144,activeRuleCount:98144,uiGroup:"安全风险",uiOrder:41,description:"Block List Project 钓鱼域名列表"},
  {id:"default:urlhaus:malware",kind:"rule",name:"URLhaus · Malware Hostfile",url:"https://urlhaus.abuse.ch/downloads/hostfile/",format:"hosts",category:"malware",updateIntervalHours:24,enabled:true,lastUpdatedAt:"2026-08-01 08:08:00",importedRuleCount:1411,activeRuleCount:1411,uiGroup:"安全风险",uiOrder:42,description:"URLhaus 恶意软件分发域名列表"},
  {id:"default:cleanweb:security-supplement",kind:"rule",name:"CleanWeb · Security Supplement",url:"https://raw.githubusercontent.com/yangsx95/clean-web/main/resources/rules/cleanweb-security-supplement.clash",format:"clash",category:"phishing",updateIntervalHours:24,enabled:true,lastUpdatedAt:"2026-08-01 08:09:00",importedRuleCount:39,activeRuleCount:39,uiGroup:"安全风险",uiOrder:43,description:"CleanWeb 安全风险补充规则"},
  {id:"default:cleanweb:safe-search",kind:"rule",name:"CleanWeb · SafeSearch DNS Mappings",url:"https://raw.githubusercontent.com/yangsx95/clean-web/main/resources/rules/cleanweb-safe-search.yaml",format:"safe-search",category:"custom",updateIntervalHours:24,enabled:true,lastUpdatedAt:"2026-08-01 08:10:00",importedRuleCount:14,activeRuleCount:14,uiGroup:"安全搜索",uiOrder:50,toggleable:true,description:"搜索引擎安全模式 DNS 补强映射"},
  {id:"local:cleanweb:entertainment-short-video",kind:"rule",name:"CleanWeb · 短视频与直播",url:"https://raw.githubusercontent.com/yangsx95/clean-web/main/resources/rules/cleanweb-entertainment-short-video.clash",format:"clash",category:"entertainment",updateIntervalHours:24,enabled:false,lastUpdatedAt:"2026-08-01 08:12:00",importedRuleCount:44,activeRuleCount:0,uiGroup:"短视频与直播",uiOrder:60,toggleable:true,description:"抖音、TikTok、快手、B 站、直播和视频平台"},
  {id:"local:cleanweb:entertainment-social",kind:"rule",name:"CleanWeb · 社交社区",url:"https://raw.githubusercontent.com/yangsx95/clean-web/main/resources/rules/cleanweb-entertainment-social.clash",format:"clash",category:"entertainment",updateIntervalHours:24,enabled:false,lastUpdatedAt:"2026-08-01 08:12:00",importedRuleCount:29,activeRuleCount:0,uiGroup:"社交社区",uiOrder:61,toggleable:true,description:"Instagram、Telegram、X、Reddit 等社交社区平台"},
  {id:"local:cleanweb:entertainment-games",kind:"rule",name:"CleanWeb · 游戏内容",url:"https://raw.githubusercontent.com/yangsx95/clean-web/main/resources/rules/cleanweb-entertainment-games.clash",format:"clash",category:"entertainment",updateIntervalHours:24,enabled:false,lastUpdatedAt:"2026-08-01 08:12:00",importedRuleCount:68,activeRuleCount:0,uiGroup:"游戏内容",uiOrder:62,toggleable:true,description:"国内外游戏平台、发行商和游戏社区"},
  {id:"default:adaway:hosts",kind:"rule",name:"AdAway · Hosts",url:"https://adaway.org/hosts.txt",format:"hosts",category:"ads",updateIntervalHours:24,enabled:false,lastUpdatedAt:"2026-08-01 08:15:00",importedRuleCount:7124,activeRuleCount:0,uiGroup:"广告与跟踪",uiOrder:70,toggleable:true,description:"AdAway 官方 hosts 广告拦截列表，体量较轻"},
  {id:"default:easylist:ads",kind:"rule",name:"EasyList · Ads",url:"https://easylist.to/easylist/easylist.txt",format:"adblock",category:"ads",updateIntervalHours:24,enabled:false,lastUpdatedAt:"2026-08-01 08:16:00",importedRuleCount:68342,activeRuleCount:0,uiGroup:"广告与跟踪",uiOrder:71,toggleable:true,description:"EasyList 官方英文广告过滤规则"},
  {id:"default:easylist:privacy",kind:"rule",name:"EasyPrivacy · Tracking",url:"https://easylist.to/easylist/easyprivacy.txt",format:"adblock",category:"ads",updateIntervalHours:24,enabled:false,lastUpdatedAt:"2026-08-01 08:17:00",importedRuleCount:42118,activeRuleCount:0,uiGroup:"广告与跟踪",uiOrder:72,toggleable:true,description:"EasyPrivacy 官方跟踪器拦截规则"},
  {id:"default:loyalsoldier:cncidr",kind:"rule",name:"Loyalsoldier · China CIDR Routes",url:"https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/cncidr.txt",format:"clash",category:"direct",updateIntervalHours:24,enabled:true,lastUpdatedAt:"2026-08-01 08:11:00",importedRuleCount:9512,activeRuleCount:9512,uiGroup:"网络基础",uiOrder:1,description:"中国大陆 IP 段直连路由基础规则"},
];
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
    const parsed = raw ? JSON.parse(raw) : null;
    const status = parsed ? { ...defaultCoreStatus, ...parsed } : structuredClone(defaultCoreStatus);
    return { ...status, components: Array.isArray(status.components) ? status.components : previewCoreComponents(status.running) };
  } catch {
    return structuredClone(defaultCoreStatus);
  }
}
function previewCoreComponents(running:boolean): CoreComponentStatus[] {
  return [
    { id:"mihomo", label:"Mihomo 内核", status:running?"ready":"stopped", detail:running?"预览进程运行中":"预览未运行" },
    { id:"active-config", label:"运行配置", status:running?"ready":"stopped", detail:running?"已记录当前配置":"等待启动后写入" },
    { id:"cleanweb-dns", label:"CleanWeb DNS", status:running?"ready":"stopped", detail:running?"127.0.0.1:19053 正常":"DNS 过滤未启动" },
    { id:"mihomo-dns", label:"本机 DNS 接管", status:running?"ready":"stopped", detail:running?"127.0.0.1:53 正常":"系统 DNS 未接管" },
  ];
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
    if (!raw) return structuredClone(previewBuiltinSubscriptions);
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed) || parsed.length === 0) return structuredClone(previewBuiltinSubscriptions);
    const records = new Map<string, Subscription>(parsed.map((item: Subscription) => [item.id, item]));
    for (const builtin of previewBuiltinSubscriptions) {
      if (!records.has(builtin.id)) records.set(builtin.id, structuredClone(builtin));
    }
    return Array.from(records.values());
  } catch {
    return structuredClone(previewBuiltinSubscriptions);
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
  return usesDesktopBackend() ? invoke<{ passwordConfigured: boolean }>("get_bootstrap_state") : { passwordConfigured: true };
}

export async function initializePassword(password: string) {
  if (usesDesktopBackend()) await invoke("initialize_password", { password });
}

export async function verifyPassword(password: string) {
  if (usesDesktopBackend()) await invoke("verify_password", { password });
  else if (password.length < 8) throw new Error("管理密码错误");
}

export async function unlock(password: string) {
  const result = usesDesktopBackend()
    ? await invoke<{ sessionToken: string; expiresInSeconds: number }>("unlock", { password })
    : previewSession(password);
  storeSessionToken(result.sessionToken);
  return result;
}

export async function lock(sessionToken: string) {
  if (usesDesktopBackend()) await invoke("lock", { sessionToken });
  clearStoredSessionToken();
}

export async function validateSession(sessionToken: string) {
  if (usesDesktopBackend()) return invoke<{ sessionToken: string; expiresInSeconds: number }>("validate_session", { sessionToken });
  if (sessionToken !== "browser-preview") throw new Error("管理会话已过期，请重新解锁");
  return { sessionToken, expiresInSeconds: 900 };
}

export async function getSettings(): Promise<Settings> {
  if (usesDesktopBackend()) return invoke<Settings>("get_settings");
  defaults = loadPreviewSettings();
  return structuredClone(defaults);
}

export async function updateSetting(sessionToken: string, key: string, value: string): Promise<Settings> {
  if (usesDesktopBackend()) return invoke<Settings>("update_setting", { sessionToken, key, value });
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
  if (!usesDesktopBackend()) previewSubscriptions = loadPreviewSubscriptions();
  return usesDesktopBackend() ? invoke("list_subscriptions", { sessionToken,kind }) : previewSubscriptions.filter((item) => !kind || item.kind === kind);
}
export async function createSubscription(sessionToken: string, input: NewSubscription): Promise<Subscription> {
  if (usesDesktopBackend()) return invoke("create_subscription", { sessionToken, input });
  const item: Subscription = { ...input, id: crypto.randomUUID(), enabled: true }; previewSubscriptions.unshift(item); savePreviewSubscriptions(); return item;
}
export async function updateSubscription(sessionToken: string, id: string, input: UpdateSubscription): Promise<Subscription> {
  if (usesDesktopBackend()) return invoke("update_subscription", { sessionToken, id, input });
  const item=previewSubscriptions.find((value)=>value.id===id);
  if(!item)throw new Error("订阅不存在");
  if(isBuiltinSubscription(item))throw new Error("内置规则不能修改");
  Object.assign(item, input, { lastError: undefined });
  savePreviewSubscriptions();
  return structuredClone(item);
}
export async function importProxyPayload(sessionToken: string, input: ManualProxyImport): Promise<Subscription> {
  if (usesDesktopBackend()) return invoke("import_proxy_payload", { sessionToken, input });
  const item: Subscription = { id: crypto.randomUUID(), kind: "proxy", name: input.name, url: "manual://preview", format: "clash", enabled: true, lastUpdatedAt: new Date().toISOString() };
  previewSubscriptions.unshift(item);
  savePreviewSubscriptions();
  return item;
}
export async function setSubscriptionEnabled(sessionToken:string,id:string,enabled:boolean) {
  if (usesDesktopBackend()) return invoke("set_subscription_enabled", { sessionToken,id,enabled });
  const item=previewSubscriptions.find((value)=>value.id===id);
  if(item&&isBuiltinSubscription(item)&&!enabled&&!item.toggleable)throw new Error("内置规则必须保持启用");
  if(item){
    item.enabled=enabled;
    if(enabled){
      if(item.category==="ads")defaults.categories.ads=true;
      if(item.category==="tracking")defaults.categories.tracking=true;
      if(item.category==="entertainment")defaults.categories.entertainment=true;
      if(item.category==="strict")defaults.strictModeEnabled=true;
      savePreviewSettings();
    }
    savePreviewSubscriptions();
  }
}
export async function deleteSubscription(sessionToken:string,id:string) {
  if (usesDesktopBackend()) return invoke("delete_subscription", { sessionToken,id });
  const item=previewSubscriptions.find((value)=>value.id===id);
  if(item&&isBuiltinSubscription(item))throw new Error("内置规则不能删除");
  const index=previewSubscriptions.findIndex((value)=>value.id===id); if(index>=0){previewSubscriptions.splice(index,1);savePreviewSubscriptions();}
}
export type RecommendedSource={name:string;url:string;format:string;category:string;description:string};
const previewRecommendedSources:RecommendedSource[]=[
  {name:"AdAway · Hosts",url:"https://adaway.org/hosts.txt",format:"hosts",category:"ads",description:"AdAway 官方 hosts 列表，适合作为轻量广告拦截源"},
  {name:"EasyList · Ads",url:"https://easylist.to/easylist/easylist.txt",format:"adblock",category:"ads",description:"EasyList 官方英文广告过滤列表，覆盖主流网页广告"},
  {name:"EasyPrivacy · Tracking",url:"https://easylist.to/easylist/easyprivacy.txt",format:"adblock",category:"ads",description:"EasyPrivacy 官方跟踪器过滤列表，补充隐私保护"},
  {name:"AdGuard · Base Filter",url:"https://filters.adtidy.org/extension/chromium/filters/2.txt",format:"adblock",category:"ads",description:"AdGuard 官方基础过滤规则，覆盖网页广告和常见跟踪"},
  {name:"AdGuard · Chinese Filter",url:"https://filters.adtidy.org/extension/chromium/filters/224.txt",format:"adblock",category:"ads",description:"AdGuard 官方中文过滤规则，适合补充国内网页广告"},
];
export async function getRecommendedSources():Promise<RecommendedSource[]>{return usesDesktopBackend()?invoke<RecommendedSource[]>("get_recommended_sources"):previewRecommendedSources;}
export async function refreshSubscription(sessionToken:string,id:string):Promise<RefreshReport>{
  if(usesDesktopBackend())return invoke("refresh_subscription",{sessionToken,id});
  if(isMobileTauri()){
    previewSubscriptions=loadPreviewSubscriptions();
    const item=previewSubscriptions.find(value=>value.id===id);
    if(!item)throw new Error("订阅不存在");
    const report=await mobileRefreshSubscription({id:item.id,url:item.url,format:item.format,category:item.category});
    Object.assign(item,{lastUpdatedAt:new Date().toISOString(),lastError:undefined,importedRuleCount:report.importedCount,activeRuleCount:item.enabled?report.importedCount:0});
    savePreviewSubscriptions();
    return report;
  }
  return {detectedFormat:"preview",importedCount:0,ignoredCount:0,proxyCount:0,groupCount:0};
}
export async function refreshDueSubscriptions():Promise<number>{return usesDesktopBackend()?invoke("refresh_due_subscriptions"):0;}
export async function getCoreStatus():Promise<CoreStatus>{if(usesDesktopBackend())return invoke("get_core_status");if(isMobileTauri())return mobileCoreStatus(await mobileVpnStatus());previewCoreStatus=loadPreviewCoreStatus();return structuredClone(previewCoreStatus);}
export async function startProtection(sessionToken:string):Promise<CoreStatus>{if(usesDesktopBackend())return invoke("start_protection",{sessionToken});if(isMobileTauri()){await mobileUpdatePolicy(JSON.stringify(await mobilePolicyPayload()));await mobilePrepareVpn();return mobileCoreStatus(await mobileStartVpn());}previewCoreStatus={running:true,pid:1234,controller:"127.0.0.1:19090",configPath:"preview",components:previewCoreComponents(true)};savePreviewCoreStatus();return structuredClone(previewCoreStatus);}
export async function autoStartProtection():Promise<CoreStatus>{return usesDesktopBackend()?invoke("auto_start_protection"):getCoreStatus();}
export async function stopProtection(sessionToken:string):Promise<CoreStatus>{if(usesDesktopBackend())return invoke("stop_protection",{sessionToken});if(isMobileTauri())return mobileCoreStatus(await mobileStopVpn());previewCoreStatus={running:false,controller:"127.0.0.1:19090",configPath:"preview",components:previewCoreComponents(false)};savePreviewCoreStatus();return structuredClone(previewCoreStatus);}
export async function reloadProtection(sessionToken:string):Promise<CoreStatus>{if(usesDesktopBackend())return invoke("reload_protection",{sessionToken});if(isMobileTauri()){await mobileUpdatePolicy(JSON.stringify(await mobilePolicyPayload()));return mobileCoreStatus(await mobileVpnStatus());}return getCoreStatus();}
export async function testProxyGroup(sessionToken:string,group="CleanWeb"):Promise<number>{if(!usesDesktopBackend())return 0;const value=await invoke<{delay:number}>("test_proxy_group",{sessionToken,group});return value.delay;}
export type ProxyNode={name:string;nodeType:string;delay?:number|null};
export type ProxyGroup={name:string;groupType:string;now:string;nodes:ProxyNode[]};
export type SubscriptionProxyNode={name:string;nodeType:string};
export type SubscriptionProxyGroup={name:string;groupType:string;members:string[]};
export type SubscriptionProxyInfo={proxies:SubscriptionProxyNode[];groups:SubscriptionProxyGroup[]};
export type ProxyDelayResult={delays:Record<string,number>};
export type ProxySelectionResult={requiresReload:boolean};
export type ProxyConnectivityResult={url:string;group:string;delay:number};
export async function getProxies(sessionToken:string):Promise<ProxyGroup[]>{return usesDesktopBackend()?invoke<ProxyGroup[]>("get_proxies",{sessionToken}):[];}
export async function getSavedProxySelection(sessionToken:string):Promise<string|undefined>{return usesDesktopBackend()?invoke<string|null>("get_saved_proxy_selection",{sessionToken}).then(value=>value??undefined):undefined;}
export async function getSubscriptionProxies(sessionToken:string,subscriptionId:string):Promise<SubscriptionProxyInfo>{if(usesDesktopBackend())return invoke<SubscriptionProxyInfo>("get_subscription_proxies",{sessionToken,subscriptionId});return{proxies:[],groups:[]};}
export async function selectProxy(sessionToken:string,group:string,name:string):Promise<ProxySelectionResult>{
  if(!usesDesktopBackend())return{requiresReload:false};
  const result=await invoke<ProxySelectionResult|null>("select_proxy",{sessionToken,group,name});
  return result??{requiresReload:false};
}
export async function testAllProxyDelays(sessionToken:string,group="CleanWeb"):Promise<ProxyDelayResult>{if(usesDesktopBackend())return invoke<ProxyDelayResult>("test_all_proxy_delays",{sessionToken,group});return{delays:{}};}
export async function testProxyConnectivity(sessionToken:string,target:string,group="CleanWeb"):Promise<ProxyConnectivityResult>{
  if(usesDesktopBackend())return invoke<ProxyConnectivityResult>("test_proxy_connectivity",{sessionToken,target,group});
  const url=target.includes("://")?target:`https://${target}`;
  return{url,group,delay:128};
}
export async function syncAccessLogs():Promise<number>{return usesDesktopBackend()?invoke("sync_access_logs"):0;}
export async function listAccessLogs(sessionToken:string,decision?:string,search?:string,limit=500):Promise<AccessLog[]>{return usesDesktopBackend()?invoke("list_access_logs",{sessionToken,decision,search,limit}):[];}
export async function getAccessLogStats(sessionToken:string):Promise<AccessLogStats>{
  if(usesDesktopBackend())return invoke("access_log_stats",{sessionToken});
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
  if(usesDesktopBackend())return invoke("public_access_log_stats");
  return getAccessLogStats("browser-preview");
}
export async function getAccessLogDailyStats(sessionToken:string):Promise<AccessLogDailyStats[]>{
  if(usesDesktopBackend())return invoke("access_log_daily_stats",{sessionToken});
  return previewAccessLogDailyStats();
}
export async function getPublicAccessLogDailyStats():Promise<AccessLogDailyStats[]>{
  if(usesDesktopBackend())return invoke("public_access_log_daily_stats");
  return previewAccessLogDailyStats();
}
function previewAccessLogDailyStats():AccessLogDailyStats[]{
  const formatter = new Intl.DateTimeFormat(undefined,{month:"2-digit",day:"2-digit"});
  return Array.from({length:7},(_,index)=>{
    const date = new Date();
    date.setDate(date.getDate() - (6 - index));
    const seed = index + 1;
    const allow = seed * 7;
    const block = index % 3 === 0 ? seed * 2 : seed;
    const warning = index % 4 === 0 ? 1 : 0;
    return {date:date.toISOString().slice(0,10),label:formatter.format(date),allow,block,warning,total:allow+block+warning};
  });
}
export async function clearAccessLogs(sessionToken:string):Promise<number>{return usesDesktopBackend()?invoke("clear_access_logs",{sessionToken}):0;}
export async function exportAccessLogsCsv(sessionToken:string):Promise<string>{return usesDesktopBackend()?invoke("export_access_logs_csv",{sessionToken}):"\ufefftime,domain\n";}
export async function saveAccessLogsCsv(sessionToken:string):Promise<string|null>{
  if(!usesDesktopBackend()){
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
  if(!usesDesktopBackend())return()=>{};
  const { listen } = await import("@tauri-apps/api/event");
  return listen("access-logs-updated", callback);
}
export async function onSubscriptionRefreshProgress(callback:(progress:SubscriptionRefreshProgress)=>void):Promise<()=>void>{
  if(!usesDesktopBackend())return()=>{};
  const { listen } = await import("@tauri-apps/api/event");
  return listen<SubscriptionRefreshProgress>("subscription-refresh-progress", event=>callback(event.payload));
}
export async function onRuntimeProgress(callback:(progress:RuntimeProgress)=>void):Promise<()=>void>{
  if(!usesDesktopBackend())return()=>{};
  const { listen } = await import("@tauri-apps/api/event");
  return listen<RuntimeProgress>("runtime-progress", event=>callback(event.payload));
}
export async function onQuitRequested(callback:()=>void):Promise<()=>void>{
  if(!usesDesktopBackend())return()=>{};
  const { listen } = await import("@tauri-apps/api/event");
  return listen("cleanweb-quit-requested", callback);
}
export async function takePendingQuitRequest():Promise<boolean>{return usesDesktopBackend()?invoke("take_pending_quit_request"):false;}
export async function hideMainWindow():Promise<void>{if(usesDesktopBackend())await invoke("hide_main_window");}
export async function confirmedQuit(password:string):Promise<void>{
  if(usesDesktopBackend())await invoke("confirmed_quit",{password});
  else await verifyPassword(password);
}
export async function listParentRules(sessionToken:string):Promise<ParentRule[]>{if(usesDesktopBackend())return invoke("list_parent_rules",{sessionToken});previewParentRules=loadPreviewParentRules();return structuredClone(previewParentRules);}
export async function createParentRule(sessionToken:string,input:NewParentRule):Promise<ParentRule>{if(usesDesktopBackend())return invoke("create_parent_rule",{sessionToken,input});const item={...input,id:crypto.randomUUID(),enabled:true};previewParentRules.unshift(item);savePreviewParentRules();return item;}
export async function setParentRuleEnabled(sessionToken:string,id:string,enabled:boolean):Promise<void>{if(usesDesktopBackend())return invoke("set_parent_rule_enabled",{sessionToken,id,enabled});const item=previewParentRules.find(value=>value.id===id);if(item){item.enabled=enabled;savePreviewParentRules();}}
export async function deleteParentRule(sessionToken:string,id:string):Promise<void>{if(usesDesktopBackend())return invoke("delete_parent_rule",{sessionToken,id});const index=previewParentRules.findIndex(value=>value.id===id);if(index>=0){previewParentRules.splice(index,1);savePreviewParentRules();}}
export async function diagnoseRuleMatch(sessionToken:string,query:string):Promise<RuleDiagnosticResult>{
  if(usesDesktopBackend())return invoke("diagnose_rule_match",{sessionToken,query});
  const normalized=query.trim().replace(/^https?:\/\//,"").split(/[/:]/)[0].toLowerCase();
  const candidates=previewParentRules.filter(rule=>rule.enabled&&previewRuleMatches(rule,normalized)).map(rule=>({id:rule.id,source:"手动规则",action:rule.action,kind:rule.kind,pattern:rule.pattern,category:rule.category,priority:rule.action==="block"?20:rule.action==="allow"?30:80,matched:true}));
  candidates.sort((a,b)=>a.priority-b.priority);
  const matched=candidates[0]??null;
  const summaryAction=matched?.action??"allow";
  const summaryLabel=matched?`最终结果：${summaryAction==="block"?"拦截":summaryAction==="proxy"?"走代理":summaryAction==="system_route"?"系统路由":"直连"}`:"最终结果：未命中，按默认策略处理";
  return{query,normalizedDomain:normalized,targetIp:undefined,summaryAction,summaryLabel,matched,candidates};
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
  {id:"chrome",name:"Chrome",engineId:"chromium",engineName:"Chromium 内核",installed:true,configured:false,needsRestart:false,details:previewBrowserPolicyDetails()},
  {id:"edge",name:"Edge",engineId:"chromium",engineName:"Chromium 内核",installed:true,configured:false,needsRestart:false,details:previewBrowserPolicyDetails()},
  {id:"brave",name:"Brave",engineId:"chromium",engineName:"Chromium 内核",installed:false,configured:false,needsRestart:false,details:previewBrowserPolicyDetails()},
  {id:"vivaldi",name:"Vivaldi",engineId:"chromium",engineName:"Chromium 内核",installed:false,configured:false,needsRestart:false,details:previewBrowserPolicyDetails()},
  {id:"chromium",name:"Chromium",engineId:"chromium",engineName:"Chromium 内核",installed:false,configured:false,needsRestart:false,details:previewBrowserPolicyDetails()},
]};
export async function getBrowserPolicyStatus():Promise<BrowserPolicyStatus>{return usesDesktopBackend()?invoke("get_browser_policy_status"):structuredClone(previewBrowserPolicyStatus);}
export async function applyBrowserPolicies(sessionToken:string):Promise<BrowserPolicyStatus>{
  if(usesDesktopBackend())return invoke("apply_browser_policies",{sessionToken});
  const applied=structuredClone(previewBrowserPolicyStatus);
  applied.browsers=applied.browsers.map(browser=>({...browser,configured:true,needsRestart:true,details:browser.details.map(detail=>{const settingKey=detail.key.replace("browser_policy.","");const enabled=defaults.browserPolicy[settingKey]??true;return {...detail,enabled,configured:true,currentValue:enabled?detail.expectedValue:null};})}));
  return applied;
}

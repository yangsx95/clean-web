import { invoke } from "@tauri-apps/api/core";

export type Settings = {
  protectionEnabled: boolean;
  proxyEnabled: boolean;
  automaticNodeSelection: boolean;
  accessLoggingEnabled: boolean;
  logRetention: string;
  categories: Record<string, boolean>;
};
export type Subscription = { id:string; kind:"rule"|"proxy"; name:string; url:string; format?:string; category?:string; updateIntervalHours?:number; enabled:boolean; lastUpdatedAt?:string; lastError?:string };
export type NewSubscription = Omit<Subscription, "id"|"enabled"|"lastUpdatedAt"|"lastError">;
export type RefreshReport = { detectedFormat:string; importedCount:number; ignoredCount:number; proxyCount:number; groupCount:number };
export type CoreStatus = { running:boolean; pid?:number; controller:string; configPath:string };
export type AccessLog={id:string;observedAt:string;domain?:string;targetIp?:string;targetPort?:number;decision:"allow"|"block"|"warning";rule?:string;category?:string;processName?:string;operatingSystem:string;systemUser:string;sourceIp?:string;route?:string;proxyGroup?:string;error?:string};
export type ParentRule={id:string;action:"allow"|"block";kind:string;pattern:string;category:string;enabled:boolean};
export type NewParentRule=Pick<ParentRule,"action"|"kind"|"pattern"|"category">;
const previewParentRules:ParentRule[]=[];
const previewSubscriptions: Subscription[] = [];

const defaults: Settings = {
  protectionEnabled: false,
  proxyEnabled: false,
  automaticNodeSelection: true,
  accessLoggingEnabled: true,
  logRetention: "30d",
  categories: { pornography: true, gambling: true, drugs: true, violence: true, self_harm: true, hate_extremism: true, fraud: true, phishing: true, malware: true, ads: true, tracking: true },
};

const isTauri = () => "__TAURI_INTERNALS__" in window;

export async function getBootstrapState() {
  return isTauri() ? invoke<{ passwordConfigured: boolean }>("get_bootstrap_state") : { passwordConfigured: true };
}

export async function initializePassword(password: string) {
  if (isTauri()) await invoke("initialize_password", { password });
}

export async function unlock(password: string) {
  if (isTauri()) return invoke<{ sessionToken: string; expiresInSeconds: number }>("unlock", { password });
  if (password.length < 8) throw new Error("管理密码错误");
  return { sessionToken: "browser-preview", expiresInSeconds: 900 };
}

export async function lock(sessionToken: string) {
  if (isTauri()) await invoke("lock", { sessionToken });
}

export async function getSettings(): Promise<Settings> {
  return isTauri() ? invoke<Settings>("get_settings") : structuredClone(defaults);
}

export async function updateSetting(sessionToken: string, key: string, value: string): Promise<Settings> {
  if (isTauri()) return invoke<Settings>("update_setting", { sessionToken, key, value });
  if (key === "protection_enabled") defaults.protectionEnabled = value === "true";
  if (key === "proxy_enabled") defaults.proxyEnabled = value === "true";
  if (key === "automatic_node_selection") defaults.automaticNodeSelection = value === "true";
  if (key === "access_logging_enabled") defaults.accessLoggingEnabled = value === "true";
  if (key.startsWith("category.")) defaults.categories[key.slice(9)] = value === "true";
  return structuredClone(defaults);
}

export async function listSubscriptions(kind?: "rule"|"proxy"): Promise<Subscription[]> {
  return isTauri() ? invoke("list_subscriptions", { kind }) : previewSubscriptions.filter((item) => !kind || item.kind === kind);
}
export async function createSubscription(sessionToken: string, input: NewSubscription): Promise<Subscription> {
  if (isTauri()) return invoke("create_subscription", { sessionToken, input });
  const item: Subscription = { ...input, id: crypto.randomUUID(), enabled: true }; previewSubscriptions.unshift(item); return item;
}
export async function setSubscriptionEnabled(sessionToken:string,id:string,enabled:boolean) {
  if (isTauri()) return invoke("set_subscription_enabled", { sessionToken,id,enabled });
  const item=previewSubscriptions.find((value)=>value.id===id); if(item)item.enabled=enabled;
}
export async function deleteSubscription(sessionToken:string,id:string) {
  if (isTauri()) return invoke("delete_subscription", { sessionToken,id });
  const index=previewSubscriptions.findIndex((value)=>value.id===id); if(index>=0)previewSubscriptions.splice(index,1);
}
export async function refreshSubscription(sessionToken:string,id:string):Promise<RefreshReport>{
  if(isTauri())return invoke("refresh_subscription",{sessionToken,id});
  return {detectedFormat:"preview",importedCount:0,ignoredCount:0,proxyCount:0,groupCount:0};
}
export async function refreshDueSubscriptions():Promise<number>{return isTauri()?invoke("refresh_due_subscriptions"):0;}
export async function getCoreStatus():Promise<CoreStatus>{return isTauri()?invoke("get_core_status"):{running:false,controller:"127.0.0.1:19090",configPath:"preview"};}
export async function startProtection(sessionToken:string):Promise<CoreStatus>{return isTauri()?invoke("start_protection",{sessionToken}):{running:true,pid:1234,controller:"127.0.0.1:19090",configPath:"preview"};}
export async function autoStartProtection():Promise<CoreStatus>{return isTauri()?invoke("auto_start_protection"):getCoreStatus();}
export async function stopProtection(sessionToken:string):Promise<CoreStatus>{return isTauri()?invoke("stop_protection",{sessionToken}):{running:false,controller:"127.0.0.1:19090",configPath:"preview"};}
export async function testProxyGroup(group="CleanWeb"):Promise<number>{const value=await invoke<{delay:number}>("test_proxy_group",{group});return value.delay;}
export async function syncAccessLogs():Promise<number>{return isTauri()?invoke("sync_access_logs"):0;}
export async function listAccessLogs(sessionToken:string,decision?:string,search?:string,limit=500):Promise<AccessLog[]>{return isTauri()?invoke("list_access_logs",{sessionToken,decision,search,limit}):[];}
export async function clearAccessLogs(sessionToken:string):Promise<number>{return isTauri()?invoke("clear_access_logs",{sessionToken}):0;}
export async function exportAccessLogsCsv(sessionToken:string):Promise<string>{return isTauri()?invoke("export_access_logs_csv",{sessionToken}):"time,domain\n";}
export async function listParentRules():Promise<ParentRule[]>{return isTauri()?invoke("list_parent_rules"):structuredClone(previewParentRules);}
export async function createParentRule(sessionToken:string,input:NewParentRule):Promise<ParentRule>{if(isTauri())return invoke("create_parent_rule",{sessionToken,input});const item={...input,id:crypto.randomUUID(),enabled:true};previewParentRules.unshift(item);return item;}
export async function setParentRuleEnabled(sessionToken:string,id:string,enabled:boolean):Promise<void>{if(isTauri())return invoke("set_parent_rule_enabled",{sessionToken,id,enabled});const item=previewParentRules.find(value=>value.id===id);if(item)item.enabled=enabled;}
export async function deleteParentRule(sessionToken:string,id:string):Promise<void>{if(isTauri())return invoke("delete_parent_rule",{sessionToken,id});const index=previewParentRules.findIndex(value=>value.id===id);if(index>=0)previewParentRules.splice(index,1);}

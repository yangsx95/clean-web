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

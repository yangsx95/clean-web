import { memo, type FormEvent, useCallback, useEffect, useRef, useState } from "react";
import jsQR from "jsqr";
import { Activity, BookOpen, ChevronDown, ChevronRight, Database, Gauge, ListFilter, LockKeyhole, MonitorCheck, Network, Pencil, Plus, RefreshCw, ScanQrCode, Settings, ShieldCheck, Trash2, Upload, X } from "lucide-react";
import * as backend from "./backend";

type ProxyImportMode = "subscription" | "node" | "file" | "qr" | "clipboard";
type AppDialog = "unlock" | "rules" | "editRuleSubscription" | "proxy" | "custom" | "quit" | null;
type AppPage = "overview" | "rules" | "logs" | "subscriptions" | "proxy" | "settings";
type AccessLogDecisionFilter = "all" | "block" | "warning";
const ACCESS_LOG_REFRESH_INTERVAL_MS = 3000;
const ACCESS_LOG_SEARCH_DEBOUNCE_MS = 400;

async function decodeQrImage(file: File): Promise<string> {
  if (!file.type.startsWith("image/")) throw new Error("请选择图片文件");
  const imageUrl = URL.createObjectURL(file);
  try {
    const image = new Image();
    image.decoding = "async";
    const loaded = new Promise<void>((resolve, reject) => {
      image.onload = () => resolve();
      image.onerror = () => reject(new Error("图片读取失败"));
    });
    image.src = imageUrl;
    await loaded;
    const canvas = document.createElement("canvas");
    canvas.width = image.naturalWidth;
    canvas.height = image.naturalHeight;
    const context = canvas.getContext("2d", { willReadFrequently: true });
    if (!context) throw new Error("无法读取图片像素");
    context.drawImage(image, 0, 0);
    const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
    const decoded = jsQR(imageData.data, imageData.width, imageData.height);
    if (!decoded?.data) throw new Error("未识别到二维码");
    return decoded.data.trim();
  } finally {
    URL.revokeObjectURL(imageUrl);
  }
}

type PolicyApplyStatus = {
  state: "applying" | "applied" | "failed";
  message: string;
  detail?: string;
};
type ErrorNotice = {
  message: string;
  detail?: string;
};

function toErrorNotice(reason: unknown, fallback = "操作失败，请稍后重试"): ErrorNotice {
  const detail = String(reason ?? "").trim();
  const lower = detail.toLowerCase();
  let message = fallback;
  if (detail.includes("已取消管理员授权")) message = detail;
  else if (detail.includes("请先解锁管理台")) message = "请先解锁管理台";
  else if (detail.includes("代理节点")) message = detail;
  else if (detail.includes("订阅")) message = detail.split("\n")[0] || fallback;
  else if (detail.includes("Mihomo 配置校验失败")) message = "保护配置校验失败，请检查规则或代理订阅格式";
  else if (detail.includes("Mihomo 热更新失败") || detail.includes("无法连接 Mihomo 热更新接口")) message = "保护正在运行，但网络策略暂时无法更新，请关闭保护后重新开启";
  else if (detail.includes("Mihomo") || lower.includes("tun") || detail.includes("Start initial configuration")) message = "保护启动失败，请检查系统授权或网络接管状态后重试";
  else if (detail.includes("浏览器策略")) message = "浏览器增强保护配置失败，请检查系统授权后重试";
  else if (detail) message = detail.split("\n")[0] || fallback;
  return { message, detail: detail && detail !== message ? detail : undefined };
}

const busyScope = {
  protection: "protection",
  createRule: "rule:create",
  createSubscription: "subscription:create",
  importProxy: "proxy:import",
  logs: "logs",
  setting: (key: string) => `setting:${key}`,
  subscription: (id: string) => `subscription:${id}`,
  rule: (id: string) => `rule:${id}`,
};
const emptyAccessLogStats: backend.AccessLogStats = { block:0, allow:0, warning:0, total:0, todayBlock:0, todayAllow:0, todayWarning:0, todayTotal:0 };

function useScopedOperations() {
  const [busyScopes, setBusyScopes] = useState<Record<string, true>>({});
  const busyRef = useRef(new Set<string>());
  const runScopedOperation = useCallback(async (scope: string, operation: () => Promise<void>) => {
    if (busyRef.current.has(scope)) return;
    busyRef.current.add(scope);
    setBusyScopes(previous => ({ ...previous, [scope]: true }));
    try { await operation(); }
    finally {
      busyRef.current.delete(scope);
      setBusyScopes(previous => {
        const next = { ...previous };
        delete next[scope];
        return next;
      });
    }
  }, []);
  const isBusy = useCallback((scope: string) => Boolean(busyScopes[scope]), [busyScopes]);
  const anyBusy = Object.keys(busyScopes).length > 0;
  return { anyBusy, isBusy, runScopedOperation };
}

function useDebouncedValue<T>(value: T, delayMs: number) {
  const [debouncedValue, setDebouncedValue] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setDebouncedValue(value), delayMs);
    return () => window.clearTimeout(timer);
  }, [value, delayMs]);
  return debouncedValue;
}

function proxyDelayLabel(d: number | undefined) {
  if (d == null) return null;
  if (d === 0) return { text: "不可达", cls: "timeout" };
  if (d < 300) return { text: `${d}ms`, cls: "fast" };
  if (d < 600) return { text: `${d}ms`, cls: "medium" };
  return { text: `${d}ms`, cls: "slow" };
}

function compactCount(value: number) {
  if (!Number.isFinite(value)) return "0";
  const abs = Math.abs(value);
  if (abs < 1000) return new Intl.NumberFormat("en-US").format(value);
  const units = [
    { threshold: 1_000_000, suffix: "m" },
    { threshold: 1_000, suffix: "k" },
  ];
  const unit = units.find(item => abs >= item.threshold);
  if (!unit) return String(value);
  const scaled = value / unit.threshold;
  const digits = Math.abs(scaled) >= 10 ? 0 : 1;
  return `${scaled.toFixed(digits).replace(/\.0$/, "")}${unit.suffix}`;
}

function formatAccessLogTime(value: string) {
  return new Date(value).toLocaleTimeString([], { hour:"2-digit", minute:"2-digit", second:"2-digit" });
}

function formatAccessLogTarget(log: backend.AccessLog) {
  const isDnsResolution = log.category === "DNS 解析" && log.targetPort === 53;
  const target = log.domain ?? log.targetIp ?? (isDnsResolution ? "DNS 解析" : "未知目标");
  return log.targetPort ? `${target}:${log.targetPort}` : target;
}

function formatAccessLogEndpoint(log: backend.AccessLog) {
  const isDnsResolution = log.category === "DNS 解析" && log.targetPort === 53;
  if (isDnsResolution) return "DNS 服务端口 :53";
  if (log.domain && log.targetIp) return log.targetPort ? `${log.targetIp}:${log.targetPort}` : log.targetIp;
  if (log.targetPort) return `端口 ${log.targetPort}`;
  if (log.targetIp) return "直接 IP";
  return "未知地址";
}

function formatAccessLogRepeat(log: backend.AccessLog) {
  return log.repeatCount && log.repeatCount > 1 ? `x${compactCount(log.repeatCount)}` : null;
}

export function App() {
  const [page, setPage] = useState<AppPage>("overview");
  const [locked, setLocked] = useState(true);
  const [dialog, setDialog] = useState<AppDialog>(null);
  const [editingSubscription, setEditingSubscription] = useState<backend.Subscription|null>(null);
  const [parentRuleMode, setParentRuleMode] = useState<"block" | "route">("block");
  const [proxyImportMode, setProxyImportMode] = useState<ProxyImportMode>("subscription");
  const [needsSetup, setNeedsSetup] = useState(false);
  const [ready, setReady] = useState(false);
  const [sessionToken, setSessionToken] = useState<string | null>(null);
  const [settings, setSettings] = useState<backend.Settings | null>(null);
  const [subscriptions, setSubscriptions] = useState<backend.Subscription[]>([]);
  const [refreshingId,setRefreshingId]=useState<string|null>(null);
  const [coreStatus,setCoreStatus]=useState<backend.CoreStatus|null>(null);
  const [runtimeError,setRuntimeError]=useState<ErrorNotice|null>(null);
  const { anyBusy, isBusy, runScopedOperation } = useScopedOperations();
  const [policyApplyStatus,setPolicyApplyStatus]=useState<PolicyApplyStatus|null>(null);
  const policyStatusTimerRef=useRef<number|null>(null);
  const [accessLogs,setAccessLogs]=useState<backend.AccessLog[]>([]);
  const [accessLogStats,setAccessLogStats]=useState<backend.AccessLogStats>(emptyAccessLogStats);
  const [accessLogDecisionFilter,setAccessLogDecisionFilter]=useState<AccessLogDecisionFilter>("all");
  const [accessLogSearch,setAccessLogSearch]=useState("");
  const debouncedAccessLogSearch=useDebouncedValue(accessLogSearch,ACCESS_LOG_SEARCH_DEBOUNCE_MS);
  const [parentRules,setParentRules]=useState<backend.ParentRule[]>([]);
  const [browserPolicyStatus,setBrowserPolicyStatus]=useState<backend.BrowserPolicyStatus|null>(null);
  const titles: Record<AppPage, string> = { overview: "网络过滤已开启", rules: "规则管理", logs: "访问日志", subscriptions: "订阅导入", proxy: "代理节点", settings: "设置" };
  const requestAction = (action: "rules" | "proxy", mode: ProxyImportMode = "subscription") => { if (action === "proxy") setProxyImportMode(mode); setDialog(locked ? "unlock" : action); };
  const hideToBackground = async () => { setDialog(null); await backend.hideMainWindow(); };
  const quitApp = async (password: string) => { await backend.confirmedQuit(password); setDialog(null); };
  const clearPolicyStatusTimer=()=>{if(policyStatusTimerRef.current!=null){window.clearTimeout(policyStatusTimerRef.current);policyStatusTimerRef.current=null;}};
  const showPolicyStatus=(status:PolicyApplyStatus)=>{clearPolicyStatusTimer();setPolicyApplyStatus(status);if(status.state==="applied"){policyStatusTimerRef.current=window.setTimeout(()=>{setPolicyApplyStatus(null);policyStatusTimerRef.current=null;},2600);}};
  useEffect(()=>()=>clearPolicyStatusTimer(),[]);
  useEffect(()=>{let cancelled=false;let unlisten:(()=>void)|undefined;let checking=false;const showQuitDialog=()=>{void backend.takePendingQuitRequest().catch(()=>false).finally(()=>{if(!cancelled)setDialog("quit");});};const showPendingQuitDialog=()=>{if(checking)return;checking=true;void backend.takePendingQuitRequest().then(pending=>{if(pending&&!cancelled)setDialog("quit");}).catch(()=>{}).finally(()=>{checking=false;});};void backend.onQuitRequested(showQuitDialog).then(stop=>{if(cancelled)stop();else unlisten=stop;});showPendingQuitDialog();const timer=window.setInterval(showPendingQuitDialog,500);window.addEventListener("focus",showPendingQuitDialog);document.addEventListener("visibilitychange",showPendingQuitDialog);return()=>{cancelled=true;window.clearInterval(timer);if(unlisten)unlisten();window.removeEventListener("focus",showPendingQuitDialog);document.removeEventListener("visibilitychange",showPendingQuitDialog);};},[]);
  useEffect(() => { void (async () => {
    const [bootstrap,current,core,publicStats,browserPolicies] = await Promise.all([backend.getBootstrapState(), backend.getSettings(),backend.getCoreStatus(),backend.getPublicAccessLogStats(),backend.getBrowserPolicyStatus()]);
    setNeedsSetup(!bootstrap.passwordConfigured); setSettings(current);setCoreStatus(core);setAccessLogStats(publicStats);setBrowserPolicyStatus(browserPolicies);
    const storedToken = backend.getStoredSessionToken();
    if (storedToken) {
      try {
        const result = await backend.validateSession(storedToken);
        const [logs,stats,saved,rules]=await Promise.all([backend.listAccessLogs(result.sessionToken,undefined,undefined,500),backend.getAccessLogStats(result.sessionToken),backend.listSubscriptions(result.sessionToken),backend.listParentRules(result.sessionToken)]);
        setSessionToken(result.sessionToken);setAccessLogs(logs);setAccessLogStats(stats);setSubscriptions(saved);setParentRules(rules);setLocked(false);
      } catch {
        backend.clearStoredSessionToken();
      }
    }
    setReady(true);
  })(); }, []);
  useEffect(()=>{const timer=window.setInterval(()=>void backend.getCoreStatus().then(setCoreStatus),5000);return()=>window.clearInterval(timer);},[]);
  useEffect(()=>{if(!sessionToken)return;const refresh=()=>{if(anyBusy)return;void backend.refreshDueSubscriptions().then(()=>reloadRuntime(sessionToken,{silent:true})).then(()=>backend.listSubscriptions(sessionToken)).then(setSubscriptions);};refresh();const timer=window.setInterval(refresh,15*60*1000);return()=>window.clearInterval(timer);},[sessionToken,anyBusy]);
  const handleUnlock = async (password: string) => { const result = await backend.unlock(password); setSessionToken(result.sessionToken);const[logs,stats,saved,rules]=await Promise.all([backend.listAccessLogs(result.sessionToken,undefined,undefined,500),backend.getAccessLogStats(result.sessionToken),backend.listSubscriptions(result.sessionToken),backend.listParentRules(result.sessionToken)]);setAccessLogs(logs);setAccessLogStats(stats);setSubscriptions(saved);setParentRules(rules); setLocked(false); setDialog(null); };
  const handleLock = async () => { if (sessionToken) await backend.lock(sessionToken); setSessionToken(null);setSubscriptions([]);setParentRules([]);setAccessLogs([]);setAccessLogStats(emptyAccessLogStats); setLocked(true); };
  const reloadRuntime=async(token:string,options:{silent?:boolean;applyingMessage?:string;idleMessage?:string}={})=>{
    if(!options.silent)showPolicyStatus({state:"applying",message:options.applyingMessage??"正在应用网络策略…"});
    try{
      const current=await backend.getCoreStatus();setCoreStatus(current);
      if(!current.running){if(!options.silent)showPolicyStatus({state:"applied",message:options.idleMessage??"设置已保存，保护启动后生效"});return current;}
      const core=await backend.reloadProtection(token);setCoreStatus(core);
      if(!options.silent)showPolicyStatus({state:"applied",message:"网络策略已生效"});
      return core;
    }catch(reason){
      const notice=toErrorNotice(reason,"网络策略应用失败，请稍后重试");
      if(!options.silent)showPolicyStatus({state:"failed",message:notice.message,detail:notice.detail});
      throw reason;
    }
  };
  const setValue = async (key: string, value: string) => {
    if (!sessionToken) { setDialog("unlock"); return; }
    setRuntimeError(null);
    await runScopedOperation(key==="protection_enabled"?busyScope.protection:busyScope.setting(key), async()=>{try {
      if(key==="protection_enabled"){showPolicyStatus({state:"applying",message:value==="true"?"正在启动保护…":"正在关闭保护…"});const core=value==="true"?await backend.startProtection(sessionToken):await backend.stopProtection(sessionToken);setCoreStatus(core);setSettings(await backend.updateSetting(sessionToken,key,value));showPolicyStatus({state:"applied",message:value==="true"?"保护已开启":"保护已关闭"});}
      else {showPolicyStatus({state:"applying",message:"正在保存并应用设置…"});setSettings(await backend.updateSetting(sessionToken,key,value));await reloadRuntime(sessionToken,{applyingMessage:"正在应用设置到运行内核…"});}
    } catch(reason) { const notice=toErrorNotice(reason,value==="true"?"保护启动失败，请稍后重试":"操作失败，请稍后重试");showPolicyStatus({state:"failed",message:notice.message,detail:notice.detail});setRuntimeError(notice); }});
  };
  const toggle = (key: string, enabled: boolean) => setValue(key, String(enabled));
  const createSubscription = async (input: backend.NewSubscription) => {
    if (!sessionToken) throw new Error("请先解锁管理台");
    await runScopedOperation(busyScope.createSubscription, async()=>{showPolicyStatus({state:"applying",message:"正在导入并应用订阅…"});const item=await backend.createSubscription(sessionToken, input);
    try { await backend.refreshSubscription(sessionToken,item.id); } catch(reason) { await backend.deleteSubscription(sessionToken,item.id); throw reason; }
    setSubscriptions(await backend.listSubscriptions(sessionToken));await reloadRuntime(sessionToken); setDialog(null);});
  };
  const updateSubscription=async(id:string,input:backend.UpdateSubscription)=>{if(!sessionToken)throw new Error("请先解锁管理台");await runScopedOperation(busyScope.subscription(id),async()=>{setRuntimeError(null);showPolicyStatus({state:"applying",message:"正在保存并更新订阅…"});await backend.updateSubscription(sessionToken,id,input);let refreshFailed:unknown;try{await backend.refreshSubscription(sessionToken,id);}catch(reason){refreshFailed=reason;}setSubscriptions(await backend.listSubscriptions(sessionToken));try{await reloadRuntime(sessionToken,{applyingMessage:"正在应用订阅修改…"});}catch(reason){const notice=toErrorNotice(reason,"订阅已修改，但保护配置重载失败");setRuntimeError({message:"订阅已修改，但保护配置重载失败",detail:notice.detail??notice.message});}setDialog(null);setEditingSubscription(null);if(refreshFailed){const notice=toErrorNotice(refreshFailed,"订阅已修改，但刷新失败，继续使用最后一次有效规则");setRuntimeError({message:"订阅已修改，但刷新失败，继续使用最后一次有效规则",detail:notice.detail??notice.message});}});};
  const importProxyPayload=async(input:backend.ManualProxyImport)=>{if(!sessionToken)throw new Error("请先解锁管理台");await runScopedOperation(busyScope.importProxy, async()=>{showPolicyStatus({state:"applying",message:"正在导入并应用代理配置…"});await backend.importProxyPayload(sessionToken,input);setSubscriptions(await backend.listSubscriptions(sessionToken));await reloadRuntime(sessionToken);setDialog(null);});};
  const toggleSubscription = async (id: string, enabled: boolean) => { if (!sessionToken) { setDialog("unlock"); return; } await runScopedOperation(busyScope.subscription(id), async()=>{showPolicyStatus({state:"applying",message:"正在更新订阅状态…"});await backend.setSubscriptionEnabled(sessionToken,id,enabled); setSubscriptions(await backend.listSubscriptions(sessionToken));await reloadRuntime(sessionToken);}); };
  const removeSubscription = async (id: string) => {
    if (!sessionToken) { setDialog("unlock"); return; }
    setRuntimeError(null);
    try {
      await runScopedOperation(busyScope.subscription(id), async()=>{showPolicyStatus({state:"applying",message:"正在删除订阅并应用配置…"});await backend.deleteSubscription(sessionToken,id);
      setSubscriptions(await backend.listSubscriptions(sessionToken));
      try { await reloadRuntime(sessionToken); }
      catch (reason) { const notice=toErrorNotice(reason,"订阅已删除，但保护配置重载失败");setRuntimeError({message:"订阅已删除，但保护配置重载失败",detail:notice.detail??notice.message}); }});
    } catch (reason) {
      const notice=toErrorNotice(reason,"删除订阅失败，请稍后重试");
      setRuntimeError({message:"删除订阅失败",detail:notice.detail??notice.message});
    }
  };
  const refreshSubscription=async(id:string)=>{if(!sessionToken){setDialog("unlock");return;}await runScopedOperation(busyScope.subscription(id), async()=>{setRefreshingId(id);showPolicyStatus({state:"applying",message:"正在更新订阅并应用配置…"});try{await backend.refreshSubscription(sessionToken,id);setSubscriptions(await backend.listSubscriptions(sessionToken));await reloadRuntime(sessionToken);}finally{setRefreshingId(null);}});};
  const clearLogs=async()=>{if(!sessionToken){setDialog("unlock");return;}await runScopedOperation(busyScope.logs, async()=>{await backend.clearAccessLogs(sessionToken);setAccessLogs([]);setAccessLogStats(emptyAccessLogStats);});};
  const exportLogs=async()=>{if(!sessionToken){setDialog("unlock");return;}await runScopedOperation(busyScope.logs, async()=>{await backend.saveAccessLogsCsv(sessionToken);});};
  const createParentRule=async(input:backend.NewParentRule)=>{if(!sessionToken)throw new Error("请先解锁管理台");await runScopedOperation(busyScope.createRule, async()=>{setRuntimeError(null);showPolicyStatus({state:"applying",message:"正在保存并应用规则…"});await backend.createParentRule(sessionToken,input);setParentRules(await backend.listParentRules(sessionToken));setDialog(null);try{await reloadRuntime(sessionToken);}catch(reason){const notice=toErrorNotice(reason,"规则已添加，但保护配置重载失败");setRuntimeError({message:"规则已添加，但保护配置重载失败",detail:notice.detail??notice.message});}});};
  const toggleParentRule=async(id:string,enabled:boolean)=>{if(!sessionToken){setDialog("unlock");return;}await runScopedOperation(busyScope.rule(id), async()=>{showPolicyStatus({state:"applying",message:"正在更新规则状态…"});await backend.setParentRuleEnabled(sessionToken,id,enabled);setParentRules(await backend.listParentRules(sessionToken));await reloadRuntime(sessionToken);});};
  const deleteParentRule=async(id:string)=>{if(!sessionToken){setDialog("unlock");return;}await runScopedOperation(busyScope.rule(id), async()=>{showPolicyStatus({state:"applying",message:"正在删除规则并应用配置…"});await backend.deleteParentRule(sessionToken,id);setParentRules(await backend.listParentRules(sessionToken));await reloadRuntime(sessionToken);});};
  const selectProxyNode=async(name:string)=>{if(!sessionToken){setDialog("unlock");return;}setRuntimeError(null);try{showPolicyStatus({state:"applying",message:"正在切换代理节点…"});const result=await backend.selectProxy(sessionToken,"CleanWeb",name);if(result?.requiresReload)await reloadRuntime(sessionToken,{applyingMessage:"正在应用代理节点…"});else showPolicyStatus({state:"applied",message:"代理节点已切换"});setSettings(await backend.getSettings());}catch(reason){const notice=toErrorNotice(reason,"代理节点切换失败，请稍后重试");showPolicyStatus({state:"failed",message:notice.message,detail:notice.detail});setRuntimeError(notice);throw reason;}};
  const applyBrowserPolicies=async()=>{if(!sessionToken){setDialog("unlock");return;}await runScopedOperation(busyScope.setting("browser_policies"),async()=>{showPolicyStatus({state:"applying",message:"正在配置浏览器增强保护…"});try{const status=await backend.applyBrowserPolicies(sessionToken);setBrowserPolicyStatus(status);showPolicyStatus({state:"applied",message:"浏览器策略已写入，重启浏览器后完全生效"});}catch(reason){const notice=toErrorNotice(reason,"浏览器增强保护配置失败，请检查系统授权后重试");showPolicyStatus({state:"failed",message:notice.message,detail:notice.detail});setRuntimeError(notice);}});};
  useEffect(()=>{
    if(!sessionToken)return;
    let cancelled=false;
    let refreshing=false;
    let unlisten:(()=>void)|undefined;
    const decision = page === "logs" && accessLogDecisionFilter !== "all" ? accessLogDecisionFilter : undefined;
    const search = page === "logs" ? debouncedAccessLogSearch.trim() || undefined : undefined;
    const refresh=()=>{
      if(refreshing)return;
      refreshing=true;
      void backend.syncAccessLogs().catch(()=>0)
        .then(()=>Promise.all([backend.listAccessLogs(sessionToken,decision,search,500),backend.getAccessLogStats(sessionToken)]))
        .then(([logs,stats])=>{if(!cancelled){setAccessLogs(logs);setAccessLogStats(stats);}})
        .catch(()=>undefined)
        .finally(()=>{refreshing=false;});
    };
    refresh();
    const interval=window.setInterval(refresh,ACCESS_LOG_REFRESH_INTERVAL_MS);
    void backend.onAccessLogsUpdated(refresh).then(stop=>{if(cancelled)stop();else unlisten=stop;});
    return()=>{cancelled=true;window.clearInterval(interval);if(unlisten)unlisten();};
  },[sessionToken,page,accessLogDecisionFilter,debouncedAccessLogSearch]);
  useEffect(()=>{
    if(sessionToken)return;
    let cancelled=false;
    let refreshing=false;
    let unlisten:(()=>void)|undefined;
    const refresh=()=>{
      if(refreshing)return;
      refreshing=true;
      void backend.getPublicAccessLogStats()
        .then(stats=>{if(!cancelled)setAccessLogStats(stats);})
        .catch(()=>undefined)
        .finally(()=>{refreshing=false;});
    };
    refresh();
    const interval=window.setInterval(refresh,ACCESS_LOG_REFRESH_INTERVAL_MS);
    void backend.onAccessLogsUpdated(refresh).then(stop=>{if(cancelled)stop();else unlisten=stop;});
    return()=>{cancelled=true;window.clearInterval(interval);if(unlisten)unlisten();};
  },[sessionToken]);
  if (!ready || !settings) return <div className="loading">正在读取 CleanWeb 配置…</div>;
  if (locked) return <LockedStatus coreStatus={coreStatus} stats={accessLogStats} runtimeError={runtimeError} needsSetup={needsSetup} onSetupComplete={() => setNeedsSetup(false)} onUnlock={handleUnlock} dialog={dialog} setDialog={setDialog} onHideToBackground={hideToBackground} onQuitApp={quitApp} />;
  return <div className="shell">
    <aside>
      <div className="brand"><ShieldCheck size={25}/><strong>CleanWeb</strong></div>
      <nav>
        <button className={page === "overview" ? "active" : ""} onClick={() => setPage("overview")}><Activity/>概览</button>
        <button className={page === "rules" ? "active" : ""} onClick={() => setPage("rules")}><BookOpen/>规则管理</button>
        <button className={page === "logs" ? "active" : ""} onClick={() => setPage("logs")}><ListFilter/>访问日志</button>
        <button className={page === "subscriptions" ? "active" : ""} onClick={() => setPage("subscriptions")}><Database/>订阅导入</button>
        <button className={page === "proxy" ? "active" : ""} onClick={() => setPage("proxy")}><Network/>代理节点</button>
        <button className={page === "settings" ? "active" : ""} onClick={() => setPage("settings")}><Settings/>设置</button>
      </nav>
      <div className={locked ? "locked" : "locked unlocked"} onClick={() => locked ? setDialog("unlock") : void handleLock()} role="button" aria-label={locked ? "点击解锁" : "点击锁定"} tabIndex={0} onKeyDown={(e)=>{if(e.key==="Enter"||e.key===" ")locked?setDialog("unlock"):void handleLock();}}><LockKeyhole size={18}/><div><b>{locked ? "管理台已锁定" : "管理台已解锁"}</b><span>{locked ? "点击解锁" : "点击锁定"}</span></div></div>
      <div className="sidebar-version">CleanWeb v0.1.0</div>
    </aside>
    <main>
      <header><div><span className="eyebrow">{page === "overview" ? "网络保护" : page === "logs" ? "本地隐私日志" : page === "subscriptions" ? "规则供应链" : page === "proxy" ? "受控代理层" : page === "settings" ? "管理员设置" : "策略规则模型"}</span><h1>{page === "overview" && coreStatus?.running !== true ? settings.protectionEnabled ? "保护需要恢复" : "保护未接管" : titles[page]}</h1></div></header>
      {runtimeError&&<ErrorNoticeView notice={runtimeError}/>}
      {policyApplyStatus&&<PolicyApplyBanner status={policyApplyStatus}/>}
      {page === "overview" && <Overview settings={settings} coreStatus={coreStatus} isBusy={isBusy} logs={accessLogs} logStats={accessLogStats} onToggle={toggle} onOpenLogs={() => setPage("logs")} onAddRule={() => { setParentRuleMode("block"); setDialog("custom"); }} />}
      {page === "rules" && <Rules parentRules={parentRules} subscriptions={subscriptions.filter((item)=>item.kind==="rule")} refreshingId={refreshingId} isBusy={isBusy} onRefresh={refreshSubscription} onToggleParentRule={toggleParentRule} onDeleteParentRule={deleteParentRule} onAddParentRule={(mode)=>{setParentRuleMode(mode);locked?setDialog("unlock"):setDialog("custom");}} onToggleSubscription={toggleSubscription} onDelete={removeSubscription} onEdit={(item)=>{setEditingSubscription(item);setDialog("editRuleSubscription");}} onAdd={() => requestAction("rules")} />}
      {page === "logs" && <LogsPage locked={locked} logs={accessLogs} logStats={accessLogStats} decisionFilter={accessLogDecisionFilter} search={accessLogSearch} isBusy={isBusy} settings={settings} onDecisionFilterChange={setAccessLogDecisionFilter} onSearchChange={setAccessLogSearch} onClear={clearLogs} onExport={exportLogs} onToggle={toggle} onRetention={(value) => setValue("log_retention", value)} />}
      {page === "subscriptions" && <SubscriptionsPage subscriptions={subscriptions} refreshingId={refreshingId} isBusy={isBusy} onRefresh={refreshSubscription} onToggle={toggleSubscription} onDelete={removeSubscription} onEdit={(item)=>{if(item.kind==="rule"){setEditingSubscription(item);setDialog("editRuleSubscription");}}} onAddRule={() => requestAction("rules")} onAddProxy={(mode) => requestAction("proxy", mode)} />}
      {page === "proxy" && <Proxy subscriptions={subscriptions.filter((item)=>item.kind==="proxy")} refreshingId={refreshingId} isBusy={isBusy} onRefresh={refreshSubscription} onToggleSubscription={toggleSubscription} onDelete={removeSubscription} onAdd={(mode) => requestAction("proxy", mode)} coreStatus={coreStatus} automatic={settings.automaticNodeSelection} onAutomatic={()=>setValue("automatic_node_selection","true")} onSelectNode={selectProxyNode} sessionToken={sessionToken} />}
      {page === "settings" && <SettingsPage settings={settings} isBusy={isBusy} browserPolicyStatus={browserPolicyStatus} onToggle={toggle} onRetention={(value) => setValue("log_retention", value)} onApplyBrowserPolicies={applyBrowserPolicies} />}
    </main>
    {needsSetup && <SetupDialog onComplete={() => setNeedsSetup(false)} />}
    {dialog === "unlock" && <UnlockDialog onClose={() => setDialog(null)} onUnlock={handleUnlock} />}
    {dialog === "rules" && <SubscriptionDialog kind="规则" onClose={() => setDialog(null)} onSubmit={createSubscription} />}
    {dialog === "editRuleSubscription" && editingSubscription && <SubscriptionDialog kind="规则" subscription={editingSubscription} onClose={() => {setDialog(null);setEditingSubscription(null);}} onSubmit={(input)=>updateSubscription(editingSubscription.id,input)} />}
    {dialog === "proxy" && <ProxyImportDialog mode={proxyImportMode} onClose={() => setDialog(null)} onSubscriptionSubmit={createSubscription} onPayloadSubmit={importProxyPayload} />}
    {dialog === "custom" && <ParentRuleDialog mode={parentRuleMode} onClose={()=>setDialog(null)} onSubmit={createParentRule}/>}
    {dialog === "quit" && <QuitConfirmDialog running={coreStatus?.running===true} onClose={()=>setDialog(null)} onHideToBackground={hideToBackground} onQuitApp={quitApp}/>}
  </div>;
}

function PolicyApplyBanner({status}:{status:PolicyApplyStatus}) {
  const label = status.state === "applying" ? "应用中" : status.state === "applied" ? "已生效" : "应用失败";
  return <div className={`policy-apply-banner ${status.state}`} role={status.state === "failed" ? "alert" : "status"} aria-live="polite">
    <span className="policy-apply-dot" />
    <b>{label}</b>
    <span>{status.message}</span>
    {status.detail&&<details><summary>技术详情</summary><pre>{status.detail}</pre></details>}
  </div>;
}

function ErrorNoticeView({notice,compact=false}:{notice:ErrorNotice;compact?:boolean}) {
  return <div className={`runtime-error${compact?" compact":""}`} role="alert">
    <span>{notice.message}</span>
    {notice.detail&&<details><summary>技术详情</summary><pre>{notice.detail}</pre></details>}
  </div>;
}

function LockedStatus({ coreStatus, stats, runtimeError, needsSetup, onSetupComplete, onUnlock, dialog, setDialog, onHideToBackground, onQuitApp }: { coreStatus:backend.CoreStatus|null;stats:backend.AccessLogStats;runtimeError:ErrorNotice|null;needsSetup:boolean;onSetupComplete:()=>void;onUnlock:(password:string)=>Promise<void>;dialog:AppDialog;setDialog:(dialog:AppDialog)=>void;onHideToBackground:()=>Promise<void>;onQuitApp:(password:string)=>Promise<void> }) {
  const running = coreStatus?.running === true;
  return <div className="locked-shell">
    <section className="locked-status-card" aria-label="CleanWeb 锁定状态">
      <div className="locked-status-head">
        <div className={running ? "locked-status-icon" : "locked-status-icon off"}><ShieldCheck size={26}/></div>
        <div><span className={running ? "status" : "status off"}>{running ? "保护运行中" : "保护未运行"}</span><h1>CleanWeb</h1></div>
      </div>
      {runtimeError && <ErrorNoticeView notice={runtimeError} compact/>}
      <div className="locked-status-stats">
        <article><span>已拦截</span><strong>{compactCount(stats.block)}</strong></article>
        <article><span>已允许</span><strong>{compactCount(stats.allow)}</strong></article>
        <article><span>总请求</span><strong>{compactCount(stats.total)}</strong></article>
      </div>
      <button className="primary full" onClick={()=>setDialog("unlock")}><LockKeyhole size={16}/>点击解锁</button>
    </section>
    <div className="locked-version">CleanWeb v0.1.0</div>
    {needsSetup && <SetupDialog onComplete={onSetupComplete} />}
    {dialog === "unlock" && <UnlockDialog onClose={() => setDialog(null)} onUnlock={onUnlock} />}
    {dialog === "quit" && <QuitConfirmDialog running={running} onClose={()=>setDialog(null)} onHideToBackground={onHideToBackground} onQuitApp={onQuitApp}/>}
  </div>;
}

function QuitConfirmDialog({ running, onClose, onHideToBackground, onQuitApp }: { running:boolean; onClose:()=>void; onHideToBackground:()=>Promise<void>; onQuitApp:(password:string)=>Promise<void> }) {
  const [error,setError]=useState("");
  const [submitting,setSubmitting]=useState(false);
  const submitQuit=async(event:FormEvent<HTMLFormElement>)=>{
    event.preventDefault();
    if(submitting)return;
    setSubmitting(true);
    setError("");
    try{
      const password=String(new FormData(event.currentTarget).get("password")??"");
      await onQuitApp(password);
    }catch(reason){
      setError(String(reason));
    }finally{
      setSubmitting(false);
    }
  };
  return <div className="modal-backdrop" onMouseDown={(event)=>event.target===event.currentTarget&&onClose()}>
    <section className="modal quit-modal" role="dialog" aria-modal="true" aria-labelledby="quit-title">
      <button className="icon-button" aria-label="关闭" onClick={onClose}><X size={18}/></button>
      <div className={running?"modal-symbol":"modal-symbol warning"}><ShieldCheck/></div>
      <h2 id="quit-title">{running?"退出前将关闭保护":"确认关闭 CleanWeb"}</h2>
      <p>{running?"退出 CleanWeb 会先关闭保护内核，并恢复系统 DNS 与路由设置。":"当前没有运行中的保护服务。你可以关闭窗口到后台，或退出 CleanWeb 管理界面。"}</p>
      {running&&<div className="quit-status" role="status"><b>保护运行中</b><span>输入管理密码后将先停止保护，再退出应用。</span></div>}
      <form onSubmit={submitQuit}>
        <label htmlFor="quit-password">管理密码</label>
        <input id="quit-password" name="password" type="password" placeholder="输入管理密码后退出" required autoFocus autoComplete="current-password" onKeyDown={(e) => { if (e.nativeEvent.isComposing || e.keyCode === 229) e.preventDefault(); }} onCompositionEnd={(e) => { const el = e.currentTarget; el.value = el.value.replace(/[^\x20-\x7E]/g, ""); }} onInput={(e) => { const el = e.currentTarget; el.value = el.value.replace(/[^\x20-\x7E]/g, ""); }} />
        {error&&<span className="form-error">{error}</span>}
        <div className="modal-actions">
          <button type="button" className="secondary" onClick={onClose}>取消</button>
          <button type="button" className="secondary" onClick={()=>void onHideToBackground()}>继续后台运行</button>
          <button type="submit" className="primary danger" disabled={submitting}>{submitting?"正在退出…":"退出"}</button>
        </div>
      </form>
    </section>
  </div>;
}

function Overview({ settings, coreStatus, isBusy, logs, logStats, onToggle, onOpenLogs, onAddRule }: { settings: backend.Settings; coreStatus:backend.CoreStatus|null;isBusy:(scope:string)=>boolean;logs:backend.AccessLog[];logStats:backend.AccessLogStats; onToggle: (key: string, enabled: boolean) => Promise<void>; onOpenLogs:()=>void; onAddRule:()=>void }) {
  const running=coreStatus?.running===true;
  const recentLogs = logs.slice(0,5);
  const enabledControls = [
    true,
    settings.strictModeEnabled,
    settings.proxyEnabled,
    settings.categories.entertainment,
  ].filter(Boolean).length;
  const protectionLabel = running ? "保护运行中" : "保护未运行";
  const protectionMessage = running
    ? `保护服务 PID ${coreStatus?.pid ?? "-"} · 安全 DNS 已配置`
    : settings.protectionEnabled
      ? "配置要求保护开启，但服务当前未运行；点击开关重新启动保护"
      : "当前网络未被 CleanWeb 接管";
  return <>
      <section className="cw-overview-actions">
        <p>CleanWeb 正在为这台设备执行本地拦截、订阅规则和受控代理策略。</p>
        <div><button className="secondary" onClick={onOpenLogs}>查看日志</button><button className="primary" onClick={onAddRule}><Plus size={16}/>添加规则</button></div>
      </section>
      <section className="cw-stat-row">
        <article className="cw-status-panel">
          <div><span>保护状态</span><b>{protectionLabel}</b></div>
          <h2>{running ? "所有策略已生效" : "保护尚未接管网络"}</h2>
          <p>{protectionMessage}</p>
          <Switch checked={running} label="总保护" disabled={isBusy(busyScope.protection)} onChange={(value) => onToggle("protection_enabled", value)} />
        </article>
        <article><span>今日拦截</span><strong>{compactCount(logStats.todayBlock)}</strong><small>累计 {compactCount(logStats.block)} 次</small></article>
        <article><span>今日放行</span><strong>{compactCount(logStats.todayAllow)}</strong><small>累计 {compactCount(logStats.allow)} 次</small></article>
        <article><span>今日请求</span><strong>{compactCount(logStats.todayTotal)}</strong><small>累计 {compactCount(logStats.total)} 条</small></article>
      </section>
      <section className="cw-dashboard-grid">
        <article className="cw-panel">
          <div className="cw-panel-head"><h3>策略开关</h3><span>{enabledControls} 项启用</span></div>
          <SettingLine title="本地拦截规则" active />
          <SettingLine title="严格模式" active={settings.strictModeEnabled}><Switch checked={settings.strictModeEnabled} label="严格模式" disabled={isBusy(busyScope.setting("strict_mode_enabled"))} onChange={(value) => onToggle("strict_mode_enabled", value)} /></SettingLine>
          <SettingLine title="短视频与游戏" active={Boolean(settings.categories.entertainment)}><Switch checked={Boolean(settings.categories.entertainment)} label="短视频与游戏" disabled={isBusy(busyScope.setting("category.entertainment"))} onChange={(value) => onToggle("category.entertainment", value)} /></SettingLine>
          <SettingLine title="代理订阅路由" active={settings.proxyEnabled}><Switch checked={settings.proxyEnabled} label="代理" disabled={isBusy(busyScope.setting("proxy_enabled"))} onChange={(value) => onToggle("proxy_enabled", value)} /></SettingLine>
        </article>
        <article className="cw-panel">
          <div className="cw-panel-head"><h3>最近访问日志</h3><span>Live</span></div>
          <MiniLogList logs={recentLogs} />
        </article>
      </section>
  </>;
}

function SettingLine({ title, active, children }: { title:string; active:boolean; children?:React.ReactNode }) {
  return <div className="setting-line"><span className={active ? "dot on" : "dot warn"} /><b>{title}</b>{children ?? <span className="fixed-state">{active ? "开启" : "关闭"}</span>}</div>;
}

function MiniLogList({ logs }: { logs: backend.AccessLog[] }) {
  if (logs.length === 0) {
    const samples = [
      { id:"sample-1", time:"10:42:18", target:"games.example.net:443", meta:"短视频", decision:"拦截", kind:"block" },
      { id:"sample-2", time:"10:39:04", target:"school.portal.edu:443", meta:"家长白名单", decision:"放行", kind:"allow" },
      { id:"sample-3", time:"10:31:55", target:"198.51.100.12:8443", meta:"未知 IP", decision:"警告", kind:"warning" },
      { id:"sample-4", time:"10:26:37", target:"search.clean:53", meta:"安全搜索", decision:"放行", kind:"allow" },
      { id:"sample-5", time:"10:22:09", target:"updates.example.org:443", meta:"默认策略", decision:"放行", kind:"allow" },
    ];
    return <div className="mini-log-list">{samples.map((row,index)=><div className={`mini-log-row ${index===0?"is-new":""}`} key={row.id}><span className={`dot ${row.kind}`} /><time>{row.time}</time><b title={row.target}>{row.target}</b><small title={row.meta}>{row.meta}</small><span className={`decision ${row.kind}`}>{row.decision}</span></div>)}</div>;
  }
  return <div className="mini-log-list">{logs.slice(0,8).map((log,index)=>{
    const target = formatAccessLogTarget(log);
    const meta = [log.category ?? log.rule ?? "默认策略", log.route].filter(Boolean).join(" / ");
    const repeat = formatAccessLogRepeat(log);
    return <div className={`mini-log-row ${index<3?"is-new":""}`} key={log.id}><span className={`dot ${log.decision}`} /><time>{formatAccessLogTime(log.observedAt)}</time><b title={target}>{target}{repeat&&<span className="log-repeat">{repeat}</span>}</b><small title={meta}>{meta}</small><span className={`decision ${log.decision}`}>{log.decision==="block"?"拦截":log.decision==="warning"?"警告":"放行"}</span></div>;
  })}</div>;
}

function LogsPage({ locked, logs, logStats, decisionFilter, search, isBusy, settings, onDecisionFilterChange, onSearchChange, onClear, onExport, onToggle, onRetention }: { locked:boolean; logs:backend.AccessLog[]; logStats:backend.AccessLogStats; decisionFilter:AccessLogDecisionFilter; search:string; isBusy:(scope:string)=>boolean; settings:backend.Settings; onDecisionFilterChange:(value:AccessLogDecisionFilter)=>void; onSearchChange:(value:string)=>void; onClear:()=>Promise<void>; onExport:()=>Promise<void>; onToggle:(key:string,enabled:boolean)=>Promise<void>; onRetention:(value:string)=>Promise<void> }) {
  return <>
    <section className="cw-page-intro"><p>查看仅保存在本机的最终网络决策。日志支持筛选、导出 CSV、清空和按策略保留。</p><div><button className="secondary" disabled={isBusy(busyScope.logs)} onClick={()=>void onExport()}>导出 CSV</button><button className="primary danger" disabled={isBusy(busyScope.logs)} onClick={()=>void onClear()}>清空日志</button></div></section>
    <section className="cw-logs-layout">
      <div className="cw-log-side">
        <article className="cw-dark-card"><h3>今日处理</h3><strong>{compactCount(logStats.todayTotal)}</strong><span>条最终决策已记录</span><div><b>{compactCount(logStats.todayBlock)}</b> 拦截 · <b>{compactCount(logStats.todayAllow)}</b> 放行 · <b>{compactCount(logStats.todayWarning)}</b> 警告</div><span>累计 {compactCount(logStats.total)} 条 · {compactCount(logStats.block)} 次拦截</span></article>
        <article className="cw-panel privacy-panel"><h3>隐私控制</h3><div className="setting-line"><b>访问日志</b><Switch checked={settings.accessLoggingEnabled} label="访问日志" disabled={isBusy(busyScope.setting("access_logging_enabled"))} onChange={(value)=>onToggle("access_logging_enabled",value)}/></div><select aria-label="日志保留时间" value={settings.logRetention} disabled={isBusy(busyScope.setting("log_retention"))} onChange={(event)=>void onRetention(event.target.value)}><option value="7d">保留期：7 天</option><option value="30d">保留期：30 天</option><option value="90d">保留期：90 天</option><option value="forever">保留期：永久</option></select><p>诊断包导出是独立功能，默认会清除域名、IP、用户名、订阅地址、节点名称和凭据。</p></article>
      </div>
      <article className="cw-log-table">
        <div className="cw-panel-head"><h3>最终决策</h3><div className="filter-pills" role="group" aria-label="日志筛选"><button className={decisionFilter==="all"?"active":""} onClick={()=>onDecisionFilterChange("all")}>全部</button><button className={decisionFilter==="block"?"active":""} onClick={()=>onDecisionFilterChange("block")}>已拦截</button><button className={decisionFilter==="warning"?"active":""} onClick={()=>onDecisionFilterChange("warning")}>未知 IP</button></div></div>
        <input className="log-search" aria-label="搜索访问日志" value={search} onChange={event=>onSearchChange(event.target.value)} placeholder="搜索域名、IP、规则、分类、路由" />
        <div className="cw-log-list">
          {locked ? <div className="empty">解锁管理台后查看访问详情</div> : logs.length === 0 ? (search.trim() || decisionFilter !== "all" ? <div className="empty">没有匹配的访问记录</div> : <SampleLogs />) : logs.map(log=><AccessLogRow log={log} key={log.id}/>)}
        </div>
      </article>
    </section>
  </>;
}

function SampleLogs() {
  const samples: Array<Partial<backend.AccessLog> & { id:string; observedAt:string; decision:backend.AccessLog["decision"]; operatingSystem:string; systemUser:string }> = [
    { id:"sample-1", observedAt:new Date().toISOString(), domain:"games.example.net", targetIp:"104.21.12.4", targetPort:443, decision:"block", category:"短视频", processName:"Safari", route:"直连", operatingSystem:"preview", systemUser:"local" },
    { id:"sample-2", observedAt:new Date().toISOString(), domain:"school.portal.edu", targetIp:"34.117.88.9", targetPort:443, decision:"allow", category:"家长白名单", processName:"Chrome", route:"代理", operatingSystem:"preview", systemUser:"local" },
    { id:"sample-3", observedAt:new Date().toISOString(), targetIp:"198.51.100.12", targetPort:8443, decision:"warning", category:"未知 IP", processName:"helperd", route:"直连", operatingSystem:"preview", systemUser:"local" },
  ];
  return <>{samples.map(log=><AccessLogRow log={log as backend.AccessLog} key={log.id}/>)}</>;
}

function AccessLogRow({ log }: { log:backend.AccessLog }) {
  const target = formatAccessLogTarget(log);
  const endpoint = formatAccessLogEndpoint(log);
  const rule = log.category ?? log.rule ?? "默认策略";
  const source = `${log.processName?.trim() || "设备流量"} / ${log.route ?? "直连"}`;
  const repeat = formatAccessLogRepeat(log);
  return <div className="cw-access-row">
    <time>{formatAccessLogTime(log.observedAt)}</time>
    <div className="access-target"><b>{target}{repeat&&<span className="log-repeat">{repeat}</span>}</b><span>{endpoint}</span></div>
    <span className={`decision ${log.decision}`}>{log.decision==="block"?"拦截":log.decision==="warning"?"警告":"放行"}</span>
    <div className="access-meta"><small>{rule}</small><small>{source}</small></div>
  </div>;
}

function SubscriptionsPage({ subscriptions, refreshingId, isBusy, onRefresh, onToggle, onDelete, onEdit, onAddRule, onAddProxy }: { subscriptions:backend.Subscription[]; refreshingId:string|null; isBusy:(scope:string)=>boolean; onRefresh:(id:string)=>Promise<void>; onToggle:(id:string,enabled:boolean)=>Promise<void>; onDelete:(id:string)=>Promise<void>; onEdit:(subscription:backend.Subscription)=>void; onAddRule:()=>void; onAddProxy:(mode:ProxyImportMode)=>void }) {
  const ruleSubs = subscriptions.filter(item=>item.kind==="rule");
  const proxySubs = subscriptions.filter(item=>item.kind==="proxy");
  return <>
    <section className="cw-page-intro"><p>安全导入规则和代理来源。CleanWeb 会验证格式、大小、分类和编译结果，再原子替换最后一次有效版本。</p><div><button className="secondary" onClick={onAddRule}>添加规则源</button><button className="primary" onClick={()=>onAddProxy("subscription")}>添加代理源</button></div></section>
    <section className="cw-sub-layout">
      <div className="cw-sub-main">
        <article className="cw-panel"><div className="cw-panel-head"><h3>启用中的规则来源</h3><span>失败保留旧版</span></div><SubscriptionRows items={ruleSubs} refreshingId={refreshingId} isBusy={isBusy} onRefresh={onRefresh} onToggle={onToggle} onDelete={onDelete} onEdit={onEdit}/></article>
      </div>
      <div className="cw-sub-side">
        <article className="cw-dark-card compact-boundary"><h3>代理订阅边界</h3><p>只保留节点和代理组；DNS、TUN、脚本、控制器、本地端口和绕过规则都会被丢弃。</p></article>
        <article className="cw-panel"><div className="cw-panel-head"><h3>代理来源</h3><span>{proxySubs.length}</span></div><SubscriptionRows items={proxySubs} refreshingId={refreshingId} isBusy={isBusy} onRefresh={onRefresh} onToggle={onToggle} onDelete={onDelete} onEdit={onEdit}/><div className="import-actions"><button className="secondary" onClick={()=>onAddProxy("file")}>配置文件</button><button className="secondary" onClick={()=>onAddProxy("qr")}>二维码</button><button className="secondary" onClick={()=>onAddProxy("clipboard")}>剪贴板</button></div></article>
      </div>
    </section>
  </>;
}

function SubscriptionRows({ items, refreshingId, isBusy, onRefresh, onToggle, onDelete, onEdit }: { items:backend.Subscription[]; refreshingId:string|null; isBusy:(scope:string)=>boolean; onRefresh:(id:string)=>Promise<void>; onToggle:(id:string,enabled:boolean)=>Promise<void>; onDelete:(id:string)=>Promise<void>; onEdit:(subscription:backend.Subscription)=>void }) {
  if (items.length === 0) return <div className="table-empty">尚未添加来源</div>;
  return <div className="subscription-rows">{items.map(item=>{const rowBusy=isBusy(busyScope.subscription(item.id));return <div className="subscription-row" key={item.id}><div className="subscription-main"><b>{item.name}</b><small className={item.lastError?"error-text":""}>{item.lastError??`${item.format??"自动检测"} · ${item.updateIntervalHours??24}小时更新`}</small></div><span className="subscription-category">{item.category??(item.kind==="proxy"?"代理":"自定义")}</span><Switch checked={item.enabled} label={`${item.name}订阅`} disabled={rowBusy} onChange={(value)=>onToggle(item.id,value)}/><div className="row-actions"><button className="row-action" disabled={rowBusy||refreshingId===item.id} onClick={()=>void onRefresh(item.id)}><RefreshCw size={15}/></button>{item.kind==="rule"&&<button className="row-action" disabled={rowBusy} onClick={()=>onEdit(item)}><Pencil size={15}/></button>}<button className="row-action" disabled={rowBusy} onClick={()=>void onDelete(item.id)}><Trash2 size={15}/></button></div></div>;})}</div>;
}

function SettingsPage({ settings, isBusy, browserPolicyStatus, onToggle, onRetention, onApplyBrowserPolicies }: { settings:backend.Settings; isBusy:(scope:string)=>boolean; browserPolicyStatus:backend.BrowserPolicyStatus|null; onToggle:(key:string,enabled:boolean)=>Promise<void>; onRetention:(value:string)=>Promise<void>; onApplyBrowserPolicies:()=>Promise<void> }) {
  const [tab,setTab]=useState<"protection"|"browser"|"privacy">("protection");
  return <>
    <section className="cw-page-intro"><p>控制保护生命周期、安全搜索、浏览器增强保护和日志保留。</p></section>
    <section className="rules-tabs settings-tabs" role="tablist" aria-label="设置分类">
      <button role="tab" aria-selected={tab==="protection"} className={tab==="protection"?"active":""} onClick={()=>setTab("protection")}>保护开关 <span>6</span></button>
      <button role="tab" aria-selected={tab==="browser"} className={tab==="browser"?"active":""} onClick={()=>setTab("browser")}>浏览器保护</button>
      <button role="tab" aria-selected={tab==="privacy"} className={tab==="privacy"?"active":""} onClick={()=>setTab("privacy")}>日志隐私</button>
    </section>
    <section className="cw-settings-layout">
      {tab==="protection"&&<article className="cw-panel settings-switches"><h3>保护开关</h3><SettingToggle title="总保护" note="网络接管、DNS 和 TUN/VPN 生命周期" checked={settings.protectionEnabled} disabled={isBusy(busyScope.protection)} onChange={(value)=>onToggle("protection_enabled",value)}/><SettingToggle title="网络代理" note="允许的流量使用当前代理策略" checked={settings.proxyEnabled} disabled={isBusy(busyScope.setting("proxy_enabled"))} onChange={(value)=>onToggle("proxy_enabled",value)}/><SettingToggle title="安全搜索" note="搜索服务安全别名" checked={settings.safeSearchEnabled} disabled={isBusy(busyScope.setting("safe_search_enabled"))} onChange={(value)=>onToggle("safe_search_enabled",value)}/><SettingToggle title="严格模式" note="基于高风险后缀和关键词，误杀风险更高" checked={settings.strictModeEnabled} disabled={isBusy(busyScope.setting("strict_mode_enabled"))} onChange={(value)=>onToggle("strict_mode_enabled",value)}/><SettingToggle title="短视频与游戏" note="拦截常见短视频、直播和游戏平台域名" checked={Boolean(settings.categories.entertainment)} disabled={isBusy(busyScope.setting("category.entertainment"))} onChange={(value)=>onToggle("category.entertainment",value)}/><SettingToggle title="广告与跟踪保护" note="仅可选类别" checked={Boolean(settings.categories.ads || settings.categories.tracking)} disabled={isBusy(busyScope.setting("category.ads"))} onChange={(value)=>onToggle("category.ads",value)}/></article>}
      {tab==="browser"&&<BrowserPolicyPanel status={browserPolicyStatus} busy={isBusy(busyScope.setting("browser_policies"))} onApply={onApplyBrowserPolicies}/>}
      {tab==="privacy"&&<article className="cw-panel management-panel"><h3>日志隐私</h3><SettingToggle title="访问日志" note="最终网络决策仅保存在本机" checked={settings.accessLoggingEnabled} disabled={isBusy(busyScope.setting("access_logging_enabled"))} onChange={(value)=>onToggle("access_logging_enabled",value)}/><select aria-label="日志保留时间" value={settings.logRetention} disabled={isBusy(busyScope.setting("log_retention"))} onChange={(event)=>void onRetention(event.target.value)}><option value="7d">日志保留：7 天</option><option value="30d">日志保留：30 天</option><option value="90d">日志保留：90 天</option><option value="forever">日志保留：永久</option></select><p>诊断包导出是独立功能，默认会清除域名、IP、用户名、订阅地址、节点名称和凭据。</p></article>}
    </section>
  </>;
}

function BrowserPolicyPanel({ status, busy, onApply }: { status:backend.BrowserPolicyStatus|null; busy:boolean; onApply:()=>Promise<void> }) {
  const browsers = status?.browsers ?? [];
  const configuredCount = browsers.filter(browser => browser.installed && browser.configured).length;
  const installedCount = browsers.filter(browser => browser.installed).length;
  return <article className="cw-panel browser-policy-panel">
    <div className="cw-panel-head"><h3>浏览器增强保护</h3><span>{configuredCount}/{installedCount || browsers.length}</span></div>
    <p>为 Chrome 和 Edge 写入浏览器策略，强制 Google SafeSearch、YouTube 受限模式，并关闭浏览器内置 DoH。</p>
    <div className="browser-policy-list">
      {browsers.length === 0 ? <div className="table-empty">正在读取浏览器状态</div> : browsers.map(browser => <BrowserPolicyRow browser={browser} key={browser.id}/>)}
    </div>
    <button className="primary full" disabled={busy || installedCount === 0} onClick={()=>void onApply()}><MonitorCheck size={16}/>{busy ? "配置中…" : "应用浏览器保护"}</button>
  </article>;
}

function BrowserPolicyRow({ browser }: { browser:backend.BrowserPolicyBrowserStatus }) {
  const statusText = !browser.installed ? "未安装" : browser.configured ? "已配置" : "需配置";
  const statusClass = !browser.installed ? "missing" : browser.configured ? "configured" : "pending";
  return <div className="browser-policy-row">
    <div><b>{browser.name}</b><span>{browser.details.map(detail => detail.configured ? detail.label : `${detail.label}待配置`).join(" · ")}</span></div>
    <strong className={statusClass}>{statusText}</strong>
  </div>;
}

function SettingToggle({ title, note, checked, disabled, onChange }: { title:string; note:string; checked:boolean; disabled:boolean; onChange:(value:boolean)=>void|Promise<void> }) {
  return <div className="setting-toggle"><div><b>{title}</b><span>{note}</span></div><Switch checked={checked} label={title} disabled={disabled} onChange={onChange}/></div>;
}

function SettingCard({ title, note, children }: { title: string; note: string; children: React.ReactNode }) { return <article className="setting-card"><div><b>{title}</b><span>{note}</span></div>{children}</article>; }
function Switch({ checked, label, disabled = false, onChange }: { checked: boolean; label: string; disabled?: boolean; onChange: (value: boolean) => void | Promise<void> }) {
  const [pending, setPending] = useState(false);
  const handleClick = async () => {
    if (pending || disabled) return;
    setPending(true);
    try { await onChange(!checked); }
    finally { setPending(false); }
  };
  return <button type="button" role="switch" aria-label={label} aria-checked={checked} aria-busy={pending} disabled={pending || disabled} className={`switch ${checked ? "on" : ""} ${pending ? "pending" : ""}`} onClick={() => void handleClick()}><span/></button>;
}

const SubProxyNodeButton = memo(function SubProxyNodeButton({ name, nodeType, isMember, isCurrent, isChoosing, isTesting, delay, disabled, onChoose }: { name:string;nodeType:string;isMember:boolean;isCurrent:boolean;isChoosing:boolean;isTesting:boolean;delay:number|undefined;disabled:boolean;onChoose:(name:string)=>void }) {
  const dl = proxyDelayLabel(delay);
  return <button type="button" className={`sub-proxy-node${isMember ? "" : " dimmed"}${isCurrent ? " current" : ""}${isTesting ? " testing" : ""}${isChoosing ? " choosing" : ""}`} disabled={disabled} aria-pressed={isCurrent} onClick={()=>onChoose(name)}>
    <span className="sub-proxy-node-name">{name}</span>
    <span className="sub-proxy-node-meta">
      {isChoosing ? <span className="sub-proxy-current">切换中</span> : isCurrent ? <span className="sub-proxy-current">当前使用</span> : <span className="sub-proxy-choose">选择</span>}
      <span className="sub-proxy-node-type">{nodeType}</span>
      {isTesting ? <span className="sub-proxy-delay testing">检测中…</span> : dl && <span className={`sub-proxy-delay ${dl.cls}`}>{dl.text}</span>}
    </span>
  </button>;
});

function Rules({ parentRules, subscriptions, refreshingId, isBusy, onRefresh, onToggleParentRule, onDeleteParentRule, onAddParentRule, onToggleSubscription, onDelete, onEdit, onAdd }: { parentRules:backend.ParentRule[]; subscriptions: backend.Subscription[]; refreshingId:string|null; isBusy:(scope:string)=>boolean; onRefresh:(id:string)=>Promise<void>;onToggleParentRule:(id:string,enabled:boolean)=>Promise<void>;onDeleteParentRule:(id:string)=>Promise<void>;onAddParentRule:(mode:"block"|"route")=>void; onToggleSubscription:(id:string,enabled:boolean)=>Promise<void>; onDelete:(id:string)=>Promise<void>; onEdit:(subscription:backend.Subscription)=>void; onAdd: () => void }) {
  const [tab,setTab]=useState<"block"|"route"|"builtin"|"external">("block");
  const isBuiltinSubscription = (item: backend.Subscription) => item.id.startsWith("default:") || item.url.startsWith("builtin://") || item.name.startsWith("内置规则") || item.name.startsWith("内置路由");
  const builtinSubscriptions = subscriptions.filter(isBuiltinSubscription);
  const externalSubscriptions = subscriptions.filter((item) => !isBuiltinSubscription(item));
  const blockRules = parentRules.filter((item) => item.action === "block");
  const routeRules = parentRules.filter((item) => item.action !== "block");
  const subscriptionFormat = (item: backend.Subscription) => item.format ?? "自动检测";
  const updateInterval = (item: backend.Subscription) => item.updateIntervalHours ? `${item.updateIntervalHours}小时更新` : "手动更新";
  const matchKindLabel = (kind: string) => ({exact:"精确域名",suffix:"域名及子域名",contains:"关键词",wildcard:"通配符",regex:"正则",ip:"IP地址",cidr:"IP网段"}[kind] ?? kind);
  const ruleActionLabel = (action: backend.ParentRule["action"]) => action === "block" ? "拦截" : action === "proxy" ? "走代理" : action === "system_route" ? "系统路由" : "直连";
  const renderParentRule = (item: backend.ParentRule) => {
    const rowBusy = isBusy(busyScope.rule(item.id));
    return <div className="table-row" key={item.id}><div><b>{item.pattern}</b><small>{matchKindLabel(item.kind)} · {item.category}</small></div><span className={`rule-action ${item.action}`}>{ruleActionLabel(item.action)}</span><Switch checked={item.enabled} label={`${item.pattern}规则`} disabled={rowBusy} onChange={value=>onToggleParentRule(item.id,value)}/><button className="row-action" aria-label={`删除${item.pattern}`} disabled={rowBusy} onClick={()=>void onDeleteParentRule(item.id)}><Trash2 size={15}/></button></div>;
  };
  return <>
    <section className="rules-tabs" role="tablist" aria-label="规则管理分类">
      <button role="tab" aria-selected={tab==="block"} className={tab==="block"?"active":""} onClick={()=>setTab("block")}>访问拦截 <span>{blockRules.length}</span></button>
      <button role="tab" aria-selected={tab==="route"} className={tab==="route"?"active":""} onClick={()=>setTab("route")}>路由设置 <span>{routeRules.length}</span></button>
      <button role="tab" aria-selected={tab==="builtin"} className={tab==="builtin"?"active":""} onClick={()=>setTab("builtin")}>内置规则 <span>{builtinSubscriptions.length}</span></button>
      <button role="tab" aria-selected={tab==="external"} className={tab==="external"?"active":""} onClick={()=>setTab("external")}>外部订阅 <span>{externalSubscriptions.length}</span></button>
    </section>
    {tab==="block"&&<><section className="toolbar"><div><h2>访问拦截</h2><p>手动阻止指定域名、关键词、IP 或网段，优先于普通内容和路由规则。</p></div><button className="primary" disabled={isBusy(busyScope.createRule)} onClick={()=>onAddParentRule("block")}><Plus size={16}/>添加拦截</button></section>
    <section className="table-card parent-rules"><div className="table-head"><span>规则</span><span>动作</span><span>状态</span><span>操作</span></div>{blockRules.length===0&&<div className="table-empty">尚未添加拦截规则</div>}{blockRules.map(renderParentRule)}</section></>}
    {tab==="route"&&<><section className="toolbar"><div><h2>路由设置</h2><p>为指定目标选择直连、走代理或按系统路由；安全和拦截规则仍然拥有更高优先级。</p></div><button className="primary" disabled={isBusy(busyScope.createRule)} onClick={()=>onAddParentRule("route")}><Plus size={16}/>添加路由</button></section>
    <section className="table-card parent-rules"><div className="table-head"><span>规则</span><span>出口</span><span>状态</span><span>操作</span></div>{routeRules.length===0&&<div className="table-empty">尚未添加路由规则</div>}{routeRules.map(renderParentRule)}</section></>}
    {tab==="builtin"&&<><section className="toolbar"><div><h2>内置规则</h2><p>CleanWeb 维护的基础规则包，安装后默认启用并每天更新。</p></div></section>
    <section className="table-card">
      <div className="table-head"><span>名称</span><span>格式</span><span>状态</span><span>操作</span></div>
      {builtinSubscriptions.length === 0 && <div className="table-empty">内置规则暂不可用</div>}
      {builtinSubscriptions.map((item) => (
        <div className="table-row" key={item.id}>
          <div>
            <b>{item.name}</b>
            <small className={item.lastError ? "error-text" : ""}>{item.lastError ?? `由 CleanWeb 维护，合并开源规则来源 · ${updateInterval(item)}`}</small>
          </div>
          <span>{subscriptionFormat(item)}</span>
          <span className="required-source">内置启用</span>
          <div className="row-actions"><button className="row-action" aria-label={`更新${item.name}`} disabled={isBusy(busyScope.subscription(item.id))||refreshingId===item.id} onClick={()=>void onRefresh(item.id)}><RefreshCw size={15}/></button></div>
        </div>
      ))}
    </section></>}
    {tab==="external"&&<><section className="toolbar"><div><h2>外部订阅</h2><p>用户导入的第三方规则来源，更新失败时保留最后一次有效规则。</p></div><button className="primary" disabled={isBusy(busyScope.createSubscription)} onClick={onAdd}><Plus size={16}/>添加订阅</button></section>
    <section className="table-card">
      <div className="table-head"><span>名称</span><span>格式</span><span>状态</span><span>操作</span></div>
      {externalSubscriptions.length === 0 && <div className="table-empty">尚未添加外部规则订阅</div>}
      {externalSubscriptions.map((item) => {
        const rowBusy = isBusy(busyScope.subscription(item.id));
        return <div className="table-row" key={item.id}>
          <div><b>{item.name}</b><small className={item.lastError?"error-text":""}>{item.lastError??item.url}</small></div>
          <span>{subscriptionFormat(item)}</span>
          <Switch checked={item.enabled} label={`${item.name}订阅`} disabled={rowBusy} onChange={(value)=>onToggleSubscription(item.id,value)}/>
          <div className="row-actions"><button className="row-action" aria-label={`更新${item.name}`} disabled={rowBusy||refreshingId===item.id} onClick={()=>void onRefresh(item.id)}><RefreshCw size={15}/></button><button className="row-action" aria-label={`编辑${item.name}`} disabled={rowBusy} onClick={()=>onEdit(item)}><Pencil size={15}/></button><button className="row-action" aria-label={`删除${item.name}`} disabled={rowBusy} onClick={()=>void onDelete(item.id)}><Trash2 size={15}/></button></div>
        </div>;
      })}
    </section></>}
  </>;
}

function Proxy({ subscriptions, refreshingId, isBusy, onRefresh, onToggleSubscription, onDelete, onAdd, coreStatus, automatic, onAutomatic, onSelectNode, sessionToken }: { subscriptions:backend.Subscription[]; refreshingId:string|null; isBusy:(scope:string)=>boolean; onRefresh:(id:string)=>Promise<void>; onToggleSubscription:(id:string,enabled:boolean)=>Promise<void>; onDelete:(id:string)=>Promise<void>; onAdd: (mode: ProxyImportMode) => void; coreStatus:backend.CoreStatus|null; automatic:boolean;onAutomatic:()=>Promise<void>;onSelectNode:(name:string)=>Promise<void>;sessionToken:string|null }) {
  const running = coreStatus?.running === true;
  const [expandedId, setExpandedId] = useState<string|null>(null);
  const [subProxies, setSubProxies] = useState<Record<string, backend.SubscriptionProxyInfo>>({});
  const [selectedGroup, setSelectedGroup] = useState<string|null>(null);
  const [delays, setDelays] = useState<Record<string, number>>({});
  const [testingSpeed, setTestingSpeed] = useState(false);
  const [testingNodeName, setTestingNodeName] = useState<string>();
  const [delayError,setDelayError]=useState("");
  const [savedSelection,setSavedSelection]=useState<string>();
  const [runtimeSelection,setRuntimeSelection]=useState<string>();
  const [selecting,setSelecting]=useState<string>();
  const selectingRef=useRef(false);
  const [importMenuOpen,setImportMenuOpen]=useState(false);
  useEffect(() => { if (refreshingId) setSubProxies(prev => { const next = { ...prev }; delete next[refreshingId]; return next; }); }, [refreshingId]);
  useEffect(() => { const ids = new Set(subscriptions.map(s => s.id)); setSubProxies(prev => { const next: Record<string, backend.SubscriptionProxyInfo> = {}; for (const [k, v] of Object.entries(prev)) if (ids.has(k)) next[k] = v; return next; }); }, [subscriptions]);
  useEffect(() => {
    if (!sessionToken) return;
    const missing = subscriptions.filter(item => item.enabled && !subProxies[item.id]);
    for (const item of missing) {
      void backend.getSubscriptionProxies(sessionToken,item.id)
        .then(info=>setSubProxies(previous=>({...previous,[item.id]:info})))
        .catch(()=>{});
    }
  }, [sessionToken,subscriptions,subProxies]);
  useEffect(()=>{if(!sessionToken)return;void backend.getSavedProxySelection(sessionToken).then(setSavedSelection);if(running)void backend.getProxies(sessionToken).then(groups=>setRuntimeSelection(groups.find(group=>group.name==="CleanWeb")?.now)).catch(()=>setRuntimeSelection(undefined));else setRuntimeSelection(undefined);},[sessionToken,running,subscriptions]);
  const toggleExpand = async (id: string) => {
    if (!sessionToken) return;
    if (expandedId === id) { setExpandedId(null); setSelectedGroup(null); return; }
    setExpandedId(id); setSelectedGroup(null);
    if (!subProxies[id]) {
      try { const info = await backend.getSubscriptionProxies(sessionToken,id); setSubProxies(prev => ({ ...prev, [id]: info })); } catch (reason) { console.error(reason); }
    }
  };
  const handleSpeedTest = async () => {
    if (!running || testingSpeed || !sessionToken) return;
    const nodes = selectableNodes;
    if (nodes.length === 0) { setDelayError("没有可检测的启用节点"); return; }
    setTestingSpeed(true);
    setDelayError("");
    setDelays(previous => {
      const next = { ...previous };
      for (const node of nodes) delete next[node.name];
      return next;
    });
    try {
      setTestingNodeName(undefined);
      const result = await backend.testAllProxyDelays(sessionToken, "CleanWeb");
      const nextDelays: Record<string, number> = {};
      let failedCount = 0;
      for (const node of nodes) {
        const delay = result.delays[node.name];
        if (delay == null) {
          failedCount += 1;
          nextDelays[node.name] = 0;
        } else {
          nextDelays[node.name] = delay;
        }
      }
      setDelays(previous => ({ ...previous, ...nextDelays }));
      if (failedCount > 0) setDelayError(`部分节点检测失败：${failedCount}/${nodes.length}`);
    } catch {
      setDelayError("节点延迟检测失败");
      setDelays(previous => {
        const next = { ...previous };
        for (const node of nodes) next[node.name] = 0;
        return next;
      });
    } finally {
      setTestingNodeName(undefined);
      setTestingSpeed(false);
    }
  };
  // 构建归一化的延迟查找表，支持模糊匹配
  const findDelay = (name: string): number | undefined => {
    if (delays[name] != null) return delays[name];
    const lower = name.toLowerCase();
    for (const [key, value] of Object.entries(delays)) {
      if (key.toLowerCase() === lower) return value;
    }
    return undefined;
  };
  const selectableNodes=Array.from(new Map(subscriptions.filter(item=>item.enabled).flatMap(item=>subProxies[item.id]?.proxies??[]).map(node=>[node.name,node])).values());
  const chooseNode=useCallback(async(name:string)=>{
    if(selectingRef.current)return;
    selectingRef.current=true;
    const previousRuntime=runtimeSelection;
    setSelecting(name);
    setRuntimeSelection(name);
    try{
      await onSelectNode(name);
      setSavedSelection(name);
    }catch(reason){
      setRuntimeSelection(previousRuntime);
      console.error(reason);
    }finally{
      selectingRef.current=false;
      setSelecting(undefined);
    }
  },[onSelectNode,runtimeSelection]);
  const openImport=(mode:ProxyImportMode)=>{setImportMenuOpen(false);onAdd(mode);};
  return <>
    <section className="toolbar"><div><h2>代理订阅</h2><p>{subscriptions.length>0?`当前出口：${automatic?"自动选择节点":runtimeSelection??savedSelection??"尚未选择节点"}`:"导入代理后，展开来源并选择节点作为当前出口。"}</p></div><div className="proxy-toolbar-actions">{subscriptions.length>0&&<button className="secondary" disabled={!running||testingSpeed||selectableNodes.length===0} onClick={()=>void handleSpeedTest()}><Gauge size={15}/>{testingSpeed?"检测中…":"节点延迟检测"}</button>}<button className={`secondary${automatic?" selected":""}`} disabled={automatic||Boolean(selecting)||subscriptions.length===0||isBusy(busyScope.setting("automatic_node_selection"))} onClick={()=>void onAutomatic()}>自动选择</button><div className="import-dropdown"><button className="primary import-main" disabled={isBusy(busyScope.importProxy)} onClick={()=>openImport("subscription")}><Plus size={16}/>导入代理</button><button className="primary import-menu-trigger" disabled={isBusy(busyScope.importProxy)} aria-label="选择代理导入方式" aria-expanded={importMenuOpen} onClick={()=>setImportMenuOpen(value=>!value)}><ChevronDown size={16}/></button>{importMenuOpen&&<div className="import-menu" role="menu"><button role="menuitem" onClick={()=>openImport("subscription")}>订阅链接</button><button role="menuitem" onClick={()=>openImport("node")}>单节点链接</button><button role="menuitem" onClick={()=>openImport("file")}>配置文件</button><button role="menuitem" onClick={()=>openImport("qr")}>二维码导入</button><button role="menuitem" onClick={()=>openImport("clipboard")}>从剪贴板导入</button></div>}</div></div></section>
    {delayError&&<div className="proxy-delay-error">{delayError}</div>}
    {subscriptions.length===0 ? <section className="proxy-card empty-proxy">尚未导入代理订阅</section> : subscriptions.map((item)=>{
      const expanded = expandedId === item.id;
      const manualSource = item.url.startsWith("manual://");
      const info = subProxies[item.id];
      const itemBusy = isBusy(busyScope.subscription(item.id));
      const currentGroup = selectedGroup != null ? info?.groups.find(g => g.name === selectedGroup) : null;
      const memberSet = currentGroup ? new Set(currentGroup.members) : null;
      const typeSummary = info ? Object.entries(info.proxies.reduce<Record<string,number>>((acc, p) => { acc[p.nodeType] = (acc[p.nodeType]||0)+1; return acc; }, {})).sort((a,b) => b[1]-a[1]).map(([t,c]) => ({ type: t, count: c })) : [];
      return <section className={`proxy-card${expanded ? " expanded" : ""}`} key={item.id}>
        <div className="proxy-card-header" onClick={()=>void toggleExpand(item.id)} role="button" tabIndex={0} onKeyDown={(e)=>{if(e.key==="Enter"||e.key===" ")void toggleExpand(item.id);}}>
          <div className="proxy-icon"><Network/></div>
          <div className="proxy-info">
            <div className="proxy-meta-row">
              <span className="status">节点来源{info ? ` · ${info.proxies.length} 节点${info.groups.length > 0 ? ` · ${info.groups.length} 组` : ""}` : ""}</span>
              {typeSummary.length > 0 && <div className="proxy-type-badges">{typeSummary.map(t => <span className="proxy-type-badge" key={t.type}><span className="proxy-type-name">{t.type.toUpperCase()}</span><span className="proxy-type-count">{t.count}</span></span>)}</div>}
            </div>
            <h3>{item.name}</h3><p className={item.lastError?"error-text":""}>{item.lastError??(manualSource?"手动导入":item.url)}</p></div>
          <div className="proxy-actions" onClick={(e)=>e.stopPropagation()}>
            <Switch checked={item.enabled} label={`${item.name}订阅`} disabled={itemBusy} onChange={(value)=>onToggleSubscription(item.id,value)}/>
            <button className="row-action" aria-label={`更新${item.name}`} disabled={manualSource||itemBusy||refreshingId===item.id} onClick={()=>void onRefresh(item.id)}><RefreshCw size={15}/></button>
            <button className="row-action" aria-label={`删除${item.name}`} disabled={itemBusy} onClick={()=>void onDelete(item.id)}><Trash2 size={15}/></button>
          </div>
          <span className="expand-chevron">{expanded ? <ChevronDown size={18}/> : <ChevronRight size={18}/>}</span>
        </div>
        {expanded && info && <div className="proxy-card-body">
          {info.proxies.length === 0 && info.groups.length === 0
            ? <div className="sub-proxy-empty">该订阅未解析到代理节点</div>
            : <div className={`sub-proxy-layout${info.groups.length === 0 ? " no-groups" : ""}`}>
                {info.groups.length > 0 && <div className="sub-proxy-sidebar">
                  <div className="sub-proxy-sidebar-title">代理组</div>
                  {info.groups.map(g => {
                    const active = selectedGroup === g.name;
                    return <button key={g.name} className={`sub-proxy-group-btn${active ? " active" : ""}`} onClick={()=>setSelectedGroup(active ? null : g.name)}>
                      <span className="sub-proxy-group-btn-name">{g.name}</span>
                      <span className="sub-proxy-group-btn-meta">{g.groupType === "Selector" ? "手动" : g.groupType === "URLTest" ? "自动" : g.groupType} · {g.members.length}</span>
                    </button>;
                  })}
                </div>}
                <div className="sub-proxy-main">
                  <div className="sub-proxy-main-head">
                    <h4>{currentGroup ? `${currentGroup.name} 节点` : "来源节点"}</h4>
                  </div>
                  <div className="sub-proxy-grid">
                    {info.proxies.map(p => {
                      const isMember = memberSet ? memberSet.has(p.name) : true;
                      const isTesting = testingNodeName === p.name;
                      const isCurrent = p.name === runtimeSelection || (!running && !automatic && p.name === savedSelection);
                      const isChoosing = selecting === p.name;
                      return <SubProxyNodeButton key={p.name} name={p.name} nodeType={p.nodeType} isMember={isMember} isCurrent={isCurrent} isChoosing={isChoosing} isTesting={isTesting} delay={findDelay(p.name)} disabled={!isMember||itemBusy} onChoose={chooseNode} />;
                    })}
                  </div>
                </div>
              </div>
          }
        </div>}
      </section>;
    })}
  </>;
}

function UnlockDialog({ onClose, onUnlock }: { onClose: () => void; onUnlock: (password: string) => Promise<void> }) {
  const [error, setError] = useState("");
  return <div className="modal-backdrop" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
    <section className="modal" role="dialog" aria-modal="true" aria-labelledby="unlock-title">
      <button className="icon-button" aria-label="关闭" onClick={onClose}><X size={18}/></button>
      <div className="modal-symbol"><LockKeyhole/></div>
      <h2 id="unlock-title">身份认证</h2>
      <p>请输入管理密码以修改规则和代理设置。</p>
      <form onSubmit={async (event) => { event.preventDefault(); setError(""); const password = new FormData(event.currentTarget).get("password") as string; try { await onUnlock(password); } catch (reason) { setError(String(reason)); } }}>
        <label htmlFor="parent-password">管理密码</label>
        <input id="parent-password" name="password" type="password" placeholder="输入管理密码" required autoFocus autoComplete="current-password" onKeyDown={(e) => { if (e.nativeEvent.isComposing || e.keyCode === 229) e.preventDefault(); }} onCompositionEnd={(e) => { const el = e.currentTarget; el.value = el.value.replace(/[^\x20-\x7E]/g, ""); }} onInput={(e) => { const el = e.currentTarget; el.value = el.value.replace(/[^\x20-\x7E]/g, ""); }} />
        {error && <span className="form-error">{error}</span>}
        <button className="primary full" type="submit">确认解锁</button>
      </form>
    </section>
  </div>;
}

function SetupDialog({ onComplete }: { onComplete: () => void }) {
  const [error, setError] = useState("");
  return <div className="modal-backdrop setup-backdrop"><section className="modal" role="dialog" aria-modal="true" aria-labelledby="setup-title">
    <div className="modal-symbol"><ShieldCheck/></div><h2 id="setup-title">设置家长管理密码</h2><p>密码用于保护网络开关、规则和代理配置，至少8个字符。</p>
    <form onSubmit={async (event) => { event.preventDefault(); const data = new FormData(event.currentTarget); const password = String(data.get("password")); const confirm = String(data.get("confirm")); if (password !== confirm) { setError("两次输入的密码不一致"); return; } try { await backend.initializePassword(password); onComplete(); } catch (reason) { setError(String(reason)); } }}>
      <label htmlFor="setup-password">管理密码</label><input id="setup-password" name="password" type="password" minLength={8} required autoFocus autoComplete="new-password" onKeyDown={(e) => { if (e.nativeEvent.isComposing || e.keyCode === 229) e.preventDefault(); }} onCompositionEnd={(e) => { const el = e.currentTarget; el.value = el.value.replace(/[^\x20-\x7E]/g, ""); }} onInput={(e) => { const el = e.currentTarget; el.value = el.value.replace(/[^\x20-\x7E]/g, ""); }} />
      <label htmlFor="setup-confirm">确认密码</label><input id="setup-confirm" name="confirm" type="password" minLength={8} required autoComplete="new-password" onKeyDown={(e) => { if (e.nativeEvent.isComposing || e.keyCode === 229) e.preventDefault(); }} onCompositionEnd={(e) => { const el = e.currentTarget; el.value = el.value.replace(/[^\x20-\x7E]/g, ""); }} onInput={(e) => { const el = e.currentTarget; el.value = el.value.replace(/[^\x20-\x7E]/g, ""); }} />
      {error && <span className="form-error">{error}</span>}<button className="primary full" type="submit">保存管理密码</button>
    </form>
  </section></div>;
}

function ParentRuleDialog({mode,onClose,onSubmit}:{mode:"block"|"route";onClose:()=>void;onSubmit:(input:backend.NewParentRule)=>Promise<void>}){
  const[error,setError]=useState("");
  const isRoute = mode === "route";
  return <div className="modal-backdrop" onMouseDown={event=>event.target===event.currentTarget&&onClose()}><section className="modal" role="dialog" aria-modal="true" aria-labelledby="parent-rule-title"><button className="icon-button" aria-label="关闭" onClick={onClose}><X size={18}/></button><h2 id="parent-rule-title">{isRoute?"添加路由规则":"添加拦截规则"}</h2><p>{isRoute?"为匹配目标指定直连、走代理或按系统路由；高风险安全与手动拦截仍会优先生效。":"手动阻止指定目标；诈骗、钓鱼和恶意软件仍保持最高优先级。"}</p><form onSubmit={async event=>{event.preventDefault();const data=new FormData(event.currentTarget);setError("");try{await onSubmit({action:String(data.get("action")) as backend.ParentRule["action"],kind:String(data.get("kind")),pattern:String(data.get("pattern")),category:String(data.get("category")||"custom")});}catch(reason){setError(String(reason));}}}><label htmlFor="parent-action">{isRoute?"出口":"动作"}</label>{isRoute?<select id="parent-action" name="action"><option value="allow">直连</option><option value="proxy">走代理</option><option value="system_route">系统路由</option></select>:<><input type="hidden" name="action" value="block"/><div className="readonly-field">拦截</div></>}<label htmlFor="parent-kind">匹配方式</label><select id="parent-kind" name="kind"><option value="suffix">域名及子域名</option><option value="exact">精确域名</option><option value="ip">IP地址</option><option value="cidr">IP网段</option><option value="contains">关键词包含</option><option value="wildcard">通配符</option><option value="regex">正则表达式</option></select><label htmlFor="parent-pattern">规则内容</label><input id="parent-pattern" name="pattern" placeholder="example.com 或 47.96.0.0/12" required autoComplete="off" spellCheck={false}/><input type="hidden" name="category" value={isRoute?"routing":"custom"}/>{error&&<span className="form-error">{error}</span>}<div className="modal-actions"><button type="button" className="secondary" onClick={onClose}>取消</button><button className="primary" type="submit">验证并保存</button></div></form></section></div>;
}

function ProxyImportDialog({ mode, onClose, onSubscriptionSubmit, onPayloadSubmit }: { mode: ProxyImportMode; onClose: () => void; onSubscriptionSubmit:(input:backend.NewSubscription)=>Promise<void>; onPayloadSubmit:(input:backend.ManualProxyImport)=>Promise<void> }) {
  const [error,setError]=useState("");
  const [importName,setImportName]=useState("");
  const [content,setContent]=useState("");
  const [qrFileName,setQrFileName]=useState("");
  const [qrDecoding,setQrDecoding]=useState(false);
  const [qrDragActive,setQrDragActive]=useState(false);
  const isSubscription=mode==="subscription";
  const title=mode==="subscription"?"导入代理订阅":mode==="node"?"导入单节点链接":mode==="file"?"导入配置文件":mode==="qr"?"导入二维码":"从剪贴板导入";
  const description=mode==="subscription"?"只会提取代理节点和代理组。":mode==="file"?"选择 Clash/Mihomo YAML 配置，只会保留代理节点和代理组。":mode==="qr"?"拖入代理二维码图片，本地解析后导入。":"支持单条或多条代理链接。";
  const handleQrFile=async(file:File|undefined)=>{if(!file)return;setQrDecoding(true);setQrDragActive(false);setError("");setQrFileName(file.name);try{setContent(await decodeQrImage(file));}catch(reason){setContent("");setError(String(reason));}finally{setQrDecoding(false);}};
  const handleConfigFile=async(file:File|undefined)=>{if(!file)return;setError("");setQrFileName(file.name);try{const text=await file.text();setContent(text);setImportName(name=>name||file.name.replace(/\.(ya?ml|conf|txt)$/i,""));}catch(reason){setContent("");setError(String(reason));}};
  useEffect(()=>{if(mode!=="clipboard")return;let cancelled=false;void navigator.clipboard?.readText().then(text=>{if(!cancelled)setContent(text);}).catch(()=>{if(!cancelled)setError("无法读取剪贴板，请手动粘贴内容");});return()=>{cancelled=true;};},[mode]);
  return <div className="modal-backdrop" onMouseDown={(event)=>event.target===event.currentTarget&&onClose()}>
    <section className="modal modal-wide" role="dialog" aria-modal="true" aria-labelledby="proxy-import-title">
      <button className="icon-button" aria-label="关闭" onClick={onClose}><X size={18}/></button>
      <h2 id="proxy-import-title">{title}</h2>
      <p>{description}</p>
      <form onSubmit={async event=>{event.preventDefault();const data=new FormData(event.currentTarget);setError("");try{if(isSubscription)await onSubscriptionSubmit({kind:"proxy",name:String(data.get("name")),url:String(data.get("url")),format:"auto",updateIntervalHours:Number(data.get("interval")||24)});else{if(!content.trim())throw new Error(mode==="qr"?"请先拖入二维码图片":mode==="file"?"请先选择配置文件":"代理内容不能为空");await onPayloadSubmit({name:String(data.get("name")),content});}}catch(reason){setError(String(reason));}}}>
        <label htmlFor="proxy-import-name">名称</label>
        <input id="proxy-import-name" name="name" value={importName} onChange={event=>setImportName(event.currentTarget.value)} placeholder={isSubscription?"我的代理订阅":mode==="file"?"配置文件名称":"我的代理节点"} required autoComplete="off" spellCheck={false}/>
        {isSubscription ? <>
          <label htmlFor="proxy-import-url">订阅地址</label>
          <input id="proxy-import-url" name="url" type="url" placeholder="https://example.com/subscription" required autoComplete="off" spellCheck={false}/>
          <label htmlFor="proxy-import-interval">更新周期</label>
          <select id="proxy-import-interval" name="interval"><option value="6">每6小时</option><option value="12">每12小时</option><option value="24">每天</option><option value="168">每7天</option></select>
        </> : mode==="qr" ? <>
          <label htmlFor="proxy-import-qr">二维码图片</label>
          <label className={`qr-dropzone${qrDecoding?" decoding":""}${qrDragActive?" dragging":""}`} htmlFor="proxy-import-qr" onDragEnter={event=>{event.preventDefault();setQrDragActive(true);}} onDragOver={event=>{event.preventDefault();event.dataTransfer.dropEffect="copy";setQrDragActive(true);}} onDragLeave={event=>{event.preventDefault();if(event.currentTarget===event.target)setQrDragActive(false);}} onDrop={event=>{event.preventDefault();event.stopPropagation();void handleQrFile(event.dataTransfer.files[0]);}}>
            <input id="proxy-import-qr" type="file" accept="image/*" onChange={event=>void handleQrFile(event.currentTarget.files?.[0])}/>
            {content ? <ScanQrCode size={24}/> : <Upload size={24}/>}
            <strong>{qrDecoding?"正在解析二维码…":content?"二维码已解析":"拖入二维码图片"}</strong>
            <span>{content?qrFileName||"已读取图片":"或点击选择图片文件"}</span>
          </label>
          {content&&<div className="qr-decoded-preview">{content}</div>}
        </> : mode==="file" ? <>
          <label htmlFor="proxy-import-file">配置文件</label>
          <label className="qr-dropzone" htmlFor="proxy-import-file">
            <input id="proxy-import-file" type="file" accept=".yaml,.yml,.conf,.txt,application/yaml,text/yaml,text/plain" onChange={event=>void handleConfigFile(event.currentTarget.files?.[0])}/>
            <Upload size={24}/>
            <strong>{content?"配置文件已读取":"选择 Clash/Mihomo 配置文件"}</strong>
            <span>{content?qrFileName||"已读取文件":"会在本机清洗后导入"}</span>
          </label>
          {content&&<div className="qr-decoded-preview">{content.slice(0,800)}</div>}
        </> : <>
          <label htmlFor="proxy-import-content">代理内容</label>
          <textarea id="proxy-import-content" value={content} onChange={event=>setContent(event.currentTarget.value)} placeholder="ss://... 或 vmess://..." required spellCheck={false}/>
          {mode==="clipboard"&&<button type="button" className="secondary inline-form-action" onClick={()=>void navigator.clipboard?.readText().then(setContent).catch(()=>setError("无法读取剪贴板，请手动粘贴内容"))}>重新读取剪贴板</button>}
        </>}
        {error&&<span className="form-error">{error}</span>}
        <div className="modal-actions"><button type="button" className="secondary" onClick={onClose}>取消</button><button className="primary" type="submit" disabled={qrDecoding}>验证并添加</button></div>
      </form>
    </section>
  </div>;
}

function SubscriptionDialog({ kind, subscription, onClose, onSubmit }: { kind: "规则" | "代理"; subscription?: backend.Subscription; onClose: () => void; onSubmit:(input:backend.NewSubscription)=>Promise<void> }) {
  const [error,setError]=useState("");
  const editing=Boolean(subscription);
  const defaultInterval=String(subscription?.updateIntervalHours??24);
  const defaultFormat=subscription?.format??"auto";
  return <div className="modal-backdrop" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
    <section className="modal modal-wide" role="dialog" aria-modal="true" aria-labelledby="subscription-title">
      <button className="icon-button" aria-label="关闭" onClick={onClose}><X size={18}/></button>
      <h2 id="subscription-title">{editing?"修改":"添加"}{kind}订阅</h2>
      <p>{kind === "规则" ? "支持 Clash、hosts、域名、IP/CIDR 和 Adblock 列表。" : "只会提取代理节点和代理组。"}</p>
      <form onSubmit={async(event) => { event.preventDefault(); const data=new FormData(event.currentTarget); setError(""); try{await onSubmit({kind:kind==="规则"?"rule":"proxy",name:String(data.get("name")),url:String(data.get("url")),format:String(data.get("format")||"auto"),category:kind==="规则"?String(data.get("category")||"custom"):undefined,updateIntervalHours:Number(data.get("interval")||24)});}catch(reason){setError(String(reason));} }}>
        {kind==="规则"&&<><label htmlFor="subscription-format">格式</label><select id="subscription-format" name="format" defaultValue={defaultFormat}><option value="auto">自动检测</option><option value="clash">Clash/Mihomo</option><option value="adblock">Adblock</option><option value="hosts">Hosts</option><option value="domain-list">域名列表</option><option value="ip-list">IP/CIDR</option><option value="safe-search">安全搜索映射</option></select></>}
        <label htmlFor="subscription-name">订阅名称</label><input id="subscription-name" name="name" defaultValue={subscription?.name??""} placeholder={`我的${kind}订阅`} required autoComplete="off" spellCheck={false} />
        <label htmlFor="subscription-url">订阅地址</label><input id="subscription-url" name="url" type="url" defaultValue={subscription?.url??""} placeholder="https://example.com/subscription" required autoComplete="off" spellCheck={false} />
        {kind==="规则"&&<><label htmlFor="subscription-category">分类</label><select id="subscription-category" name="category" defaultValue={subscription?.category??"custom"}><option value="custom">自定义</option><option value="routing">代理路由</option><option value="direct">直连路由</option><option value="pornography">色情与擦边</option><option value="gambling">赌博</option><option value="malware">恶意软件</option><option value="entertainment">短视频与游戏</option><option value="ads">广告</option></select></>}
        <label htmlFor="subscription-interval">更新周期</label><select id="subscription-interval" name="interval" defaultValue={defaultInterval}><option value="6">每6小时</option><option value="12">每12小时</option><option value="24">每天</option><option value="168">每7天</option></select>
        {error&&<span className="form-error">{error}</span>}
        <div className="modal-actions"><button type="button" className="secondary" onClick={onClose}>取消</button><button className="primary" type="submit">{editing?"保存修改":"验证并添加"}</button></div>
      </form>
    </section>
  </div>;
}

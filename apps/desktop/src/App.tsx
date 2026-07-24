import { memo, type FormEvent, useCallback, useEffect, useRef, useState } from "react";
import jsQR from "jsqr";
import { Activity, BookOpen, ChevronDown, ChevronRight, Gauge, LockKeyhole, Network, Pencil, Plus, RefreshCw, ScanQrCode, ShieldCheck, Trash2, Upload, X } from "lucide-react";
import * as backend from "./backend";

type ProxyImportMode = "subscription" | "node" | "file" | "qr" | "clipboard";
type AppDialog = "unlock" | "rules" | "editRuleSubscription" | "proxy" | "custom" | "quit" | null;

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
};

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

function proxyDelayLabel(d: number | undefined) {
  if (d == null) return null;
  if (d === 0) return { text: "不可达", cls: "timeout" };
  if (d < 300) return { text: `${d}ms`, cls: "fast" };
  if (d < 600) return { text: `${d}ms`, cls: "medium" };
  return { text: `${d}ms`, cls: "slow" };
}

export function App() {
  const [page, setPage] = useState<"overview" | "rules" | "proxy">("overview");
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
  const [runtimeError,setRuntimeError]=useState("");
  const { anyBusy, isBusy, runScopedOperation } = useScopedOperations();
  const [policyApplyStatus,setPolicyApplyStatus]=useState<PolicyApplyStatus|null>(null);
  const policyStatusTimerRef=useRef<number|null>(null);
  const [accessLogs,setAccessLogs]=useState<backend.AccessLog[]>([]);
  const [accessLogStats,setAccessLogStats]=useState<backend.AccessLogStats>({block:0,allow:0,warning:0,total:0});
  const [parentRules,setParentRules]=useState<backend.ParentRule[]>([]);
  const titles = { overview: "网络环境安全", rules: "规则管理", proxy: "代理节点" };
  const requestAction = (action: "rules" | "proxy", mode: ProxyImportMode = "subscription") => { if (action === "proxy") setProxyImportMode(mode); setDialog(locked ? "unlock" : action); };
  const hideToBackground = async () => { setDialog(null); await backend.hideMainWindow(); };
  const quitApp = async () => { setDialog(null); await backend.confirmedQuit(); };
  const clearPolicyStatusTimer=()=>{if(policyStatusTimerRef.current!=null){window.clearTimeout(policyStatusTimerRef.current);policyStatusTimerRef.current=null;}};
  const showPolicyStatus=(status:PolicyApplyStatus)=>{clearPolicyStatusTimer();setPolicyApplyStatus(status);if(status.state==="applied"){policyStatusTimerRef.current=window.setTimeout(()=>{setPolicyApplyStatus(null);policyStatusTimerRef.current=null;},2600);}};
  useEffect(()=>()=>clearPolicyStatusTimer(),[]);
  useEffect(()=>{const preventContextMenu=(event:MouseEvent)=>event.preventDefault();window.addEventListener("contextmenu",preventContextMenu);return()=>window.removeEventListener("contextmenu",preventContextMenu);},[]);
  useEffect(()=>{let cancelled=false;let unlisten:(()=>void)|undefined;const showQuitDialog=()=>{void backend.takePendingQuitRequest().catch(()=>false).finally(()=>{if(!cancelled)setDialog("quit");});};const showPendingQuitDialog=()=>{void backend.takePendingQuitRequest().then(pending=>{if(pending&&!cancelled)setDialog("quit");}).catch(()=>{});};void backend.onQuitRequested(showQuitDialog).then(stop=>{if(cancelled)stop();else unlisten=stop;});showPendingQuitDialog();window.addEventListener("focus",showPendingQuitDialog);document.addEventListener("visibilitychange",showPendingQuitDialog);return()=>{cancelled=true;if(unlisten)unlisten();window.removeEventListener("focus",showPendingQuitDialog);document.removeEventListener("visibilitychange",showPendingQuitDialog);};},[]);
  useEffect(() => { void (async () => {
    const [bootstrap,current,core,publicStats] = await Promise.all([backend.getBootstrapState(), backend.getSettings(),backend.getCoreStatus(),backend.getPublicAccessLogStats()]);
    setNeedsSetup(!bootstrap.passwordConfigured); setSettings(current);setCoreStatus(core);setAccessLogStats(publicStats);
    const storedToken = backend.getStoredSessionToken();
    if (storedToken) {
      try {
        const result = await backend.validateSession(storedToken);
        const [logs,stats,saved,rules]=await Promise.all([backend.listAccessLogs(result.sessionToken,undefined,undefined,100),backend.getAccessLogStats(result.sessionToken),backend.listSubscriptions(result.sessionToken),backend.listParentRules(result.sessionToken)]);
        setSessionToken(result.sessionToken);setAccessLogs(logs);setAccessLogStats(stats);setSubscriptions(saved);setParentRules(rules);setLocked(false);
      } catch {
        backend.clearStoredSessionToken();
      }
    }
    setReady(true);
    if(current.protectionEnabled)void backend.autoStartProtection().then(setCoreStatus).catch(async reason=>{setRuntimeError(String(reason));try{setSettings(await backend.getSettings());}catch{}});
  })(); }, []);
  useEffect(()=>{const timer=window.setInterval(()=>void backend.getCoreStatus().then(setCoreStatus),5000);return()=>window.clearInterval(timer);},[]);
  useEffect(()=>{if(!sessionToken)return;const refresh=()=>{if(anyBusy)return;void backend.refreshDueSubscriptions().then(()=>reloadRuntime(sessionToken,{silent:true})).then(()=>backend.listSubscriptions(sessionToken)).then(setSubscriptions);};refresh();const timer=window.setInterval(refresh,15*60*1000);return()=>window.clearInterval(timer);},[sessionToken,anyBusy]);
  const handleUnlock = async (password: string) => { const result = await backend.unlock(password); setSessionToken(result.sessionToken);const[logs,stats,saved,rules]=await Promise.all([backend.listAccessLogs(result.sessionToken,undefined,undefined,100),backend.getAccessLogStats(result.sessionToken),backend.listSubscriptions(result.sessionToken),backend.listParentRules(result.sessionToken)]);setAccessLogs(logs);setAccessLogStats(stats);setSubscriptions(saved);setParentRules(rules); setLocked(false); setDialog(null); };
  const handleLock = async () => { if (sessionToken) await backend.lock(sessionToken); setSessionToken(null);setSubscriptions([]);setParentRules([]);setAccessLogs([]);setAccessLogStats({block:0,allow:0,warning:0,total:0}); setLocked(true); };
  const reloadRuntime=async(token:string,options:{silent?:boolean;applyingMessage?:string;idleMessage?:string}={})=>{
    if(!options.silent)showPolicyStatus({state:"applying",message:options.applyingMessage??"正在应用网络策略…"});
    try{
      const current=await backend.getCoreStatus();setCoreStatus(current);
      if(!current.running){if(!options.silent)showPolicyStatus({state:"applied",message:options.idleMessage??"设置已保存，保护启动后生效"});return current;}
      const core=await backend.reloadProtection(token);setCoreStatus(core);
      if(!options.silent)showPolicyStatus({state:"applied",message:"网络策略已生效"});
      return core;
    }catch(reason){
      if(!options.silent)showPolicyStatus({state:"failed",message:`网络策略应用失败：${String(reason)}`});
      throw reason;
    }
  };
  const setValue = async (key: string, value: string) => {
    if (!sessionToken) { setDialog("unlock"); return; }
    setRuntimeError("");
    await runScopedOperation(key==="protection_enabled"?busyScope.protection:busyScope.setting(key), async()=>{try {
      if(key==="protection_enabled"){showPolicyStatus({state:"applying",message:value==="true"?"正在启动保护…":"正在关闭保护…"});const core=value==="true"?await backend.startProtection(sessionToken):await backend.stopProtection(sessionToken);setCoreStatus(core);setSettings(await backend.updateSetting(sessionToken,key,value));showPolicyStatus({state:"applied",message:value==="true"?"保护已开启":"保护已关闭"});}
      else {showPolicyStatus({state:"applying",message:"正在保存并应用设置…"});setSettings(await backend.updateSetting(sessionToken,key,value));await reloadRuntime(sessionToken,{applyingMessage:"正在应用设置到运行内核…"});}
    } catch(reason) { showPolicyStatus({state:"failed",message:`操作失败：${String(reason)}`});setRuntimeError(String(reason)); }});
  };
  const toggle = (key: string, enabled: boolean) => setValue(key, String(enabled));
  const createSubscription = async (input: backend.NewSubscription) => {
    if (!sessionToken) throw new Error("请先解锁管理台");
    await runScopedOperation(busyScope.createSubscription, async()=>{showPolicyStatus({state:"applying",message:"正在导入并应用订阅…"});const item=await backend.createSubscription(sessionToken, input);
    try { await backend.refreshSubscription(sessionToken,item.id); } catch(reason) { await backend.deleteSubscription(sessionToken,item.id); throw reason; }
    setSubscriptions(await backend.listSubscriptions(sessionToken));await reloadRuntime(sessionToken); setDialog(null);});
  };
  const updateSubscription=async(id:string,input:backend.UpdateSubscription)=>{if(!sessionToken)throw new Error("请先解锁管理台");await runScopedOperation(busyScope.subscription(id),async()=>{setRuntimeError("");showPolicyStatus({state:"applying",message:"正在保存并更新订阅…"});await backend.updateSubscription(sessionToken,id,input);let refreshFailed:unknown;try{await backend.refreshSubscription(sessionToken,id);}catch(reason){refreshFailed=reason;}setSubscriptions(await backend.listSubscriptions(sessionToken));try{await reloadRuntime(sessionToken,{applyingMessage:"正在应用订阅修改…"});}catch(reason){setRuntimeError(`订阅已修改，但保护配置重载失败：${String(reason)}`);}setDialog(null);setEditingSubscription(null);if(refreshFailed){setRuntimeError(`订阅已修改，但刷新失败，继续使用最后一次有效规则：${String(refreshFailed)}`);}});};
  const importProxyPayload=async(input:backend.ManualProxyImport)=>{if(!sessionToken)throw new Error("请先解锁管理台");await runScopedOperation(busyScope.importProxy, async()=>{showPolicyStatus({state:"applying",message:"正在导入并应用代理配置…"});await backend.importProxyPayload(sessionToken,input);setSubscriptions(await backend.listSubscriptions(sessionToken));await reloadRuntime(sessionToken);setDialog(null);});};
  const toggleSubscription = async (id: string, enabled: boolean) => { if (!sessionToken) { setDialog("unlock"); return; } await runScopedOperation(busyScope.subscription(id), async()=>{showPolicyStatus({state:"applying",message:"正在更新订阅状态…"});await backend.setSubscriptionEnabled(sessionToken,id,enabled); setSubscriptions(await backend.listSubscriptions(sessionToken));await reloadRuntime(sessionToken);}); };
  const removeSubscription = async (id: string) => {
    if (!sessionToken) { setDialog("unlock"); return; }
    setRuntimeError("");
    try {
      await runScopedOperation(busyScope.subscription(id), async()=>{showPolicyStatus({state:"applying",message:"正在删除订阅并应用配置…"});await backend.deleteSubscription(sessionToken,id);
      setSubscriptions(await backend.listSubscriptions(sessionToken));
      try { await reloadRuntime(sessionToken); }
      catch (reason) { setRuntimeError(`订阅已删除，但保护配置重载失败：${String(reason)}`); }});
    } catch (reason) {
      setRuntimeError(`删除订阅失败：${String(reason)}`);
    }
  };
  const refreshSubscription=async(id:string)=>{if(!sessionToken){setDialog("unlock");return;}await runScopedOperation(busyScope.subscription(id), async()=>{setRefreshingId(id);showPolicyStatus({state:"applying",message:"正在更新订阅并应用配置…"});try{await backend.refreshSubscription(sessionToken,id);setSubscriptions(await backend.listSubscriptions(sessionToken));await reloadRuntime(sessionToken);}finally{setRefreshingId(null);}});};
  const clearLogs=async()=>{if(!sessionToken){setDialog("unlock");return;}await runScopedOperation(busyScope.logs, async()=>{await backend.clearAccessLogs(sessionToken);setAccessLogs([]);setAccessLogStats({block:0,allow:0,warning:0,total:0});});};
  const exportLogs=async()=>{if(!sessionToken){setDialog("unlock");return;}await runScopedOperation(busyScope.logs, async()=>{const csv=await backend.exportAccessLogsCsv(sessionToken);const url=URL.createObjectURL(new Blob([csv],{type:"text/csv;charset=utf-8"}));const link=document.createElement("a");link.href=url;link.download="cleanweb-access-logs.csv";link.click();URL.revokeObjectURL(url);});};
  const createParentRule=async(input:backend.NewParentRule)=>{if(!sessionToken)throw new Error("请先解锁管理台");await runScopedOperation(busyScope.createRule, async()=>{setRuntimeError("");showPolicyStatus({state:"applying",message:"正在保存并应用规则…"});await backend.createParentRule(sessionToken,input);setParentRules(await backend.listParentRules(sessionToken));setDialog(null);try{await reloadRuntime(sessionToken);}catch(reason){setRuntimeError(`规则已添加，但保护配置重载失败：${String(reason)}`);}});};
  const toggleParentRule=async(id:string,enabled:boolean)=>{if(!sessionToken){setDialog("unlock");return;}await runScopedOperation(busyScope.rule(id), async()=>{showPolicyStatus({state:"applying",message:"正在更新规则状态…"});await backend.setParentRuleEnabled(sessionToken,id,enabled);setParentRules(await backend.listParentRules(sessionToken));await reloadRuntime(sessionToken);});};
  const deleteParentRule=async(id:string)=>{if(!sessionToken){setDialog("unlock");return;}await runScopedOperation(busyScope.rule(id), async()=>{showPolicyStatus({state:"applying",message:"正在删除规则并应用配置…"});await backend.deleteParentRule(sessionToken,id);setParentRules(await backend.listParentRules(sessionToken));await reloadRuntime(sessionToken);});};
  const selectProxyNode=async(name:string)=>{if(!sessionToken){setDialog("unlock");return;}setRuntimeError("");try{showPolicyStatus({state:"applying",message:"正在切换代理节点…"});const result=await backend.selectProxy(sessionToken,"CleanWeb",name);if(result?.requiresReload)await reloadRuntime(sessionToken,{applyingMessage:"正在应用代理节点…"});else showPolicyStatus({state:"applied",message:"代理节点已切换"});setSettings(await backend.getSettings());}catch(reason){showPolicyStatus({state:"failed",message:`代理节点切换失败：${String(reason)}`});setRuntimeError(String(reason));throw reason;}};
  useEffect(()=>{if(!sessionToken)return;let cancelled=false;let unlisten:(()=>void)|undefined;const refresh=()=>void backend.syncAccessLogs().catch(()=>0).then(()=>Promise.all([backend.listAccessLogs(sessionToken,undefined,undefined,100),backend.getAccessLogStats(sessionToken)])).then(([logs,stats])=>{if(!cancelled){setAccessLogs(logs);setAccessLogStats(stats);}});refresh();void backend.onAccessLogsUpdated(refresh).then(stop=>{if(cancelled)stop();else unlisten=stop;});return()=>{cancelled=true;if(unlisten)unlisten();};},[sessionToken]);
  useEffect(()=>{if(sessionToken)return;let cancelled=false;let unlisten:(()=>void)|undefined;const refresh=()=>void backend.getPublicAccessLogStats().then(stats=>{if(!cancelled)setAccessLogStats(stats);});refresh();void backend.onAccessLogsUpdated(refresh).then(stop=>{if(cancelled)stop();else unlisten=stop;});return()=>{cancelled=true;if(unlisten)unlisten();};},[sessionToken]);
  if (!ready || !settings) return <div className="loading">正在读取 CleanWeb 配置…</div>;
  if (locked) return <LockedStatus coreStatus={coreStatus} stats={accessLogStats} runtimeError={runtimeError} needsSetup={needsSetup} onSetupComplete={() => setNeedsSetup(false)} onUnlock={handleUnlock} dialog={dialog} setDialog={setDialog} onHideToBackground={hideToBackground} onQuitApp={quitApp} />;
  return <div className="shell">
    <aside>
      <div className="brand"><ShieldCheck size={25}/><strong>CleanWeb</strong></div>
      <nav>
        <button className={page === "overview" ? "active" : ""} onClick={() => setPage("overview")}><Activity/>概览</button>
        <button className={page === "rules" ? "active" : ""} onClick={() => setPage("rules")}><BookOpen/>规则管理</button>
        <button className={page === "proxy" ? "active" : ""} onClick={() => setPage("proxy")}><Network/>代理节点</button>
      </nav>
      <div className={locked ? "locked" : "locked unlocked"} onClick={() => locked ? setDialog("unlock") : void handleLock()} role="button" aria-label={locked ? "点击解锁" : "点击锁定"} tabIndex={0} onKeyDown={(e)=>{if(e.key==="Enter"||e.key===" ")locked?setDialog("unlock"):void handleLock();}}><LockKeyhole size={18}/><div><b>{locked ? "管理台已锁定" : "管理台已解锁"}</b><span>{locked ? "点击解锁" : "点击锁定"}</span></div></div>
      <div className="sidebar-version">CleanWeb v0.1.0</div>
    </aside>
    <main>
      <header><div><span className="eyebrow">网络保护</span><h1>{titles[page]}</h1></div></header>
      {runtimeError&&<div className="runtime-error" role="alert">{runtimeError}</div>}
      {policyApplyStatus&&<PolicyApplyBanner status={policyApplyStatus}/>}
      {page === "overview" && <Overview settings={settings} coreStatus={coreStatus} locked={locked} isBusy={isBusy} logs={accessLogs} logStats={accessLogStats} onClear={clearLogs} onExport={exportLogs} onToggle={toggle} onRetention={(value) => setValue("log_retention", value)} />}
      {page === "rules" && <Rules parentRules={parentRules} subscriptions={subscriptions.filter((item)=>item.kind==="rule")} refreshingId={refreshingId} isBusy={isBusy} onRefresh={refreshSubscription} onToggleParentRule={toggleParentRule} onDeleteParentRule={deleteParentRule} onAddParentRule={(mode)=>{setParentRuleMode(mode);locked?setDialog("unlock"):setDialog("custom");}} onToggleSubscription={toggleSubscription} onDelete={removeSubscription} onEdit={(item)=>{setEditingSubscription(item);setDialog("editRuleSubscription");}} onAdd={() => requestAction("rules")} />}
      {page === "proxy" && <Proxy subscriptions={subscriptions.filter((item)=>item.kind==="proxy")} refreshingId={refreshingId} isBusy={isBusy} onRefresh={refreshSubscription} onToggleSubscription={toggleSubscription} onDelete={removeSubscription} onAdd={(mode) => requestAction("proxy", mode)} coreStatus={coreStatus} automatic={settings.automaticNodeSelection} onAutomatic={()=>setValue("automatic_node_selection","true")} onSelectNode={selectProxyNode} sessionToken={sessionToken} />}
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
  </div>;
}

function LockedStatus({ coreStatus, stats, runtimeError, needsSetup, onSetupComplete, onUnlock, dialog, setDialog, onHideToBackground, onQuitApp }: { coreStatus:backend.CoreStatus|null;stats:backend.AccessLogStats;runtimeError:string;needsSetup:boolean;onSetupComplete:()=>void;onUnlock:(password:string)=>Promise<void>;dialog:AppDialog;setDialog:(dialog:AppDialog)=>void;onHideToBackground:()=>Promise<void>;onQuitApp:()=>Promise<void> }) {
  const running = coreStatus?.running === true;
  return <div className="locked-shell">
    <section className="locked-status-card" aria-label="CleanWeb 锁定状态">
      <div className="locked-status-head">
        <div className={running ? "locked-status-icon" : "locked-status-icon off"}><ShieldCheck size={26}/></div>
        <div><span className={running ? "status" : "status off"}>{running ? "保护运行中" : "保护未运行"}</span><h1>CleanWeb</h1></div>
      </div>
      {runtimeError && <div className="runtime-error compact" role="alert">{runtimeError}</div>}
      <div className="locked-status-stats">
        <article><span>已拦截</span><strong>{stats.block}</strong></article>
        <article><span>已允许</span><strong>{stats.allow}</strong></article>
        <article><span>总请求</span><strong>{stats.total}</strong></article>
      </div>
      <button className="primary full" onClick={()=>setDialog("unlock")}><LockKeyhole size={16}/>点击解锁</button>
    </section>
    <div className="locked-version">CleanWeb v0.1.0</div>
    {needsSetup && <SetupDialog onComplete={onSetupComplete} />}
    {dialog === "unlock" && <UnlockDialog onClose={() => setDialog(null)} onUnlock={onUnlock} />}
    {dialog === "quit" && <QuitConfirmDialog running={running} onClose={()=>setDialog(null)} onHideToBackground={onHideToBackground} onQuitApp={onQuitApp}/>}
  </div>;
}

function QuitConfirmDialog({ running, onClose, onHideToBackground, onQuitApp }: { running:boolean; onClose:()=>void; onHideToBackground:()=>Promise<void>; onQuitApp:()=>Promise<void> }) {
  const [error,setError]=useState("");
  const [submitting,setSubmitting]=useState(false);
  const submitQuit=async(event:FormEvent<HTMLFormElement>)=>{
    event.preventDefault();
    if(submitting)return;
    setSubmitting(true);
    setError("");
    try{
      const password=String(new FormData(event.currentTarget).get("password")??"");
      await backend.verifyPassword(password);
      await onQuitApp();
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
      <h2 id="quit-title">{running?"保护仍会在后台运行":"确认关闭 CleanWeb"}</h2>
      <p>{running?"当前保护和代理由后台服务继续执行。关闭窗口或退出管理界面不会自动停止网络接管；如需停止，请先解锁并关闭总保护。":"当前没有运行中的保护服务。你可以关闭窗口到后台，或退出 CleanWeb 管理界面。"}</p>
      {running&&<div className="quit-status" role="status"><b>后台保护运行中</b><span>退出应用后，代理和过滤仍可能继续生效。</span></div>}
      <form onSubmit={submitQuit}>
        <label htmlFor="quit-password">管理密码</label>
        <input id="quit-password" name="password" type="password" placeholder="输入管理密码后退出" required autoFocus autoComplete="current-password" onKeyDown={(e) => { if (e.nativeEvent.isComposing || e.keyCode === 229) e.preventDefault(); }} onCompositionEnd={(e) => { const el = e.currentTarget; el.value = el.value.replace(/[^\x20-\x7E]/g, ""); }} onInput={(e) => { const el = e.currentTarget; el.value = el.value.replace(/[^\x20-\x7E]/g, ""); }} />
        {error&&<span className="form-error">{error}</span>}
        <div className="modal-actions">
          <button type="button" className="secondary" onClick={onClose}>取消</button>
          <button type="button" className="secondary" onClick={()=>void onHideToBackground()}>继续后台运行</button>
          <button type="submit" className="primary danger" disabled={submitting}>{submitting?"验证中…":"退出"}</button>
        </div>
      </form>
    </section>
  </div>;
}

function Overview({ settings, coreStatus, locked, isBusy, logs, logStats, onClear, onExport, onToggle, onRetention }: { settings: backend.Settings; coreStatus:backend.CoreStatus|null;locked:boolean;isBusy:(scope:string)=>boolean;logs:backend.AccessLog[];logStats:backend.AccessLogStats;onClear:()=>Promise<void>;onExport:()=>Promise<void>; onToggle: (key: string, enabled: boolean) => Promise<void>; onRetention: (value: string) => Promise<void> }) {
  const running=coreStatus?.running===true;
  const protectionMessage = running
    ? `保护服务 PID ${coreStatus?.pid} · 安全 DNS 已配置`
    : settings.protectionEnabled
      ? "配置要求保护开启，但服务当前未运行；点击开关重新启动保护"
      : "当前网络未被 Clean Web 接管";
  const blockedCount = logStats.block;
  const allowedCount = logStats.allow;
  const totalCount = logStats.total;
  return <>
      <section className={running ? "hero" : "hero off"}>
        <div className={running ? "pulse" : "pulse off"}><ShieldCheck size={34}/>{!running&&<X className="pulse-x" size={19}/>}</div>
        <div className="hero-copy"><span className={running ? "status" : "status off"}>{running ? "保护运行中" : "保护未运行"}</span><h2>{running ? "Clean Web 正在执行网络策略" : "开启后将启动保护并接管网络"}</h2><p>{protectionMessage}</p></div>
        <Switch checked={running} label="总保护" disabled={isBusy(busyScope.protection)} onChange={(value) => onToggle("protection_enabled", value)} />
      </section>
      <section className="stats">
        <article><span>已拦截</span><strong>{blockedCount}</strong><small>访问日志总计</small></article>
        <article><span>已允许</span><strong>{allowedCount}</strong><small>正常访问请求</small></article>
        <article><span>总请求</span><strong>{totalCount}</strong><small>监控期间总计</small></article>
      </section>
      <section className="setting-grid">
        <SettingCard title="网络代理" note="由管理者决定是否使用代理节点"><Switch checked={settings.proxyEnabled} label="代理" disabled={isBusy(busyScope.setting("proxy_enabled"))} onChange={(value) => onToggle("proxy_enabled", value)} /></SettingCard>
        <SettingCard title="自动选择节点" note="根据延迟与可用性自动选择"><Switch checked={settings.automaticNodeSelection} label="自动选点" disabled={isBusy(busyScope.setting("automatic_node_selection"))} onChange={(value) => onToggle("automatic_node_selection", value)} /></SettingCard>
        <SettingCard title="安全搜索" note="强制 Google、Bing、YouTube 使用安全模式"><Switch checked={settings.safeSearchEnabled} label="安全搜索" disabled={isBusy(busyScope.setting("safe_search_enabled"))} onChange={(value) => onToggle("safe_search_enabled", value)} /></SettingCard>
        <SettingCard title="严格模式" note="追加明确高风险后缀、关键词和地址段"><Switch checked={settings.strictModeEnabled} label="严格模式" disabled={isBusy(busyScope.setting("strict_mode_enabled"))} onChange={(value) => onToggle("strict_mode_enabled", value)} /></SettingCard>
        <SettingCard title="访问日志" note="本地存储"><div className="inline-control"><select aria-label="日志保留时间" value={settings.logRetention} disabled={isBusy(busyScope.setting("log_retention"))} onChange={(event) => void onRetention(event.target.value)}><option value="7d">7天</option><option value="30d">30天</option><option value="90d">90天</option><option value="forever">永久</option></select><Switch checked={settings.accessLoggingEnabled} label="日志" disabled={isBusy(busyScope.setting("access_logging_enabled"))} onChange={(value) => onToggle("access_logging_enabled", value)} /></div></SettingCard>
      </section>
      <section className="panel log-panel"><div className="panel-heading"><div><span className="eyebrow">最近事件</span><h3>访问记录</h3></div><div><button className="secondary" disabled={isBusy(busyScope.logs)} onClick={()=>void onExport()}>导出 CSV</button><button className="secondary danger" disabled={isBusy(busyScope.logs)} onClick={()=>void onClear()}>清空</button></div></div>{locked?<div className="empty">解锁管理台后查看访问详情</div>:logs.length===0?<div className="empty">暂无真实网络事件</div>:<div className="log-table">{logs.map(log=><div className="log-row" key={log.id}><span className={`decision ${log.decision}`}>{log.decision==="block"?"已阻止":log.decision==="warning"?"警告":"允许"}</span><div><b>{log.domain??log.targetIp??"未知目标"}</b><small>{log.processName??"未知进程"} · {log.rule??"未命中规则"}</small></div><span>{log.targetIp}{log.targetPort?`:${log.targetPort}`:""}</span><time>{new Date(log.observedAt).toLocaleString()}</time></div>)}</div>}</section>
  </>;
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
  const builtinSubscriptions = subscriptions.filter((item) => item.id.startsWith("default:"));
  const externalSubscriptions = subscriptions.filter((item) => !item.id.startsWith("default:"));
  const blockRules = parentRules.filter((item) => item.action === "block");
  const routeRules = parentRules.filter((item) => item.action !== "block");
  const subscriptionFormat = (item: backend.Subscription) => item.format ?? "自动检测";
  const updateInterval = (item: backend.Subscription) => item.updateIntervalHours ? `${item.updateIntervalHours}小时更新` : "手动更新";
  const matchKindLabel = (kind: string) => ({exact:"精确域名",suffix:"域名及子域名",contains:"关键词",wildcard:"通配符",regex:"正则",ip:"IP地址",cidr:"IP网段"}[kind] ?? kind);
  const ruleActionLabel = (action: backend.ParentRule["action"]) => action === "block" ? "拦截" : action === "proxy" ? "走代理" : "直连";
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
    {tab==="route"&&<><section className="toolbar"><div><h2>路由设置</h2><p>为指定目标选择直连或走代理；安全和拦截规则仍然拥有更高优先级。</p></div><button className="primary" disabled={isBusy(busyScope.createRule)} onClick={()=>onAddParentRule("route")}><Plus size={16}/>添加路由</button></section>
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
    let failedCount = 0;
    try {
      for (const node of nodes) {
        setTestingNodeName(node.name);
        try {
          const delay = await backend.testProxyGroup(sessionToken, node.name);
          setDelays(previous => ({ ...previous, [node.name]: delay }));
        } catch {
          failedCount += 1;
          setDelays(previous => ({ ...previous, [node.name]: 0 }));
        }
      }
      if (failedCount > 0) setDelayError(`部分节点检测失败：${failedCount}/${nodes.length}`);
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
    if(selectingRef.current||testingSpeed)return;
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
  },[onSelectNode,runtimeSelection,testingSpeed]);
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
                      return <SubProxyNodeButton key={p.name} name={p.name} nodeType={p.nodeType} isMember={isMember} isCurrent={isCurrent} isChoosing={isChoosing} isTesting={isTesting} delay={findDelay(p.name)} disabled={!isMember||itemBusy||testingSpeed} onChoose={chooseNode} />;
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
  return <div className="modal-backdrop" onMouseDown={event=>event.target===event.currentTarget&&onClose()}><section className="modal" role="dialog" aria-modal="true" aria-labelledby="parent-rule-title"><button className="icon-button" aria-label="关闭" onClick={onClose}><X size={18}/></button><h2 id="parent-rule-title">{isRoute?"添加路由规则":"添加拦截规则"}</h2><p>{isRoute?"为匹配目标指定直连或走代理；高风险安全与手动拦截仍会优先生效。":"手动阻止指定目标；诈骗、钓鱼和恶意软件仍保持最高优先级。"}</p><form onSubmit={async event=>{event.preventDefault();const data=new FormData(event.currentTarget);setError("");try{await onSubmit({action:String(data.get("action")) as "allow"|"block"|"proxy",kind:String(data.get("kind")),pattern:String(data.get("pattern")),category:String(data.get("category")||"custom")});}catch(reason){setError(String(reason));}}}><label htmlFor="parent-action">{isRoute?"出口":"动作"}</label>{isRoute?<select id="parent-action" name="action"><option value="allow">直连</option><option value="proxy">走代理</option></select>:<><input type="hidden" name="action" value="block"/><div className="readonly-field">拦截</div></>}<label htmlFor="parent-kind">匹配方式</label><select id="parent-kind" name="kind"><option value="suffix">域名及子域名</option><option value="exact">精确域名</option><option value="ip">IP地址</option><option value="cidr">IP网段</option><option value="contains">关键词包含</option><option value="wildcard">通配符</option><option value="regex">正则表达式</option></select><label htmlFor="parent-pattern">规则内容</label><input id="parent-pattern" name="pattern" placeholder="example.com 或 47.96.0.0/12" required autoComplete="off" spellCheck={false}/><input type="hidden" name="category" value={isRoute?"routing":"custom"}/>{error&&<span className="form-error">{error}</span>}<div className="modal-actions"><button type="button" className="secondary" onClick={onClose}>取消</button><button className="primary" type="submit">验证并保存</button></div></form></section></div>;
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
        {kind==="规则"&&<><label htmlFor="subscription-category">分类</label><select id="subscription-category" name="category" defaultValue={subscription?.category??"custom"}><option value="custom">自定义</option><option value="pornography">色情与擦边</option><option value="gambling">赌博</option><option value="malware">恶意软件</option><option value="ads">广告</option></select></>}
        <label htmlFor="subscription-interval">更新周期</label><select id="subscription-interval" name="interval" defaultValue={defaultInterval}><option value="6">每6小时</option><option value="12">每12小时</option><option value="24">每天</option><option value="168">每7天</option></select>
        {error&&<span className="form-error">{error}</span>}
        <div className="modal-actions"><button type="button" className="secondary" onClick={onClose}>取消</button><button className="primary" type="submit">{editing?"保存修改":"验证并添加"}</button></div>
      </form>
    </section>
  </div>;
}

import { useEffect, useRef, useState } from "react";
import { Activity, BookOpen, ChevronDown, ChevronRight, Gauge, LockKeyhole, Network, Plus, RefreshCw, ShieldCheck, Trash2, X } from "lucide-react";
import * as backend from "./backend";

export function App() {
  const [page, setPage] = useState<"overview" | "rules" | "proxy">("overview");
  const [locked, setLocked] = useState(false); // TODO: 测试期间默认解锁，上线前恢复 true
  const [dialog, setDialog] = useState<"unlock" | "rules" | "proxy" | "custom" | null>(null);
  const [needsSetup, setNeedsSetup] = useState(false);
  const [ready, setReady] = useState(false);
  const [sessionToken, setSessionToken] = useState<string | null>("dev"); // TODO: 测试期间使用虚拟 token，上线前恢复 null
  const [settings, setSettings] = useState<backend.Settings | null>(null);
  const [subscriptions, setSubscriptions] = useState<backend.Subscription[]>([]);
  const [refreshingId,setRefreshingId]=useState<string|null>(null);
  const [coreStatus,setCoreStatus]=useState<backend.CoreStatus|null>(null);
  const [runtimeError,setRuntimeError]=useState("");
  const [accessLogs,setAccessLogs]=useState<backend.AccessLog[]>([]);
  const [parentRules,setParentRules]=useState<backend.ParentRule[]>([]);
  const titles = { overview: "网络环境安全", rules: "规则管理", proxy: "代理节点" };
  const requestAction = (action: "rules" | "proxy") => setDialog(locked ? "unlock" : action);
  useEffect(() => { Promise.all([backend.getBootstrapState(), backend.getSettings(), backend.listSubscriptions(),backend.getCoreStatus(),backend.listParentRules()]).then(([bootstrap, current, saved,core,rules]) => {
    setNeedsSetup(!bootstrap.passwordConfigured); setSettings(current); setSubscriptions(saved);setCoreStatus(core);setParentRules(rules); setReady(true);
    if(current.protectionEnabled&&!core.running)void backend.autoStartProtection().then(setCoreStatus).catch(reason=>setRuntimeError(String(reason)));
  }); }, []);
  useEffect(()=>{const timer=window.setInterval(()=>void backend.getCoreStatus().then(setCoreStatus),5000);return()=>window.clearInterval(timer);},[]);
  useEffect(()=>{void backend.refreshDueSubscriptions().then(()=>backend.listSubscriptions()).then(setSubscriptions);const timer=window.setInterval(()=>{void backend.refreshDueSubscriptions().then(()=>backend.listSubscriptions()).then(setSubscriptions);},15*60*1000);return()=>window.clearInterval(timer);},[]);
  const handleUnlock = async (password: string) => { const result = await backend.unlock(password); setSessionToken(result.sessionToken);setAccessLogs(await backend.listAccessLogs(result.sessionToken,undefined,undefined,100)); setLocked(false); setDialog(null); };
  const handleLock = async () => { if (sessionToken) await backend.lock(sessionToken); setSessionToken(null); setLocked(true); };
  const setValue = async (key: string, value: string) => {
    if (!sessionToken) { setDialog("unlock"); return; }
    setRuntimeError("");
    try {
      if(key==="protection_enabled"){const core=value==="true"?await backend.startProtection(sessionToken):await backend.stopProtection(sessionToken);setCoreStatus(core);}
      setSettings(await backend.updateSetting(sessionToken, key, value));
    } catch(reason) { setRuntimeError(String(reason)); }
  };
  const toggle = (key: string, enabled: boolean) => setValue(key, String(enabled));
  const createSubscription = async (input: backend.NewSubscription) => {
    if (!sessionToken) throw new Error("请先解锁管理台");
    const item=await backend.createSubscription(sessionToken, input);
    try { await backend.refreshSubscription(sessionToken,item.id); } catch(reason) { await backend.deleteSubscription(sessionToken,item.id); throw reason; }
    setSubscriptions(await backend.listSubscriptions()); setDialog(null);
  };
  const toggleSubscription = async (id: string, enabled: boolean) => { if (!sessionToken) { setDialog("unlock"); return; } await backend.setSubscriptionEnabled(sessionToken,id,enabled); setSubscriptions(await backend.listSubscriptions()); };
  const removeSubscription = async (id: string) => { if (!sessionToken) { setDialog("unlock"); return; } await backend.deleteSubscription(sessionToken,id); setSubscriptions(await backend.listSubscriptions()); };
  const refreshSubscription=async(id:string)=>{if(!sessionToken){setDialog("unlock");return;}setRefreshingId(id);try{await backend.refreshSubscription(sessionToken,id);setSubscriptions(await backend.listSubscriptions());}finally{setRefreshingId(null);}};
  const clearLogs=async()=>{if(!sessionToken){setDialog("unlock");return;}await backend.clearAccessLogs(sessionToken);setAccessLogs([]);};
  const exportLogs=async()=>{if(!sessionToken){setDialog("unlock");return;}const csv=await backend.exportAccessLogsCsv(sessionToken);const url=URL.createObjectURL(new Blob([csv],{type:"text/csv;charset=utf-8"}));const link=document.createElement("a");link.href=url;link.download="cleanweb-access-logs.csv";link.click();URL.revokeObjectURL(url);};
  const createParentRule=async(input:backend.NewParentRule)=>{if(!sessionToken)throw new Error("请先解锁管理台");await backend.createParentRule(sessionToken,input);setParentRules(await backend.listParentRules());setDialog(null);};
  const toggleParentRule=async(id:string,enabled:boolean)=>{if(!sessionToken){setDialog("unlock");return;}await backend.setParentRuleEnabled(sessionToken,id,enabled);setParentRules(await backend.listParentRules());};
  const deleteParentRule=async(id:string)=>{if(!sessionToken){setDialog("unlock");return;}await backend.deleteParentRule(sessionToken,id);setParentRules(await backend.listParentRules());};
  useEffect(()=>{if(!sessionToken)return;const refresh=()=>void backend.syncAccessLogs().then(()=>backend.listAccessLogs(sessionToken,undefined,undefined,100)).then(setAccessLogs);refresh();const timer=window.setInterval(refresh,3000);return()=>window.clearInterval(timer);},[sessionToken]);
  if (!ready || !settings) return <div className="loading">正在读取 CleanWeb 配置…</div>;
  return <div className="shell">
    <aside>
      <div className="brand"><ShieldCheck size={25}/><strong>CleanWeb</strong></div>
      <nav>
        <button className={page === "overview" ? "active" : ""} onClick={() => setPage("overview")}><Activity/>概览</button>
        <button className={page === "rules" ? "active" : ""} onClick={() => setPage("rules")}><BookOpen/>规则管理</button>
        <button className={page === "proxy" ? "active" : ""} onClick={() => setPage("proxy")}><Network/>代理节点</button>
      </nav>
      <div className={locked ? "locked" : "locked unlocked"} onClick={() => locked ? setDialog("unlock") : void handleLock()} role="button" aria-label={locked ? "点击解锁" : "点击锁定"} tabIndex={0} onKeyDown={(e)=>{if(e.key==="Enter"||e.key===" ")locked?setDialog("unlock"):void handleLock();}}><LockKeyhole size={18}/><div><b>{locked ? "管理台已锁定" : "管理台已解锁"}</b><span>{locked ? "点击解锁" : "点击锁定"}</span></div></div>
    </aside>
    <main>
      <header><div><span className="eyebrow">家庭网络保护</span><h1>{titles[page]}</h1></div></header>
      {runtimeError&&<div className="runtime-error" role="alert">{runtimeError}</div>}
      {page === "overview" && <Overview settings={settings} coreStatus={coreStatus} locked={locked} logs={accessLogs} onClear={clearLogs} onExport={exportLogs} onToggle={toggle} onRetention={(value) => setValue("log_retention", value)} />}
      {page === "rules" && <Rules parentRules={parentRules} subscriptions={subscriptions.filter((item)=>item.kind==="rule")} refreshingId={refreshingId} onRefresh={refreshSubscription} onToggleParentRule={toggleParentRule} onDeleteParentRule={deleteParentRule} onAddParentRule={()=>locked?setDialog("unlock"):setDialog("custom")} onToggleSubscription={toggleSubscription} onDelete={removeSubscription} onAdd={() => requestAction("rules")} />}
      {page === "proxy" && <Proxy subscriptions={subscriptions.filter((item)=>item.kind==="proxy")} refreshingId={refreshingId} onRefresh={refreshSubscription} onToggleSubscription={toggleSubscription} onDelete={removeSubscription} onAdd={() => requestAction("proxy")} coreStatus={coreStatus} locked={locked} />}
    </main>
    {needsSetup && <SetupDialog onComplete={() => setNeedsSetup(false)} />}
    {dialog === "unlock" && <UnlockDialog onClose={() => setDialog(null)} onUnlock={handleUnlock} />}
    {dialog === "rules" && <SubscriptionDialog kind="规则" onClose={() => setDialog(null)} onSubmit={createSubscription} />}
    {dialog === "proxy" && <SubscriptionDialog kind="代理" onClose={() => setDialog(null)} onSubmit={createSubscription} />}
    {dialog === "custom" && <ParentRuleDialog onClose={()=>setDialog(null)} onSubmit={createParentRule}/>} 
  </div>;
}

function Overview({ settings, coreStatus, locked, logs, onClear, onExport, onToggle, onRetention }: { settings: backend.Settings; coreStatus:backend.CoreStatus|null;locked:boolean;logs:backend.AccessLog[];onClear:()=>Promise<void>;onExport:()=>Promise<void>; onToggle: (key: string, enabled: boolean) => Promise<void>; onRetention: (value: string) => Promise<void> }) {
  const running=coreStatus?.running===true;
  return <>
      <section className="hero">
        <div className="pulse"><ShieldCheck size={34}/></div>
        <div className="hero-copy"><span className={running ? "status" : "status off"}>{running ? "保护运行中" : "保护未运行"}</span><h2>{running ? "Mihomo TUN 正在执行网络策略" : "开启后将启动内核并接管网络"}</h2><p>{running?`内核 PID ${coreStatus?.pid} · fake-IP DNS 已配置`:settings.protectionEnabled?"配置要求保护开启，但内核当前未运行":"当前网络未被 CleanWeb 接管"}</p></div>
        <Switch checked={settings.protectionEnabled} label="总保护" onChange={(value) => onToggle("protection_enabled", value)} />
      </section>
      <section className="setting-grid">
        <SettingCard title="网络代理" note="由家长决定是否使用代理节点"><Switch checked={settings.proxyEnabled} label="代理" onChange={(value) => onToggle("proxy_enabled", value)} /></SettingCard>
        <SettingCard title="自动选择节点" note="根据延迟与可用性自动选择"><Switch checked={settings.automaticNodeSelection} label="自动选点" onChange={(value) => onToggle("automatic_node_selection", value)} /></SettingCard>
        <SettingCard title="安全搜索" note="强制 Google、Bing、YouTube 使用安全模式"><Switch checked={settings.safeSearchEnabled} label="安全搜索" onChange={(value) => onToggle("safe_search_enabled", value)} /></SettingCard>
        <SettingCard title="访问日志" note="本地存储"><div className="inline-control"><select aria-label="日志保留时间" value={settings.logRetention} onChange={(event) => void onRetention(event.target.value)}><option value="7d">7天</option><option value="30d">30天</option><option value="90d">90天</option><option value="forever">永久</option></select><Switch checked={settings.accessLoggingEnabled} label="日志" onChange={(value) => onToggle("access_logging_enabled", value)} /></div></SettingCard>
      </section>
      <section className="panel log-panel"><div className="panel-heading"><div><span className="eyebrow">最近事件</span><h3>访问记录</h3></div><div><button className="secondary" onClick={()=>void onExport()}>导出 CSV</button><button className="secondary danger" onClick={()=>void onClear()}>清空</button></div></div>{locked?<div className="empty">解锁管理台后查看访问详情</div>:logs.length===0?<div className="empty">暂无真实网络事件</div>:<div className="log-table">{logs.map(log=><div className="log-row" key={log.id}><span className={`decision ${log.decision}`}>{log.decision==="block"?"已阻止":log.decision==="warning"?"警告":"允许"}</span><div><b>{log.domain??log.targetIp??"未知目标"}</b><small>{log.processName??"未知进程"} · {log.rule??"未命中规则"}</small></div><span>{log.targetIp}{log.targetPort?`:${log.targetPort}`:""}</span><time>{new Date(log.observedAt).toLocaleString()}</time></div>)}</div>}</section>
  </>;
}

function SettingCard({ title, note, children }: { title: string; note: string; children: React.ReactNode }) { return <article className="setting-card"><div><b>{title}</b><span>{note}</span></div>{children}</article>; }
function Switch({ checked, label, onChange }: { checked: boolean; label: string; onChange: (value: boolean) => void }) { return <button type="button" role="switch" aria-label={label} aria-checked={checked} className={`switch ${checked ? "on" : ""}`} onClick={() => onChange(!checked)}><span/></button>; }

function Rules({ parentRules, subscriptions, refreshingId, onRefresh, onToggleParentRule, onDeleteParentRule, onAddParentRule, onToggleSubscription, onDelete, onAdd }: { parentRules:backend.ParentRule[]; subscriptions: backend.Subscription[]; refreshingId:string|null; onRefresh:(id:string)=>Promise<void>;onToggleParentRule:(id:string,enabled:boolean)=>Promise<void>;onDeleteParentRule:(id:string)=>Promise<void>;onAddParentRule:()=>void; onToggleSubscription:(id:string,enabled:boolean)=>Promise<void>; onDelete:(id:string)=>Promise<void>; onAdd: () => void }) {
  return <>
    <section className="toolbar"><div><h2>家庭自定义规则</h2><p>家长黑白名单优先于普通内容和第三方订阅规则。</p></div><button className="primary" onClick={onAddParentRule}><Plus size={16}/>添加规则</button></section>
    <section className="table-card parent-rules"><div className="table-head"><span>规则</span><span>动作</span><span>状态</span><span>操作</span></div>{parentRules.length===0&&<div className="table-empty">尚未添加家庭规则</div>}{parentRules.map(item=><div className="table-row" key={item.id}><div><b>{item.pattern}</b><small>{item.kind} · {item.category}</small></div><span className={`rule-action ${item.action}`}>{item.action==="block"?"拦截":item.action==="proxy"?"代理放行":"直连放行"}</span><Switch checked={item.enabled} label={`${item.pattern}规则`} onChange={value=>void onToggleParentRule(item.id,value)}/><button className="row-action" aria-label={`删除${item.pattern}`} onClick={()=>void onDeleteParentRule(item.id)}><Trash2 size={15}/></button></div>)}</section>
    <section className="toolbar"><div><h2>规则来源</h2><p>标准化并合并多个来源，保留每条规则的出处。</p></div><button className="primary" onClick={onAdd}><Plus size={16}/>添加订阅</button></section>
    <section className="table-card">
      <div className="table-head"><span>名称</span><span>格式</span><span>状态</span><span>操作</span></div>
      {subscriptions.length === 0 && <div className="table-empty">尚未添加规则订阅</div>}
      {subscriptions.map((item) => <div className="table-row" key={item.id}><div><b>{item.name}</b><small className={item.lastError?"error-text":""}>{item.lastError??item.url}</small></div><span>{item.format ?? "自动检测"}</span><Switch checked={item.enabled} label={`${item.name}订阅`} onChange={(value)=>void onToggleSubscription(item.id,value)}/><div className="row-actions"><button className="row-action" aria-label={`更新${item.name}`} disabled={refreshingId===item.id} onClick={()=>void onRefresh(item.id)}><RefreshCw size={15}/></button><button className="row-action" aria-label={`删除${item.name}`} onClick={()=>void onDelete(item.id)}><Trash2 size={15}/></button></div></div>)}
    </section>
    <section className="hint"><ShieldCheck size={19}/><div><b>匹配能力</b><p>支持精确域名、域名后缀、关键词、通配符、正则表达式、IP 与 CIDR。</p></div></section>
  </>;
}

function Proxy({ subscriptions, refreshingId, onRefresh, onToggleSubscription, onDelete, onAdd, coreStatus, locked }: { subscriptions:backend.Subscription[]; refreshingId:string|null; onRefresh:(id:string)=>Promise<void>; onToggleSubscription:(id:string,enabled:boolean)=>Promise<void>; onDelete:(id:string)=>Promise<void>; onAdd: () => void; coreStatus:backend.CoreStatus|null; locked:boolean }) {
  const [groups, setGroups] = useState<backend.ProxyGroup[]>([]);
  const running = coreStatus?.running === true;
  const [expandedId, setExpandedId] = useState<string|null>(null);
  const [subProxies, setSubProxies] = useState<Record<string, backend.SubscriptionProxyInfo>>({});
  const [selectedGroup, setSelectedGroup] = useState<string|null>(null);
  const [delays, setDelays] = useState<Record<string, number>>({});
  const [testingSpeed, setTestingSpeed] = useState(false);
  const refreshProxies = () => { if (running) void backend.getProxies().then(setGroups).catch(() => {}); };
  useEffect(() => { refreshProxies(); const timer = running ? window.setInterval(refreshProxies, 10000) : 0; return () => { if (timer) window.clearInterval(timer); }; }, [running]);
  useEffect(() => { if (refreshingId) setSubProxies(prev => { const next = { ...prev }; delete next[refreshingId]; return next; }); }, [refreshingId]);
  useEffect(() => { const ids = new Set(subscriptions.map(s => s.id)); setSubProxies(prev => { const next: Record<string, backend.SubscriptionProxyInfo> = {}; for (const [k, v] of Object.entries(prev)) if (ids.has(k)) next[k] = v; return next; }); }, [subscriptions]);
  const handleSelect = async (group: string, name: string) => { if (locked) return; try { await backend.selectProxy(group, name); refreshProxies(); } catch (reason) { console.error(reason); } };
  const toggleExpand = async (id: string) => {
    if (expandedId === id) { setExpandedId(null); setSelectedGroup(null); return; }
    setExpandedId(id); setSelectedGroup(null);
    if (!subProxies[id]) {
      try { const info = await backend.getSubscriptionProxies(id); setSubProxies(prev => ({ ...prev, [id]: info })); } catch (reason) { console.error(reason); }
    }
  };
  const handleSpeedTest = async () => {
    if (!running || testingSpeed) return;
    setTestingSpeed(true);
    try {
      const result = await backend.testAllProxyDelays();
      setDelays(result.delays);
      refreshProxies();
    } catch (reason) { console.error(reason); }
    finally { setTestingSpeed(false); }
  };
  const delayLabel = (d: number | undefined) => {
    if (d == null) return null;
    if (d === 0) return { text: "超时", cls: "timeout" };
    if (d < 200) return { text: `${d}ms`, cls: "fast" };
    if (d < 500) return { text: `${d}ms`, cls: "medium" };
    return { text: `${d}ms`, cls: "slow" };
  };
  return <>
    <section className="toolbar"><div><h2>家长管理的代理</h2><p>导入代理订阅，仅提取节点和代理组，自动过滤不相关的网络配置。</p></div><button className="primary" onClick={onAdd}><Plus size={16}/>导入订阅</button></section>
    {subscriptions.length===0 ? <section className="proxy-card empty-proxy">尚未导入代理订阅</section> : subscriptions.map((item)=>{
      const expanded = expandedId === item.id;
      const info = subProxies[item.id];
      const currentGroup = selectedGroup != null ? info?.groups.find(g => g.name === selectedGroup) : null;
      const memberSet = currentGroup ? new Set(currentGroup.members) : null;
      const typeSummary = info ? Object.entries(info.proxies.reduce<Record<string,number>>((acc, p) => { acc[p.nodeType] = (acc[p.nodeType]||0)+1; return acc; }, {})).sort((a,b) => b[1]-a[1]).map(([t,c]) => ({ type: t, count: c })) : [];
      return <section className={`proxy-card${expanded ? " expanded" : ""}`} key={item.id}>
        <div className="proxy-card-header" onClick={()=>void toggleExpand(item.id)} role="button" tabIndex={0} onKeyDown={(e)=>{if(e.key==="Enter"||e.key===" ")void toggleExpand(item.id);}}>
          <div className="proxy-icon"><Network/></div>
          <div className="proxy-info">
            <div className="proxy-meta-row">
              <span className="status">代理订阅{info ? ` · ${info.proxies.length} 节点${info.groups.length > 0 ? ` · ${info.groups.length} 组` : ""}` : ""}</span>
              {typeSummary.length > 0 && <div className="proxy-type-badges">{typeSummary.map(t => <span className="proxy-type-badge" key={t.type}><span className="proxy-type-name">{t.type.toUpperCase()}</span><span className="proxy-type-count">{t.count}</span></span>)}</div>}
            </div>
            <h3>{item.name}</h3><p className={item.lastError?"error-text":""}>{item.lastError??item.url}</p></div>
          <div className="proxy-actions" onClick={(e)=>e.stopPropagation()}>
            <Switch checked={item.enabled} label={`${item.name}订阅`} onChange={(value)=>void onToggleSubscription(item.id,value)}/>
            <button className="row-action" aria-label={`更新${item.name}`} disabled={refreshingId===item.id} onClick={()=>void onRefresh(item.id)}><RefreshCw size={15}/></button>
            <button className="row-action" aria-label={`删除${item.name}`} onClick={()=>void onDelete(item.id)}><Trash2 size={15}/></button>
          </div>
          <span className="expand-chevron">{expanded ? <ChevronDown size={18}/> : <ChevronRight size={18}/>}</span>
        </div>
        {expanded && info && <div className="proxy-card-body">
          {info.proxies.length === 0 && info.groups.length === 0
            ? <div className="sub-proxy-empty">该订阅未解析到代理节点</div>
            : <div className="sub-proxy-layout">
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
                    <h4>{currentGroup ? `${currentGroup.name} 节点` : "节点列表"}</h4>
                    {running && <button className={`speed-test-btn${testingSpeed ? " testing" : ""}`} disabled={testingSpeed} onClick={handleSpeedTest}><Gauge size={14}/>{testingSpeed ? "测速中…" : "网速检测"}</button>}
                  </div>
                  <div className="sub-proxy-grid">
                    {info.proxies.map(p => {
                      const isMember = memberSet ? memberSet.has(p.name) : true;
                      const dl = delayLabel(delays[p.name]);
                      return <div className={`sub-proxy-node${isMember ? "" : " dimmed"}`} key={p.name}>
                        <span className="sub-proxy-node-name">{p.name}</span>
                        <span className="sub-proxy-node-meta">
                          <span className="sub-proxy-node-type">{p.nodeType}</span>
                          {dl && <span className={`sub-proxy-delay ${dl.cls}`}>{dl.text}</span>}
                        </span>
                      </div>;
                    })}
                  </div>
                </div>
              </div>
          }
        </div>}
      </section>;
    })}
    {running && groups.length > 0 && <section className="proxy-groups"><div className="toolbar"><div><h2>代理组与节点</h2><p>选择每个代理组使用的节点。点击网速检测测试所有节点延迟。</p></div><button className={`speed-test-btn${testingSpeed ? " testing" : ""}`} disabled={testingSpeed} onClick={handleSpeedTest}><Gauge size={14}/>{testingSpeed ? "测速中…" : "全网测速"}</button></div>{groups.map(group => <div className="proxy-group-block" key={group.name}><div className="proxy-group-head"><h3>{group.name}</h3><span className="proxy-group-type">{group.groupType === "Selector" ? "手动选择" : group.groupType === "URLTest" ? "自动测速" : group.groupType}</span></div><div className="proxy-node-grid">{group.nodes.map(node => { const active = group.now === node.name; const dl = delayLabel(delays[node.name] ?? node.delay ?? undefined); return <button key={node.name} className={`proxy-node ${active ? "active" : ""}`} disabled={locked && !active} onClick={() => void handleSelect(group.name, node.name)}><div className="proxy-node-name">{node.name}</div><div className="proxy-node-meta"><span className="proxy-node-type">{node.nodeType}</span>{dl && <span className={`proxy-node-delay ${dl.cls}`}>{dl.text}</span>}</div></button>; })}</div></div>)}</section>}
  </>;
}

function UnlockDialog({ onClose, onUnlock }: { onClose: () => void; onUnlock: (password: string) => Promise<void> }) {
  const [error, setError] = useState("");
  return <div className="modal-backdrop" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
    <section className="modal" role="dialog" aria-modal="true" aria-labelledby="unlock-title">
      <button className="icon-button" aria-label="关闭" onClick={onClose}><X size={18}/></button>
      <div className="modal-symbol"><LockKeyhole/></div>
      <h2 id="unlock-title">家长身份验证</h2>
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
      {error && <span className="form-error">{error}</span>}<button className="primary full" type="submit">保存管理密码</button>
    </form>
  </section></div>;
}

function ParentRuleDialog({onClose,onSubmit}:{onClose:()=>void;onSubmit:(input:backend.NewParentRule)=>Promise<void>}){
  const[error,setError]=useState("");
  return <div className="modal-backdrop" onMouseDown={event=>event.target===event.currentTarget&&onClose()}><section className="modal" role="dialog" aria-modal="true" aria-labelledby="parent-rule-title"><button className="icon-button" aria-label="关闭" onClick={onClose}><X size={18}/></button><h2 id="parent-rule-title">添加家庭规则</h2><p>家长规则优先于普通内容规则；诈骗、钓鱼和恶意软件仍保持最高优先级。</p><form onSubmit={async event=>{event.preventDefault();const data=new FormData(event.currentTarget);setError("");try{await onSubmit({action:String(data.get("action")) as "allow"|"block"|"proxy",kind:String(data.get("kind")),pattern:String(data.get("pattern")),category:String(data.get("category")||"custom")});}catch(reason){setError(String(reason));}}}><label htmlFor="parent-action">动作</label><select id="parent-action" name="action"><option value="block">拦截（阻止访问）</option><option value="proxy">代理放行（走代理）</option><option value="allow">直连放行（不走代理）</option></select><label htmlFor="parent-kind">匹配方式</label><select id="parent-kind" name="kind"><option value="suffix">域名及子域名</option><option value="contains">关键词包含</option><option value="wildcard">通配符</option><option value="regex">正则表达式</option><option value="ip">IP地址</option><option value="cidr">IP网段</option></select><label htmlFor="parent-pattern">规则内容</label><input id="parent-pattern" name="pattern" placeholder="example.com 或 *.example.com" required autoComplete="off" spellCheck={false}/><input type="hidden" name="category" value="custom"/>{error&&<span className="form-error">{error}</span>}<div className="modal-actions"><button type="button" className="secondary" onClick={onClose}>取消</button><button className="primary" type="submit">验证并保存</button></div></form></section></div>;
}

function SubscriptionDialog({ kind, onClose, onSubmit }: { kind: "规则" | "代理"; onClose: () => void; onSubmit:(input:backend.NewSubscription)=>Promise<void> }) {
  const [error,setError]=useState("");
  const [allSources,setAllSources]=useState<backend.RecommendedSource[]>([]);
  const [selectedFormat,setSelectedFormat]=useState("auto");
  const formRef=useRef<HTMLFormElement>(null);
  useEffect(()=>{ if(kind==="规则"){ backend.getRecommendedSources().then(setAllSources).catch(()=>setAllSources([])); } },[kind]);
  const filteredSources = selectedFormat==="auto" ? allSources : allSources.filter(s=>s.format===selectedFormat);
  const handleFormatChange=(fmt:string)=>{ setSelectedFormat(fmt); };
  const applySource=(src:backend.RecommendedSource)=>{ const form=formRef.current; if(!form)return; (form.elements.namedItem("name")as HTMLInputElement).value=src.name; (form.elements.namedItem("url")as HTMLInputElement).value=src.url; (form.elements.namedItem("format")as HTMLSelectElement).value=src.format; (form.elements.namedItem("category")as HTMLSelectElement).value=src.category; };
  return <div className="modal-backdrop" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
    <section className="modal modal-wide" role="dialog" aria-modal="true" aria-labelledby="subscription-title">
      <button className="icon-button" aria-label="关闭" onClick={onClose}><X size={18}/></button>
      <h2 id="subscription-title">添加{kind}订阅</h2>
      <p>{kind === "规则" ? "支持 Clash、hosts、域名、IP/CIDR 和 Adblock 列表。" : "只会提取代理节点和代理组。"}</p>
      <form ref={formRef} onSubmit={async(event) => { event.preventDefault(); const data=new FormData(event.currentTarget); setError(""); try{await onSubmit({kind:kind==="规则"?"rule":"proxy",name:String(data.get("name")),url:String(data.get("url")),format:String(data.get("format")||"auto"),category:kind==="规则"?String(data.get("category")||"custom"):undefined,updateIntervalHours:Number(data.get("interval")||24)});}catch(reason){setError(String(reason));} }}>
        {kind==="规则"&&<><label htmlFor="subscription-format">格式</label><select id="subscription-format" name="format" value={selectedFormat} onChange={e=>handleFormatChange(e.target.value)}><option value="auto">自动检测</option><option value="clash">Clash/Mihomo</option><option value="adblock">Adblock</option><option value="hosts">Hosts</option><option value="domain-list">域名列表</option><option value="ip-list">IP/CIDR</option></select></>}
        <label htmlFor="subscription-name">订阅名称</label><input id="subscription-name" name="name" placeholder={`我的${kind}订阅`} required autoComplete="off" spellCheck={false} />
        <label htmlFor="subscription-url">订阅地址</label><input id="subscription-url" name="url" type="url" placeholder="https://example.com/subscription" required autoComplete="off" spellCheck={false} />
        {kind==="规则"&&<><label htmlFor="subscription-category">分类</label><select id="subscription-category" name="category"><option value="custom">自定义</option><option value="pornography">色情与擦边</option><option value="gambling">赌博</option><option value="malware">恶意软件</option><option value="ads">广告</option></select>
        {filteredSources.length>0 && <div className="recommended-sources"><span className="recommended-sources-title">推荐规则源（点击自动填入）</span><div className="recommended-sources-grid">{filteredSources.map(src=><button type="button" className="recommended-source-card" key={src.url} onClick={()=>applySource(src)}><div className="recommended-source-head"><span className="recommended-source-name">{src.name}</span><span className="recommended-source-badge">{src.format}</span></div><p className="recommended-source-desc">{src.description}</p></button>)}</div></div>}
        </>}
        <label htmlFor="subscription-interval">更新周期</label><select id="subscription-interval" name="interval"><option value="6">每6小时</option><option value="12">每12小时</option><option value="24">每天</option><option value="168">每7天</option></select>
        {error&&<span className="form-error">{error}</span>}
        <div className="modal-actions"><button type="button" className="secondary" onClick={onClose}>取消</button><button className="primary" type="submit">验证并添加</button></div>
      </form>
    </section>
  </div>;
}

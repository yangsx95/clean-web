import React from "react";
import type { CoreComponentStatus, CoreStatus } from "./backend";

export function fallbackCoreComponents(running:boolean): CoreComponentStatus[] {
  return [
    { id:"mihomo", label:"Mihomo 内核", status:running?"ready":"stopped", detail:running?"进程运行中":"未检测到运行进程" },
    { id:"active-config", label:"运行配置", status:running?"ready":"stopped", detail:running?"已记录当前配置":"缺少 active-config" },
    { id:"cleanweb-dns", label:"CleanWeb DNS", status:running?"ready":"stopped", detail:running?"127.0.0.1:19053 正常":"19053 健康探测失败" },
    { id:"mihomo-dns", label:"本机 DNS 接管", status:running?"ready":"stopped", detail:running?"127.0.0.1:53 正常":"53 端口健康探测失败" },
  ];
}

export function RuntimeComponentStatus({ coreStatus, compact=false, pending=false }: { coreStatus:CoreStatus|null; compact?:boolean; pending?:boolean }) {
  const running = coreStatus?.running === true;
  const components = coreStatus?.components?.length ? coreStatus.components : fallbackCoreComponents(running);
  const readyCount = components.filter(component => component.status === "ready").length;
  return <section className={`cw-panel component-status-panel${compact ? " compact" : ""}`} aria-label="组件状态">
    <div className="cw-panel-head"><h3>组件状态</h3><span>{readyCount}/{components.length} 正常</span></div>
    <div className="component-status-list">
      {components.map(component => <ComponentStatusItem component={component} pending={pending} key={component.id} />)}
    </div>
  </section>;
}

function ComponentStatusItem({ component, pending }: { component:CoreComponentStatus; pending:boolean }) {
  const label = component.status === "ready" ? "正常" : pending ? "检测中" : component.status === "warning" ? "异常" : "未运行";
  return <div className={`component-status-item ${component.status}${pending && component.status !== "ready" ? " pending" : ""}`}>
    <span className="component-status-dot" aria-hidden="true" />
    <div><b>{component.label}</b><small title={component.detail}>{component.detail}</small></div>
    <strong>{label}</strong>
  </div>;
}

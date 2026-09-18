"use strict";
const $ = id => document.getElementById(id);
let csrf = "", selected = "", offset = 0, timer;
function notice(text) { $("notice").textContent = text; }
async function api(path, options = {}) {
  const response = await fetch(path, {...options, headers: {"X-CSRF-Token": csrf, ...options.headers}});
  if (!response.ok) { let detail; try { detail = (await response.json()).detail; } catch (_) { detail = response.statusText; } throw Error(typeof detail === "string" ? detail : JSON.stringify(detail)); }
  return response.json();
}
function json(method, data) { return {method, headers: {"Content-Type": "application/json"}, body: JSON.stringify(data)}; }
function button(label, action) { const b = document.createElement("button"); b.textContent = label; b.onclick = () => Promise.resolve(action()).catch(e => notice(e.message)); return b; }
function cell(row, text) { const td = row.insertCell(); td.textContent = text; return td; }
async function refresh() {
  const jobs = await api(`/api/jobs?q=${encodeURIComponent($("search").value)}&offset=${offset}`);
  $("jobs").replaceChildren(); $("empty").hidden = jobs.length > 0;
  for (const j of jobs) {
    const tr = document.createElement("tr"); cell(tr, j.name);
    const status = document.createElement("span"); status.className = `badge ${j.status}`; status.textContent = j.status; cell(tr, "").append(status);
    cell(tr, new Date(j.created * 1000).toLocaleString()); cell(tr, j.result?.summary?.risk || j.result?.verdict?.risk || "—");
    const actions = cell(tr, "");
    if (j.status === "completed") actions.append(button("Inspect", () => inspect(j)));
    if (["queued", "running"].includes(j.status)) actions.append(button("Cancel", async () => { await api(`/api/jobs/${j.id}/cancel`, {method: "POST"}); await refresh(); }));
    if (j.error) actions.append(button("Details", () => notice(j.error)));
    $("jobs").append(tr);
  }
  $("previous").disabled = offset === 0; $("next").disabled = jobs.length < 100;
  const m = await api("/api/metrics"); $("metrics").textContent = `${m.jobs.running || 0} running · ${m.jobs.queued || 0} queued · ${m.jobs.completed || 0} completed`;
}
async function evidence() {
  if (!selected) return;
  const result = await api(`/api/jobs/${selected}/evidence?q=${encodeURIComponent($("evidence-search").value)}`);
  $("evidence").replaceChildren();
  const count = document.createElement("p"); count.textContent = `${result.total} findings · showing first 100`; $("evidence").append(count);
  for (const e of result.items) { const d = document.createElement("details"); d.className = "evidence-row"; const s = document.createElement("summary"); s.textContent = `${e.source} · ${e.operation} · confidence ${e.confidence}`; const p = document.createElement("pre"); p.textContent = JSON.stringify(e, null, 2); d.append(s, p); $("evidence").append(d); }
}
function graph(data) {
  const svg = $("graph"), ns = "http://www.w3.org/2000/svg"; svg.replaceChildren();
  const nodes = data.nodes.slice(0, 180), positions = new Map();
  nodes.forEach((n, i) => { const angle = 2 * Math.PI * i / nodes.length; const ring = n.label === "Evidence" ? 180 : 115; positions.set(n.id, [500 + Math.cos(angle) * ring * 2, 225 + Math.sin(angle) * ring]); });
  function element(tag, attrs) { const e = document.createElementNS(ns, tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, String(v)); return e; }
  for (const edge of data.edges) { const a = positions.get(edge.src), b = positions.get(edge.dst); if (a && b) svg.append(element("line", {x1:a[0],y1:a[1],x2:b[0],y2:b[1]})); }
  for (const n of nodes) { const [x,y] = positions.get(n.id); const c = element("circle", {cx:x,cy:y,r:7,fill:n.label === "Evidence" ? "#93a7ba" : "#94dbbd",tabindex:0,role:"button","aria-label":n.props.display || n.id}); const select = () => { $("node-detail").textContent = JSON.stringify({node:n,relationships:data.edges.filter(e => e.src === n.id || e.dst === n.id)},null,2); }; c.onclick = select; c.onkeydown = e => { if (e.key === "Enter") select(); }; svg.append(c); }
  if (nodes.length <= 60) for (const n of nodes) { const [x,y] = positions.get(n.id); const t = element("text",{x:x+10,y:y-8}); t.textContent = (n.props.display || n.props.summary || n.label).slice(0,32); svg.append(t); }
  $("node-detail").textContent = `${data.nodes.length} nodes, ${data.edges.length} relationships. Displaying up to 180 nodes.`;
}
async function inspect(job) {
  $("schedule-form").elements.job.value = job.id;
  selected = job.id; $("detail").hidden = false; $("detail-title").textContent = job.name; $("detail-meta").textContent = job.sha256; $("answer").textContent = "";
  $("downloads").replaceChildren(); for (const kind of ["html","json","jsonl"]) { const a = document.createElement("a"); a.href = `/api/jobs/${job.id}/download/${kind}`; a.textContent = `Download ${kind.toUpperCase()}`; $("downloads").append(a); }
  for (const kind of ["stix","misp","navigator","openioc","csv"]) { const a = document.createElement("a"); a.href = `/api/jobs/${job.id}/export/${kind}`; a.textContent = kind.toUpperCase(); $("downloads").append(a); }
  graph(await api(`/api/jobs/${job.id}/graph`)); await evidence(); $("detail").scrollIntoView({behavior:"smooth"});
}
async function keys() {
  $("keys").replaceChildren(); for (const k of await api("/api/keys")) { const d = document.createElement("p"); d.textContent = `${k.id.slice(0,12)} · ${k.revoked ? "revoked" : "expires " + new Date(k.expires*1000).toLocaleDateString()} `; if (!k.revoked) d.append(button("Revoke",async () => { await api(`/api/keys/${k.id}`,{method:"DELETE"}); await keys(); })); $("keys").append(d); }
}
async function start() {
  const me = await api("/api/me"); csrf = me.csrf; $("identity").textContent = `${me.workspace} / ${me.username} / ${me.role}`;
  $("login").hidden = true; $("workspace").hidden = false; $("logout").hidden = false; $("admin").hidden = me.role !== "admin";
  $("profiles").replaceChildren(); for (const name of Object.keys(await api("/api/profiles"))) { const o = document.createElement("option"); o.value = name; o.textContent = name; $("profiles").append(o); }
  if (me.role === "admin") $("events").textContent = JSON.stringify(await api("/api/events"), null, 2);
  $("members-panel").hidden = me.role !== "admin";
  if (me.role === "admin") await members(me.id);
  await refresh(); await keys(); await schedules(); clearInterval(timer); timer = setInterval(() => refresh().catch(e => notice(e.message)), 5000);
}
async function schedules() { $("schedules").replaceChildren(); for (const s of await api("/api/schedules")) { const d=document.createElement("p"); d.textContent=`${s.source_job.slice(0,12)} · every ${s.interval_seconds/60} minutes · ${s.enabled ? "active" : "disabled"} `; if(s.enabled) d.append(button("Disable",async()=>{await api(`/api/schedules/${s.id}`,{method:"DELETE"});await schedules();})); $("schedules").append(d); } }
async function members(self) { $("members").replaceChildren(); for (const m of await api("/api/users")) { const d=document.createElement("p"); d.textContent=`${m.username} · ${m.role} · ${m.active ? "active" : "disabled"} `; if(m.active && m.id!==self) d.append(button("Disable",async()=>{await api(`/api/users/${m.id}`,{method:"DELETE"});await members(self);})); $("members").append(d); } }
$("schedule-form").onsubmit = async e => { e.preventDefault(); try { const data=new FormData(e.target); await api(`/api/jobs/${encodeURIComponent(data.get("job"))}/schedule`,json("POST",{interval_seconds:Number(data.get("minutes"))*60}));await schedules();notice("Recurring analysis scheduled.");} catch(err){notice(err.message);} };
$("login-form").onsubmit = async e => { e.preventDefault(); try { const data = Object.fromEntries(new FormData(e.target)); await api("/api/login",json("POST",data)); e.target.reset(); await start(); notice(""); } catch (err) { notice(err.message); } };
$("submit-form").onsubmit = async e => { e.preventDefault(); const form = new FormData(e.target), file = form.get("sample"); try { const q = new URLSearchParams({name:file.name,profile:form.get("profile"),delay:String(Number(form.get("delay"))*60)}); await api(`/api/jobs?${q}`,{method:"POST",body:file}); notice("Analysis queued."); await refresh(); } catch (err) { notice(err.message); } };
$("ask-form").onsubmit = async e => { e.preventDefault(); try { const a = await api(`/api/jobs/${selected}/ask`,json("POST",{question:new FormData(e.target).get("question")})); $("answer").textContent = a.answer + "\n\nEvidence: " + a.citations.join(", "); } catch (err) { notice(err.message); } };
$("user-form").onsubmit = async e => { e.preventDefault(); try { await api("/api/users",json("POST",Object.fromEntries(new FormData(e.target)))); e.target.reset(); notice("Workspace member created."); } catch (err) { notice(err.message); } };
$("logout").onclick = async () => { await api("/api/logout",{method:"POST"}); location.reload(); };
$("new-key").onclick = async () => { try { $("new-key-value").textContent = (await api("/api/keys",{method:"POST"})).key + "\nCopy now; this key is shown only once."; await keys(); } catch (err) { notice(err.message); } };
$("refresh").onclick = () => refresh().catch(e => notice(e.message)); $("search").onchange = () => { offset=0; refresh().catch(e=>notice(e.message)); };
$("previous").onclick = () => { offset=Math.max(0,offset-100); refresh().catch(e=>notice(e.message)); }; $("next").onclick = () => { offset+=100; refresh().catch(e=>notice(e.message)); };
$("evidence-search").onchange = () => evidence().catch(e=>notice(e.message)); $("close-detail").onclick = () => { $("detail").hidden=true; selected=""; };
start().catch(() => {});

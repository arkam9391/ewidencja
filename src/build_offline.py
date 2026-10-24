"""Builds the offline (single-file, no internet) version of the Ewidencja sprzedaży app
from the online artifact source (index.html in this folder).

Usage: python3 build_offline.py  -> writes ewidencja-offline.html next to this script.
"""
import pathlib
import re

HERE = pathlib.Path(__file__).parent
src = (HERE / "index.html").read_text(encoding="utf-8")


def swap(text, old, new, count=1):
    if text.count(old) != count:
        raise SystemExit(f"Expected {count}x in source, found {text.count(old)}: {old[:70]!r}")
    return text.replace(old, new)


def swap_re(text, pattern, new):
    out, n = re.subn(pattern, lambda m: new, text, flags=re.S)
    if n != 1:
        raise SystemExit(f"Pattern matched {n}x: {pattern[:70]!r}")
    return out


# 1. No web fonts offline: the CSS font stacks already fall back to system fonts.
src = swap_re(src, r'<link rel="preconnect"[^>]*>\s*<link rel="stylesheet" href="https://fonts\.googleapis\.com[^>]*>\s*', "")

# 2. Labels and copy that mention claude.ai.
src = swap(src, '<span class="lsub">sprzedaży</span>', '<span class="lsub">sprzedaży · na komputerze</span>')
src = swap(src, "Kopie w aplikacji chronią przed pomyłką, np. przypadkowym usunięciem wpisu. Przed awarią konta chroni tylko kopia poza claude.ai: pobierz plik i przenieś go na pendrive, dysk zewnętrzny albo do chmury, potem potwierdź to przyciskiem.",
           "Dane i kopie w aplikacji są zapisane w przeglądarce na tym komputerze. Chronią przed pomyłką, np. przypadkowym usunięciem wpisu, ale znikną po wyczyszczeniu danych przeglądarki albo awarii dysku. Dlatego regularnie pobieraj plik kopii, przenoś go na pendrive lub dysk zewnętrzny i potwierdzaj to przyciskiem.")
src = swap(src, "Wybierz plik JSON pobrany wcześniej z tej aplikacji.",
           "Wybierz plik JSON pobrany wcześniej z tej aplikacji albo z wersji online w claude.ai.")

# 3. Storage: IndexedDB instead of the claude.ai database (localStorage as a fallback).
src = swap_re(src, r"function lsLoad\(\)\{.*?\n(?=function lsSave)", r"""const IDB = (() => { try{ return new Promise((res,rej)=>{ const r=indexedDB.open("ewidencja-dn",1); r.onupgradeneeded=()=>r.result.createObjectStore("kv"); r.onsuccess=()=>res(r.result); r.onerror=()=>rej(r.error); }); }catch(e){ return Promise.reject(e); } })();
IDB.catch(()=>{});
function idb(mode, fn){ return IDB.then(d=>new Promise((res,rej)=>{ const t=d.transaction("kv",mode); const q=fn(t.objectStore("kv")); t.oncomplete=()=>res(q&&q.result); t.onerror=()=>rej(t.error); })); }
let useLS=false;
function applyLoaded(d){ if(!d) return; state.sales=d.sales||[]; state.costs=d.costs||[]; state.settings={...DEFAULT_SETTINGS,...(d.settings||{}),wages:{...DEFAULT_SETTINGS.wages,...((d.settings||{}).wages||{})},eurRates:{...DEFAULT_SETTINGS.eurRates,...((d.settings||{}).eurRates||{})}}; state.bstate={...BK_DEFAULT,...(d.bstate||{})}; state.events=d.events||[]; state.tomb=d.tomb||{}; if(d.backups) state.backups=d.backups; }
async function lsLoad(){
  let vault=null; try{ vault=await idb("readonly",s=>s.get("vault")); }catch(e){}
  if(vault){ applyLoaded(await unlockScreen(vault)); return; }
  try{
    const main=await idb("readonly",s=>s.get("main")), bk=await idb("readonly",s=>s.get("backups"));
    if(main){ applyLoaded({...main, backups:bk||[]}); return; }
    let old=null; try{ old=JSON.parse(localStorage.getItem(LS)||"null"); }catch(e){}
    if(old){ applyLoaded(old); lsSave(); }
  }catch(e){
    useLS=true; try{ applyLoaded(JSON.parse(localStorage.getItem(LS)||"null")); }catch(e2){}
    showBanner("Ta przeglądarka nie pozwala na pełny zapis danych z pliku. Dane zapisują się w ograniczonym trybie. Najlepiej otwieraj program w Chrome lub Edge.");
  }
}
""")
src = swap_re(src, r"function lsSave\(\)\{.*?\n", r"""function lsSave(){
  const main={sales:state.sales,costs:state.costs,events:state.events,settings:state.settings,bstate:state.bstate,tomb:state.tomb||{}};
  syncSoon();
  if(useLS){ try{ localStorage.setItem(LS, JSON.stringify({...main,backups:state.backups})); }catch(e){ showBanner("Nie udało się zapisać danych. Pobierz kopię w zakładce Kopie bezpieczeństwa."); } return; }
  const backups=state.backups.map(b=>({...b})), key=lock.key, salt=lock.salt;
  saving++;
  saveChain=saveChain.then(async()=>{
    if(key){ const v=await encryptVault({...main,backups},key,salt); await idb("readwrite",s=>{ s.put(v,"vault"); s.delete("main"); s.delete("backups"); }); }
    else await idb("readwrite",s=>{ s.put(main,"main"); s.put(backups,"backups"); s.delete("vault"); });
  }).catch(()=>showBanner("Nie udało się zapisać danych. Pobierz kopię w zakładce Kopie bezpieczeństwa.")).finally(()=>saving--);
}
// ---------- password lock (AES-GCM, key from PBKDF2) ----------
const lock={key:null, salt:null}; let saveChain=Promise.resolve(), saving=0;
const LOCK_IDLE="ewidencja-lock-idle";
async function deriveKey(pw, salt){
  const base=await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2", salt, iterations:310000, hash:"SHA-256"}, base, {name:"AES-GCM", length:256}, false, ["encrypt","decrypt"]);
}
async function encryptVault(obj, key, salt){
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, new TextEncoder().encode(JSON.stringify(obj)));
  return {v:1, salt, iv, ct:new Uint8Array(ct)};
}
async function decryptVault(v, key){ return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({name:"AES-GCM", iv:v.iv}, key, v.ct))); }
function unlockScreen(vault){
  return new Promise(resolve=>{
    $("#lock").hidden=false; setTimeout(()=>$("#lockPw").focus(),50);
    $("#lockForm").onsubmit=async e=>{
      e.preventDefault(); $("#lockErr").textContent="Sprawdzam…";
      try{ const key=await deriveKey($("#lockPw").value, vault.salt); const d=await decryptVault(vault, key);
        lock.key=key; lock.salt=vault.salt; $("#lockPw").value=""; $("#lockErr").textContent=""; $("#lock").hidden=true; resolve(d); }
      catch(err){ $("#lockErr").textContent="Nieprawidłowe hasło. Spróbuj ponownie."; $("#lockPw").select(); }
    };
    $("#lockWipe").onclick=async ()=>{
      const b=$("#lockWipe"); if(!b.dataset.armed){ b.dataset.armed="1"; b.textContent="Na pewno? Dane z tego komputera znikną"; return; }
      await idb("readwrite",s=>s.clear());
      $("#lock").hidden=true; resolve({}); toast("Usunięto dane. Wczytaj plik kopii w zakładce Kopie bezpieczeństwa.");
    };
  });
}
function renderLock(){
  const on=!!lock.key; $("#lockPill").className="pill "+(on?"ok":""); $("#lockPill").textContent=on?"włączone":"wyłączone";
  $("#lockSet").textContent=on?"Zmień hasło":"Ustaw hasło"; $("#lockOff").hidden=!on; $("#lockNow").hidden=!on;
  if(useLS){ $("#lockSet").disabled=true; $("#lockMsg").textContent="Hasło działa tylko w Chrome lub Edge."; }
}
function initLockUI(){
  try{ $("#lock_idle").value=localStorage.getItem(LOCK_IDLE)||"15"; }catch(e){}
  $("#lock_idle").onchange=e=>{ try{ localStorage.setItem(LOCK_IDLE,e.target.value); }catch(err){} toast("Zapisano"); };
  $("#lockSet").onclick=async ()=>{
    const a=$("#lock_pw1").value, b=$("#lock_pw2").value;
    if(a.length<6){ $("#lockMsg").textContent="Hasło musi mieć co najmniej 6 znaków."; return; }
    if(a!==b){ $("#lockMsg").textContent="Hasła się różnią."; return; }
    $("#lockMsg").textContent="Szyfruję dane…";
    const prev=lock.key; lock.salt=crypto.getRandomValues(new Uint8Array(16)); lock.key=await deriveKey(a, lock.salt);
    lsSave(); await saveChain; await reencryptAtts(prev, lock.key); $("#lock_pw1").value=""; $("#lock_pw2").value="";
    $("#lockMsg").textContent="Hasło ustawione. Dane na tym komputerze są zaszyfrowane."; renderLock();
  };
  $("#lockOff").onclick=async ()=>{
    const b=$("#lockOff"); if(!b.dataset.armed){ b.dataset.armed="1"; b.textContent="Na pewno wyłączyć?"; return; }
    b.dataset.armed=""; b.textContent="Wyłącz hasło"; const prev=lock.key; lock.key=null; lock.salt=null; lsSave(); await saveChain; await reencryptAtts(prev, null);
    $("#lockMsg").textContent="Hasło wyłączone. Dane nie są już szyfrowane."; renderLock();
  };
  $("#lockNow").onclick=async ()=>{ await saveChain; location.reload(); };
  let last=Date.now(); for(const ev of ["pointerdown","keydown","wheel","touchstart"]) addEventListener(ev,()=>{ last=Date.now(); },{passive:true});
  setInterval(()=>{ let m=15; try{ m=+(localStorage.getItem(LOCK_IDLE)||15); }catch(e){}
    if(lock.key && m>0 && !saving && Date.now()-last>m*60000) location.reload(); }, 20000);
  renderLock();
}
""")
src = swap_re(src, r"async function initStore\(\)\{.*?\n\}\n(?=\n// ---------- backups)", """
// ---------- Google Drive sync (hidden app folder, AES-GCM with the sync password) ----------
const SYNC_CLIENT_ID = "";
const SYNC_LS = "ewidencja-sync", SYNC_FILE = "ewidencja-sync.bin", SYNC_SCOPE = "https://www.googleapis.com/auth/drive.appdata";
const sync = {cfg:{}, key:null, busy:false, again:false, timer:null, applying:false};
const b64 = u => btoa(String.fromCharCode(...u)), unb64 = t => Uint8Array.from(atob(t), c=>c.charCodeAt(0));
function syncCfgSave(){ try{ localStorage.setItem(SYNC_LS, JSON.stringify(sync.cfg)); }catch(e){} }
const syncClientId = () => SYNC_CLIENT_ID || sync.cfg.cid || "";
const syncCanRun = () => location.protocol === "https:" || location.hostname === "localhost" || location.hostname === "127.0.0.1";
function loadGis(){
  if(window.google?.accounts?.oauth2) return Promise.resolve();
  return loadGis._p ||= new Promise((res,rej)=>{ const s=document.createElement("script"); s.src="https://accounts.google.com/gsi/client"; s.async=true; s.onload=()=>res(); s.onerror=()=>{ loadGis._p=null; rej(new Error("offline")); }; document.head.appendChild(s); });
}
const tokenValid = () => sync.cfg.token && Date.now() < (sync.cfg.tokenExp||0) - 60000;
function askToken(){
  // Must run straight from a click: Google opens a sign-in window.
  return new Promise((res,rej)=>{
    if(!window.google?.accounts?.oauth2){ rej(new Error("offline")); return; }
    const c=google.accounts.oauth2.initTokenClient({client_id:syncClientId(), scope:SYNC_SCOPE, prompt:"", login_hint:sync.cfg.email||undefined,
      callback:r=>{ if(r.error){ rej(new Error(r.error)); return; } sync.cfg.token=r.access_token; sync.cfg.tokenExp=Date.now()+(+r.expires_in||3600)*1000; syncCfgSave(); res(); },
      error_callback:e=>rej(new Error(e?.type||"popup"))});
    c.requestAccessToken();
  });
}
async function gfetch(url, opt={}){
  if(!tokenValid()) throw new Error("auth");
  const r=await fetch(url, {...opt, headers:{...(opt.headers||{}), Authorization:"Bearer "+sync.cfg.token}});
  if(r.status===401){ sync.cfg.token=""; syncCfgSave(); throw new Error("auth"); }
  if(!r.ok) throw new Error("drive "+r.status);
  return r;
}
async function driveList(){ const r=await gfetch("https://www.googleapis.com/drive/v3/files?spaces=appDataFolder&pageSize=1000&fields=files(id,name)"); return (await r.json()).files||[]; }
async function driveGet(id){ return new Uint8Array(await (await gfetch("https://www.googleapis.com/drive/v3/files/"+id+"?alt=media")).arrayBuffer()); }
async function drivePut(name, bytes, id){
  if(id){ await gfetch("https://www.googleapis.com/upload/drive/v3/files/"+id+"?uploadType=media", {method:"PATCH", headers:{"Content-Type":"application/octet-stream"}, body:bytes}); return id; }
  const fd=new FormData(); fd.append("metadata", new Blob([JSON.stringify({name, parents:["appDataFolder"]})], {type:"application/json"})); fd.append("file", new Blob([bytes], {type:"application/octet-stream"}));
  return (await (await gfetch("https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id", {method:"POST", body:fd})).json()).id;
}
// File layout: "EWS1" + salt(16) + iv(12) + ciphertext.
const MAGIC = [69,87,83,49];
async function seal(bytes){
  const salt=unb64(sync.cfg.salt), iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM", iv}, sync.key, bytes));
  const out=new Uint8Array(32+ct.length); out.set(MAGIC,0); out.set(salt,4); out.set(iv,20); out.set(ct,32); return out;
}
const fileSalt = u => { if(MAGIC.some((m,i)=>u[i]!==m)) throw new Error("format"); return u.slice(4,20); };
async function unseal(u, key=sync.key){ fileSalt(u); return new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM", iv:u.slice(20,32)}, key, u.slice(32))); }
const enc = o => new TextEncoder().encode(JSON.stringify(o)), dec = u => JSON.parse(new TextDecoder().decode(u));
const recTime = o => +o.updatedAt || +o.createdAt || 0;
function mergeSettings(a, b){
  const ta=a._ts||{}, tb=b._ts||{}, out={}, ts={};
  for(const k of new Set([...Object.keys(a), ...Object.keys(b)])){ if(k==="_ts") continue;
    const x=(ta[k]||0), y=(tb[k]||0), aDef=JSON.stringify(a[k])===JSON.stringify(DEFAULT_SETTINGS[k]);
    const useB = !(k in a) || (k in b && (y>x || (y===x && (aDef || JSON.stringify(b[k])!==JSON.stringify(DEFAULT_SETTINGS[k])) && !(x===0 && !aDef && JSON.stringify(b[k])===JSON.stringify(DEFAULT_SETTINGS[k])))));
    out[k]=useB?b[k]:a[k]; ts[k]=Math.max(x,y); }
  out._ts=ts; return out;
}
function mergeData(a, b){
  const tomb={...(a.tomb||{})}; for(const [k,v] of Object.entries(b.tomb||{})) tomb[k]=Math.max(tomb[k]||0, v);
  const out={v:1};
  for(const c of ["sales","costs","events"]){
    const m=new Map(); for(const o of [...(a[c]||[]), ...(b[c]||[])]){ const p=m.get(o.id); if(!p || recTime(o)>recTime(p)) m.set(o.id, o); }
    out[c]=[...m.values()].filter(o=>!((tomb[o.id]||0)>=recTime(o) && tomb[o.id])).sort((x,y)=>x.id<y.id?-1:x.id>y.id?1:0);
  }
  out.settings=b.settings ? mergeSettings(a.settings||{}, b.settings) : a.settings;
  out.tomb=tomb; return out;
}
const localData = () => ({sales:state.sales, costs:state.costs, events:state.events, settings:state.settings, tomb:state.tomb||{}});
function syncSoon(){ if(sync.applying || !sync.cfg.on) return; clearTimeout(sync.timer); sync.timer=setTimeout(()=>syncNow(), 4000); }
function syncUI(text, kind){
  const btn=$("#syncBtn"), pip=$("#syncPip"); if(btn){ btn.hidden=!sync.cfg.on; btn.title=text; btn.setAttribute("aria-label","Synchronizacja z Google Drive: "+text); pip.hidden=!kind||kind==="busy"; pip.style.background=kind==="ok"?"var(--ok)":kind==="err"?"var(--crit)":"var(--warn)"; btn.classList.toggle("spin", kind==="busy"); }
  if($("#syncMsg") && text) $("#syncMsg").textContent=text;
  const pl=$("#syncPill"); if(pl){ pl.className="pill "+(sync.cfg.on?(kind==="err"?"crit":kind==="warn"?"warn":"ok"):""); pl.textContent=sync.cfg.on?"włączona":"wyłączona"; }
  if($("#syncOn")){ $("#syncOn").hidden=!!sync.cfg.on; $("#syncGo").hidden=!sync.cfg.on; $("#syncOff").hidden=!sync.cfg.on; $("#syncSetup").hidden=!!sync.cfg.on; }
}
async function syncAtts(files){
  const names=new Map(files.map(f=>[f.name, f.id]));
  const have=new Set((await idb("readonly", s=>s.getAllKeys())).filter(k=>typeof k==="string" && k.startsWith("att:")).map(k=>k.slice(4)));
  for(const c of state.costs){ const id=c.att?.id; if(!id || c.att.store==="asset") continue; const fname="att-"+id+".bin";
    if(have.has(id) && !names.has(fname)){
      const r=await attOpenRec(await idb("readonly", s=>s.get("att:"+id)), lock.key); if(!r) continue;
      const head=enc({name:r.name, type:r.type, size:r.size}), buf=new Uint8Array(r.buf), u=new Uint8Array(4+head.length+buf.length);
      new DataView(u.buffer).setUint32(0, head.length); u.set(head,4); u.set(buf,4+head.length);
      await drivePut(fname, await seal(u));
    } else if(!have.has(id) && names.has(fname)){
      const u=await unseal(await driveGet(names.get(fname))), n=new DataView(u.buffer).getUint32(0), h=dec(u.slice(4,4+n));
      const rec=await attSeal({...h, buf:u.slice(4+n)}, lock.key); await idb("readwrite", s=>s.put(rec, "att:"+id));
    }
  }
}
async function syncNow(){
  if(!sync.cfg.on || !sync.key) return;
  if(sync.busy){ sync.again=true; return; }
  if(!navigator.onLine){ syncUI("Brak internetu. Zsynchronizuję po połączeniu.", "warn"); return; }
  if(!tokenValid()){ syncUI("Kliknij ikonę chmury, żeby połączyć się z Google Drive.", "warn"); return; }
  sync.busy=true; syncUI("Synchronizuję…", "busy");
  try{
    await saveChain;
    const files=await driveList(), f=files.find(x=>x.name===SYNC_FILE);
    const remote=f ? dec(await unseal(await driveGet(f.id))) : null;
    const local=localData(), m=mergeData(local, remote||{});
    const same=(x,y)=>JSON.stringify(x)===JSON.stringify(y);
    const sortIds=arr=>(arr||[]).slice().sort((x,y)=>x.id<y.id?-1:x.id>y.id?1:0);
    if(!same(sortIds(local.sales),m.sales) || !same(sortIds(local.costs),m.costs) || !same(sortIds(local.events),m.events) || !same(local.settings,m.settings) || !same(local.tomb,m.tomb)){
      const setChanged=!same(local.settings,m.settings);
      state.sales=m.sales; state.costs=m.costs; state.events=m.events; state.tomb=m.tomb;
      state.settings={...DEFAULT_SETTINGS, ...m.settings, wages:{...DEFAULT_SETTINGS.wages, ...(m.settings.wages||{})}, eurRates:{...DEFAULT_SETTINGS.eurRates, ...(m.settings.eurRates||{})}};
      sync.applying=true; try{ lsSave(); } finally{ sync.applying=false; }
      if(setChanged){ markSettingsBase(); fillSettings(); } renderAll();
    }
    if(!remote || !same({sales:remote.sales,costs:remote.costs,events:remote.events,settings:remote.settings,tomb:remote.tomb}, {sales:m.sales,costs:m.costs,events:m.events,settings:m.settings,tomb:m.tomb}))
      await drivePut(SYNC_FILE, await seal(enc({...m, at:Date.now()})), f?.id);
    await syncAtts(files);
    sync.cfg.last=Date.now(); syncCfgSave(); syncUI("Zsynchronizowano "+fmtDT(sync.cfg.last)+".", "ok");
  }catch(e){
    if(e.message==="auth") syncUI("Kliknij ikonę chmury, żeby połączyć się ponownie z Google Drive.", "warn");
    else if(e.name==="OperationError") syncUI("Hasło synchronizacji nie pasuje do danych na Dysku. Wyłącz synchronizację i połącz ponownie z właściwym hasłem.", "err");
    else syncUI("Synchronizacja nie udała się ("+e.message+"). Spróbuję ponownie.", "err");
  }finally{ sync.busy=false; if(sync.again){ sync.again=false; syncSoon(); } }
}
async function syncConnect(){
  const pw=$("#sync_pw").value, cid=($("#sync_cid")?.value||"").trim();
  if(!SYNC_CLIENT_ID && !/\\.apps\\.googleusercontent\\.com$/.test(cid)){ syncUI("Wklej identyfikator klienta Google (kończy się na .apps.googleusercontent.com).", "warn"); return; }
  if(pw.length<8){ syncUI("Hasło synchronizacji musi mieć co najmniej 8 znaków.", "warn"); return; }
  sync.cfg.cid=cid; syncCfgSave();
  try{ await loadGis(); await askToken(); }catch(e){ syncUI(e.message==="offline"?"Nie mogę połączyć się z Google. Sprawdź internet.":"Nie udało się zalogować do Google ("+e.message+").", "err"); return; }
  syncUI("Sprawdzam dane na Dysku…", "busy");
  try{
    const f=(await driveList()).find(x=>x.name===SYNC_FILE);
    if(f){ const u=await driveGet(f.id), salt=fileSalt(u), key=await deriveKey(pw, salt);
      try{ await unseal(u, key); }catch(e){ syncUI("To hasło nie pasuje do danych już zapisanych na Dysku. Wpisz to samo hasło co na drugim urządzeniu.", "err"); return; }
      sync.cfg.salt=b64(salt); sync.key=key; }
    else { const salt=crypto.getRandomValues(new Uint8Array(16)); sync.cfg.salt=b64(salt); sync.key=await deriveKey(pw, salt); }
    try{ await idb("readwrite", s=>s.put(sync.key, "syncKey")); }catch(e){}
    sync.cfg.on=true; syncCfgSave(); $("#sync_pw").value="";
    await createBackup("pre").catch(()=>{});
    await syncNow();
  }catch(e){ syncUI("Nie udało się połączyć z Dyskiem ("+e.message+").", "err"); }
}
async function initSync(){
  try{ sync.cfg=JSON.parse(localStorage.getItem(SYNC_LS)||"{}"); }catch(e){ sync.cfg={}; }
  if(!syncCanRun()){ const c=$("#syncCard"); if(c){ $("#syncSetup").hidden=true; $("#syncOn").hidden=true; $("#syncMsg").textContent="Synchronizacja działa w wersji zainstalowanej ze strony https://arkam9391.github.io/ewidencja/."; } return; }
  if(SYNC_CLIENT_ID) $("#sync_cidWrap").hidden=true; else if(sync.cfg.cid) $("#sync_cid").value=sync.cfg.cid;
  $("#tabs").addEventListener("click", e=>{ if(e.target.closest("[data-tab=ustawienia]")) loadGis().catch(()=>{}); });
  if(state.tab==="ustawienia") loadGis().catch(()=>{});
  $("#syncOn").onclick=syncConnect;
  $("#syncGo").onclick=$("#syncBtn").onclick=async ()=>{ if(!tokenValid()){ try{ await askToken(); }catch(e){ syncUI("Nie udało się zalogować do Google. Spróbuj jeszcze raz.", "err"); loadGis().catch(()=>{}); return; } } syncNow(); };
  $("#syncOff").onclick=async ()=>{ const b=$("#syncOff"); if(!b.dataset.armed){ b.dataset.armed="1"; b.textContent="Na pewno? Dane zostaną na tym urządzeniu"; return; } b.dataset.armed=""; b.textContent="Wyłącz na tym urządzeniu";
    try{ if(sync.cfg.token && window.google?.accounts?.oauth2) google.accounts.oauth2.revoke(sync.cfg.token, ()=>{}); }catch(e){}
    sync.cfg={cid:sync.cfg.cid}; sync.key=null; syncCfgSave(); try{ await idb("readwrite", s=>s.delete("syncKey")); }catch(e){} syncUI("Synchronizacja wyłączona na tym urządzeniu.", ""); };
  if(sync.cfg.on){ try{ sync.key=await idb("readonly", s=>s.get("syncKey")); }catch(e){}
    if(!sync.key){ sync.cfg.on=false; syncCfgSave(); syncUI("Połącz ponownie z Google Drive.", "warn"); return; }
    loadGis().catch(()=>{}); syncUI(sync.cfg.last?"Ostatnia synchronizacja "+fmtDT(sync.cfg.last)+".":"", "ok"); syncNow();
    addEventListener("online", ()=>syncNow());
    document.addEventListener("visibilitychange", ()=>{ if(!document.hidden && Date.now()-(sync.cfg.last||0)>60000) syncNow(); });
    setInterval(()=>{ if(!document.hidden) syncNow(); }, 300000);
  } else syncUI("", "");
}
async function initStore(){
  await lsLoad(); markSettingsBase(); fillSettings(); fillBackupSettings(); renderAll(); initLockUI(); initSync();
  try{ if(navigator.storage && navigator.storage.persist) await navigator.storage.persist(); }catch(e){}
  maybeAutoBackup();
}
""")

# 3a. Purchase documents: same IndexedDB as the data, encrypted when a password is set.
src = swap_re(src, r"// <att-local>.*?// </att-local>\n", r"""async function attSeal(rec, key){
  if(!key) return rec;
  const iv=crypto.getRandomValues(new Uint8Array(12));
  return {name:rec.name, type:rec.type, size:rec.size, iv, ct:new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, rec.buf))};
}
async function attOpenRec(rec, key){
  if(!rec || !rec.ct) return rec;
  if(!key) throw new Error("locked");
  return {name:rec.name, type:rec.type, size:rec.size, buf:new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM", iv:rec.iv}, key, rec.ct))};
}
async function attPutLocal(id, file){ const rec=await attSeal({name:file.name, type:file.type, size:file.size, buf:new Uint8Array(await file.arrayBuffer())}, lock.key); await idb("readwrite", s=>s.put(rec, "att:"+id)); }
async function attGetLocal(id){ const r=await attOpenRec(await idb("readonly", s=>s.get("att:"+id)), lock.key); return r ? new Blob([r.buf],{type:r.type}) : null; }
async function attDelLocal(id){ await idb("readwrite", s=>s.delete("att:"+id)); }
async function reencryptAtts(fromKey, toKey){
  const keys=(await idb("readonly", s=>s.getAllKeys())).filter(k=>typeof k==="string" && k.startsWith("att:"));
  for(const k of keys){ const r=await attOpenRec(await idb("readonly", s=>s.get(k)), fromKey); const sealed=await attSeal(r, toKey); await idb("readwrite", s=>s.put(sealed, k)); }
}
""")

# 3b. Password lock UI: settings card and the lock screen.
src = swap(src, '<section data-panel="ustawienia" hidden style="display:grid;gap:18px">', """<section data-panel="ustawienia" hidden style="display:grid;gap:18px">
    <div class="card">
      <div class="row"><h2>Hasło do programu</h2><span id="lockPill" class="pill">wyłączone</span></div>
      <p class="small muted" style="margin:0;max-width:72ch">Z hasłem dane na tym komputerze są zaszyfrowane i bez hasła nikt ich nie otworzy ani nie odczyta. Zapamiętaj je dobrze: bez hasła dane da się odzyskać tylko z pliku kopii. Pobrane pliki kopii nie są szyfrowane, więc trzymaj nośnik w bezpiecznym miejscu.</p>
      <div class="fields">
        <label>Nowe hasło<input type="password" id="lock_pw1" autocomplete="new-password"></label>
        <label>Powtórz hasło<input type="password" id="lock_pw2" autocomplete="new-password"></label>
        <label>Blokuj po bezczynności<select id="lock_idle"><option value="5">5 minut</option><option value="15">15 minut</option><option value="30">30 minut</option><option value="60">1 godzina</option><option value="0">Nigdy</option></select></label>
      </div>
      <div class="btns"><button class="b primary" type="button" id="lockSet">Ustaw hasło</button><button class="b" type="button" id="lockNow" hidden>Zablokuj teraz</button><button class="b danger" type="button" id="lockOff" hidden>Wyłącz hasło</button><span class="status" id="lockMsg"></span></div>
    </div>
    <div class="card" id="syncCard">
      <div class="row"><h2>Synchronizacja z Google Drive</h2><span id="syncPill" class="pill">wyłączona</span></div>
      <p class="small muted" style="margin:0;max-width:72ch">Telefon i komputer korzystają z tych samych danych. Dane trafiają do ukrytego folderu tej aplikacji na Twoim Dysku Google, zaszyfrowane hasłem synchronizacji, więc Google ich nie odczyta. Na każdym urządzeniu zaloguj się tym samym kontem Google i wpisz to samo hasło. Zmiany wysyłają się kilka sekund po zapisie; bez internetu czekają, aż połączenie wróci.</p>
      <div class="fields" id="syncSetup">
        <label id="sync_cidWrap">Identyfikator klienta Google<input id="sync_cid" placeholder="….apps.googleusercontent.com" autocomplete="off" spellcheck="false"></label>
        <label>Hasło synchronizacji<input type="password" id="sync_pw" autocomplete="new-password" placeholder="co najmniej 8 znaków"></label>
      </div>
      <div class="btns"><button class="b primary" type="button" id="syncOn">Połącz z Google Drive</button><button class="b" type="button" id="syncGo" hidden>Synchronizuj teraz</button><button class="b danger" type="button" id="syncOff" hidden>Wyłącz na tym urządzeniu</button><span class="status" id="syncMsg"></span></div>
    </div>""")
src = swap(src, '<div class="toast" id="toast" hidden></div>', """<div id="lock" hidden style="position:fixed;inset:0;z-index:30;background:var(--bg);display:grid;place-items:center;padding-inline:16px">
  <form id="lockForm" class="card" style="width:min(100%,380px)" autocomplete="off">
    <h2>Ewidencja sprzedaży</h2>
    <p class="small muted" style="margin:0">Program jest zablokowany. Wpisz hasło, żeby otworzyć dane.</p>
    <label>Hasło<input type="password" id="lockPw" autocomplete="current-password" required></label>
    <div class="status" id="lockErr" role="alert"></div>
    <div class="btns"><button class="b primary" type="submit">Odblokuj</button></div>
    <details class="small"><summary style="cursor:pointer">Nie pamiętam hasła</summary><p style="max-width:60ch">Bez hasła zaszyfrowanych danych nie da się odczytać. Możesz usunąć dane z tego komputera i wczytać ostatni plik kopii z nośnika zewnętrznego.</p><button class="b danger sm" type="button" id="lockWipe">Usuń dane z tego komputera</button></details>
  </form>
</div>
<div class="toast" id="toast" hidden></div>""")

# 3c. Google Drive sync: settings card and the cloud button in the top bar.
src = swap(src, '<button class="iconbtn" type="button" id="calBtn"', '<button class="iconbtn" type="button" id="syncBtn" hidden aria-label="Synchronizacja z Google Drive"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7 18a5 5 0 0 1-.5-9.97A6 6 0 0 1 18 9a4.5 4.5 0 0 1-.5 9z"/><path d="m9.5 13 2.5-2.5 2.5 2.5M12 10.5V16"/></svg><span class="pip" id="syncPip" hidden></span></button><button class="iconbtn" type="button" id="calBtn"')
src = swap(src, "@media (prefers-reduced-motion:reduce){.meter i{transition:none}}", "@media (prefers-reduced-motion:reduce){.meter i{transition:none}}\n.iconbtn.spin svg{animation:syncspin 1.2s linear infinite}@keyframes syncspin{50%{opacity:.35}}")

# 4. File downloads: a normal browser download instead of the claude.ai save dialog.
src = swap_re(src, r"async function download\(filename, data\)\{.*?\n\}\n", r"""async function download(filename, data){
  try{
    const type=/\.json$/.test(filename)?"application/json":/\.csv$/.test(filename)?"text/csv":"text/html";
    const a=document.createElement("a"); a.href=URL.createObjectURL(new Blob([data],{type:type+";charset=utf-8"})); a.download=filename;
    document.body.appendChild(a); a.click(); a.remove(); setTimeout(()=>URL.revokeObjectURL(a.href),10000);
    toast("Pobrano plik "+filename); return true;
  }catch(e){ toast("Nie udało się pobrać pliku"); return false; }
}
""")

# 5. Proper standalone document: head with charset, viewport and the base reset.
title_style_end = src.index("</style>") + len("</style>")
head, body = src[:title_style_end], src[title_style_end:]
doc = ("<!doctype html>\n<html lang=\"pl\">\n<head>\n<meta charset=\"utf-8\">\n"
       "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\">\n"
       "<style>:root{color-scheme:light;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}"
       "body{margin:0;font:14px system-ui,sans-serif}img{max-width:100%}[hidden]{display:none!important}</style>\n"
       + head + "\n</head>\n<body>" + body + "\n</body>\n</html>\n")

assert 'use("db")' not in doc and 'use("downloads")' not in doc and "fonts.googleapis" not in doc, "online-only code left in offline build"
(HERE / "ewidencja-offline.html").write_text(doc, encoding="utf-8")
print("OK", len(doc), "bytes")

# 6. Installable web app (PWA) with automatic updates: pwa/ folder ready for static hosting.
import hashlib
import json

version = hashlib.sha1(doc.encode("utf-8") + pathlib.Path(__file__).read_bytes() + (HERE / "changelog.json").read_bytes() + b"".join(f.read_bytes() for f in sorted((HERE / "icons").glob("*.png")))).hexdigest()[:10]
pwa = HERE / "pwa"
pwa.mkdir(exist_ok=True)
pwa_head = ('<link rel="manifest" href="manifest.webmanifest">\n<link rel="icon" href="favicon.svg" type="image/svg+xml">\n'
            '<link rel="apple-touch-icon" href="icons/paragon-apple-180.png">\n<meta name="theme-color" content="#1d5b86">\n</head>')
changes = json.loads((HERE / "changelog.json").read_text(encoding="utf-8"))
pwa_boot = """<script>
(() => {
  const V = "%s", CH = %s, LAST = CH.length ? CH[CH.length-1].n : 0;
  const ls = (k, v) => { try{ if(v===undefined) return localStorage.getItem(k); localStorage.setItem(k, v); }catch(e){ return null; } };
  const esc = s => String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  // After an update: say what is new since the version this device ran before.
  const old = ls("ewidencja-app-version"), seen = +(ls("ewidencja-seen-change")||0);
  ls("ewidencja-app-version", V); ls("ewidencja-seen-change", String(LAST));
  if(old && old !== V){
    const fresh = CH.filter(c => c.n > seen).slice(-5);
    setTimeout(() => showBar("Program zaktualizowany", fresh, false), 600);
  }
  function showBar(title, items, withReload){
    let bar = document.getElementById("updBar");
    if(!bar){ bar = document.createElement("div"); bar.id = "updBar"; bar.className = "card"; bar.setAttribute("role", "status");
      bar.style.cssText = "position:fixed;left:16px;right:16px;bottom:16px;z-index:40;max-width:560px;margin-inline:auto;box-shadow:0 10px 30px rgba(0,0,0,.25);border:2px solid var(--accent,#1d5b86)";
      document.body.appendChild(bar); }
    bar.innerHTML = `<div class="row"><h2 style="margin:0">${esc(title)}</h2><button class="b sm" type="button" data-upd="close" aria-label="Zamknij">✕</button></div>`
      + (items.length ? `<ul class="small" style="margin:6px 0 0;padding-left:18px">${items.map(c => `<li>${esc(c.text)}</li>`).join("")}</ul>` : "")
      + (withReload ? `<p class="small muted" style="margin:8px 0 0">Wpisane dane są już zapisane. Niezapisany formularz zostanie wyczyszczony.</p><div class="btns" style="margin-top:8px"><button class="b primary" type="button" data-upd="reload">Przeładuj teraz</button><button class="b" type="button" data-upd="close">Później</button></div>` : "");
    bar.hidden = false;
    bar.onclick = e => { const b = e.target.closest("[data-upd]"); if(!b) return;
      if(b.dataset.upd === "reload"){ b.disabled = true; b.textContent = "Przeładowuję…"; location.reload(); }
      else { bar.hidden = true; if(withReload) snoozed = Date.now(); } };
  }
  let snoozed = 0, offered = null;
  async function check(){
    if(!navigator.onLine) return;
    try{
      const r = await fetch("version.json?t=" + Date.now(), {cache: "no-store"}); if(!r.ok) return;
      const j = await r.json(); if(!j.version || j.version === V) return;
      if(offered === j.version && Date.now() - snoozed < 3600000) return;
      if(offered === j.version && !document.getElementById("updBar")?.hidden) return;
      offered = j.version;
      showBar("Dostępna jest nowa wersja programu", (j.changes||[]).filter(c => c.n > LAST).slice(-5), true);
    }catch(e){}
  }
  if("serviceWorker" in navigator && location.protocol.startsWith("http")){
    navigator.serviceWorker.register("sw.js").then(reg => { setInterval(() => reg.update().catch(() => {}), 1800000); }).catch(() => {});
    navigator.serviceWorker.addEventListener("controllerchange", check);
  }
  if(location.protocol.startsWith("http")){
    setTimeout(check, 5000); setInterval(check, 900000);
    document.addEventListener("visibilitychange", () => { if(!document.hidden) check(); });
    addEventListener("online", check);
  }
})();
</script>
</body>""" % (version, json.dumps(changes, ensure_ascii=False))
# The app script itself contains "</body>" inside a template string, so splice at the LAST one.
pwa_doc = doc.replace("</head>", pwa_head, 1)
cut = pwa_doc.rindex("</body>")
pwa_doc = pwa_doc[:cut] + pwa_boot + pwa_doc[cut + len("</body>"):]
(pwa / "index.html").write_text(pwa_doc, encoding="utf-8")
(pwa / "version.json").write_text(json.dumps({"version": version, "changes": changes}, ensure_ascii=False), encoding="utf-8")
(pwa / "manifest.webmanifest").write_text(json.dumps({
    "name": "Ewidencja sprzedaży", "short_name": "Ewidencja", "lang": "pl",
    "description": "Ewidencja sprzedaży dla działalności nierejestrowanej",
    "start_url": "./", "scope": "./", "display": "standalone",
    "background_color": "#f3f5f7", "theme_color": "#1d5b86",
    "icons": [{"src": "icons/paragon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
              {"src": "icons/paragon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"},
              {"src": "icons/paragon-maskable-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"},
              {"src": "icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any"}],
}, ensure_ascii=False, indent=2), encoding="utf-8")
# Logo "Paragon": receipt with a zigzag bottom edge. icon.svg has rounded corners; the maskable one is full-bleed with the receipt inside the safe zone.
PAPER = '<path d="M10 6h12v20l-2-1.5-2 1.5-2-1.5-2 1.5-2-1.5-2 1.5z" fill="#fff"/><path d="M13 11h6M13 15h6M13 19h3.5" stroke="#1d5b86" stroke-width="1.8" stroke-linecap="round" fill="none"/>'
(pwa / "icon.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="#1d5b86"/>' + PAPER + '</svg>\n', encoding="utf-8")
(pwa / "icon-maskable.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" fill="#1d5b86"/><g transform="translate(16 16) scale(.78) translate(-16 -16)">' + PAPER + '</g></svg>\n', encoding="utf-8")
import shutil
shutil.copytree(HERE / "icons", pwa / "icons", dirs_exist_ok=True)
(pwa / "favicon.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="#1d5b86"/><path d="M10 6h12v20l-2-1.5-2 1.5-2-1.5-2 1.5-2-1.5-2 1.5z" fill="#fff"/></svg>\n', encoding="utf-8")
(pwa / "sw.js").write_text("""// Network first for the app itself (so every online start gets the newest version), cache as the offline fallback.
const CACHE = "ewidencja-%s";
const FILES = ["./", "index.html", "manifest.webmanifest", "icon.svg", "icon-maskable.svg", "favicon.svg", "icons/paragon-192.png", "icons/paragon-512.png", "icons/paragon-maskable-512.png", "icons/paragon-apple-180.png"];
self.addEventListener("install", e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(FILES)).then(() => self.skipWaiting())); });
self.addEventListener("activate", e => { e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener("fetch", e => {
  const url = new URL(e.request.url);
  if (e.request.method !== "GET" || url.origin !== location.origin || url.pathname.endsWith("/version.json")) return;
  e.respondWith(
    Promise.race([fetch(e.request, {cache: "no-cache"}), new Promise((_, rej) => setTimeout(rej, 4000))])
      .then(r => { if (r.ok) { const copy = r.clone(); caches.open(CACHE).then(c => c.put(e.request, copy)); } return r; })
      .catch(() => caches.match(e.request, {ignoreSearch: true}).then(r => r || caches.match("index.html")))
  );
});
""" % version, encoding="utf-8")
print("PWA", version)

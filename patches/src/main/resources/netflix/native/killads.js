'use strict';
// Netflix ad-kill (self-contained, single-shot each, NO re-patch loop) + read-only monitor.
//  (A)   manifest pre/mid-roll (legacy model): AdsState hydration -> empty metadata.ads=[]
//  (ADV) dynamic ad-insertion master kill: empty adverts.adBreaks at its single manifest source
//  (DAI) dynamic ad-insertion belt: applyDaiPrefetch returns content unchanged when ads present
//  (MASTER) 13.0.1+ re-anchor: getAdMetadata -> empty ad-break list (if(0)+else b=[]); crash-free
//  (B)   pause overlay: z() saga -> force f=e.displayAd to void 0 -> no ad opportunity
//  (FP/GAID) privacy opt-ins (default OFF); (HH/MHU) household-prompt opt-in (default OFF)
//  MONITOR (read-only): KILLMARK(__adkill)/rawRealPods = legacy manifest ad kills; rawDisplayAd =
//  server pause ad delivered; BOOKMARK = distinct resume positions seen (resume/bookmark intact).
var logw = new NativeFunction(Module.findGlobalExportByName('__android_log_write'),
  'int', ['int', 'pointer', 'pointer']);
var TAG = Memory.allocUtf8String('KILL');
function L(m){ logw(6, TAG, Memory.allocUtf8String(m)); }
function pat(s){ return s.split('').map(function(c){return ('0'+c.charCodeAt(0).toString(16)).slice(-2);}).join(' '); }
function bytesOf(s){ var b=[]; for (var i=0;i<s.length;i++) b.push(s.charCodeAt(i)); return b; }
// ---------- scheduling helpers (2026-10) ----------
// WHY: Memory.scanSync holds Frida's single JS lock for the whole scan (~2.4s per full-heap pattern on the
// TV). The ad-kill passes (apply: ~15 patterns, fastMASTER, observe) and the old household passes (22
// patterns) are each tens of seconds of back-to-back scanSync, so on a device log (killlog3) one fastHH
// pass blocked the thread for 39s and starved the dispatcher break, every timer and the diagnostics.
// Memory.scan (async) runs on a worker thread and only calls back into JS per match: host test
// (frida 17): JS-thread worst gap 21ms vs 672ms for scanSync, same pass time, and a hooked function
// called from another thread was NOT slowed (1.28s vs 1.27s baseline; scanSync: 5.43s).
// - aScanAll(): async scan of every range with at most AS_MAX scans in flight (leave CPU for Netflix).
// - runSteps(): run steps one per timer tick so other work can interleave between them.
// ADK_HH_PERIOD: in household builds the ad-kill passes (apply/fastMASTER) are throttled to this period.
// Each is several synchronous full-heap scans that hold the JS lock, and the household patches found by
// the async scans can only be written from JS, i.e. between those blocks. (MASTER cannot land on the
// current 13.0.1 JS anyway: M2-MISS.)
var ADK_HH_PERIOD=120000;
// killlog4 (device): scans=2+11741 queued and barely moving. Every async scan completes by calling back
// into the JS thread, and once apply()/fastMASTER ran their multi-second synchronous steps back to back
// the callbacks only got a ~25ms slot between steps (~3 scans per 7s). So, in household builds:
//  - the ad-kill work (adkDefer) waits 60s after launch, and then only runs while NO async scan is pending
//    or running (hhBusy), and is further throttled to ADK_HH_PERIOD;
//  - household jobs have priority over the low-priority diagnostics (two queues);
//  - ranges under AS_MIN_RANGE are skipped (thousands of tiny thread-stack/arena mappings; the device
//    has ~550 rw- ranges, JS source lives in the big heap ranges).
// Queues (2026-10, after killlog5-7): 0 = eval-hook sources, 1 = household sweeps, 2 = ad-kill sweeps,
// 3 = diagnostics. killlog6/7 (fastADK added) showed the household layers landing ~10s later than the
// household-only build (killlog5): one ad-kill cycle (4 sweeps, ~2000 range jobs) sat ahead of the household
// pass in the single FIFO queue. Now (a) fastADK is held until household has landed (adkHold, below), and
// (b) once both families are queued they SHARE the pool: whichever family has fewer scans running goes next,
// so neither can starve the other (strict household priority starved the ad-kill in steady state: the
// persistent household detectors alone use nearly the whole pool).
var AS_MAX=2, AS_MIN_RANGE=32768, _asRun=0, _asRunP=[0,0,0,0], _asQ=[[],[],[],[]];
function hhBusy(){ return _asRun+_asQ[0].length+_asQ[1].length+_asQ[2].length+_asQ[3].length>0; }
function adkDefer(){ return HH_ENABLED && ((Date.now()-_fcT0)<60000 || hhBusy()); }
function aScanPick(){ if(_asQ[0].length) return 0;
  var h=_asQ[1].length>0, a=_asQ[2].length>0;
  if(h&&a) return (_asRunP[2]<_asRunP[1])?2:1;
  if(h) return 1; if(a) return 2; if(_asQ[3].length) return 3; return -1; }
function aScanPump(){ while(_asRun<AS_MAX){ var p=aScanPick(); if(p<0) return; var job=_asQ[p].shift(); _asRun++; _asRunP[p]++; job(p); } }
// Diagnostics: which range sizes actually hold the anchors (to pick AS_MIN_RANGE from data, not a guess).
var _rhN=0, _rhBy={};
function rangeHit(r,patStr){ if(_rhN>=48) return; var key=patStr.slice(0,29), c=_rhBy[key]||0; if(c>=4) return; _rhBy[key]=c+1; _rhN++;
  var t=patStr.split(' '), lbl=''; for(var i=0;i<t.length&&i<10;i++) lbl+=(t[i]==='??'?'?':String.fromCharCode(parseInt(t[i],16)));
  L('RANGEHIT '+lbl+' rangeSize='+r.size+' base='+r.base+' +'+(Date.now()-_fcT0)+'ms'); }
function aScanRange(r,patStr,onMatch,done,prio){
  var pq=(prio===true?3:(prio==null||prio===false?1:prio));
  _asQ[pq].push(function(p){ var fin=false;
    function end(){ if(fin) return; fin=true; _asRun--; _asRunP[p]--; try{ done(); }catch(e){ L('aScan done ERR '+e); } aScanPump(); }
    try{ Memory.scan(r.base,r.size,patStr,{ onMatch:function(a,sz){ if(pq!==0){ try{ rangeHit(r,patStr); }catch(e){} } try{ onMatch(a,sz); }catch(e){ L('aScan match ERR '+e); } }, onError:function(){ end(); }, onComplete:end }); }
    catch(e){ end(); } });
  aScanPump(); }
// Biggest ranges first: JS source strings are multi-MB allocations, so a first hit comes earlier.
function aScanAll(rs,patStr,onMatch,done,prio){ var list=[];
  for(var i=0;i<rs.length;i++) if(rs[i].size>=AS_MIN_RANGE&&rs[i].size<=128*1024*1024) list.push(rs[i]);
  list.sort(function(x,y){ return y.size-x.size; });
  var left=list.length; if(!left){ done(); return; }
  for(var k=0;k<list.length;k++) aScanRange(list[k],patStr,onMatch,function(){ if(--left===0) done(); },prio); }
var _rsLogged=false;
function logRangeStats(rs){ if(_rsLogged) return; _rsLogged=true;
  var n=[0,0,0,0], by=[0,0,0,0], th=[32768,262144,1048576,8388608];
  for(var i=0;i<rs.length;i++){ var s=rs[i].size; if(s>128*1024*1024) continue; for(var k=0;k<th.length;k++) if(s>=th[k]){ n[k]++; by[k]+=s; } }
  L('RANGESTAT rw-ranges='+rs.length+' >=32K:'+n[0]+'('+Math.round(by[0]/1048576)+'MB) >=256K:'+n[1]+'('+Math.round(by[1]/1048576)+'MB) >=1M:'+n[2]+'('+Math.round(by[2]/1048576)+'MB) >=8M:'+n[3]+'('+Math.round(by[3]/1048576)+'MB)'); }
function runSteps(steps,done,gated){ var i=0;
  (function next(){ if(i>=steps.length){ if(done) done(); return; }
    if(gated&&adkDefer()){ setTimeout(next,300); return; }   // ad-kill steps only run while no household scan is pending
    var st=steps[i++]; try{ st(); }catch(e){ L('step ERR '+e); } setTimeout(next,25); })(); }

// ---------- (A) manifest patch — legacy metadata.ads[] pod model ----------
// Kept for anyone still served the old model. Newer appboots deliver dynamic ads (see ADV/DAI);
// on those this anchor simply isn't present and patchA no-ops harmlessly.
var A_OLD='var f=e.value;f.syncAdStates();f.state.isHydrated&&"viewable"!==f.metadata.source&&f.applyHydration(f.state.hydrationSequenceId)';
var A_NEW='var f=e.value;f.metadata&&(f.metadata.ads.length&&(f.__adkill=f.metadata.ads.length),f.metadata.ads=[]);f.syncAdStates();/*...*/';
var aDone=false;
function patchA(rs){ if(aDone)return; if(A_NEW.length!==A_OLD.length){L('A length mismatch — ABORT');aDone=true;return;}
  var p=pat(A_OLD);
  for(var i=0;i<rs.length;i++){var r=rs[i];if(r.size>128*1024*1024)continue;
    try{var h=Memory.scanSync(r.base,r.size,p);for(var j=0;j<h.length;j++){Memory.protect(h[j].address,A_NEW.length,'rw-');h[j].address.writeByteArray(bytesOf(A_NEW));aDone=true;L('PATCH A: prepareAdBreakStates @'+h[j].address);}}catch(e){}}
}
// ---------- (ADV) empty adverts.adBreaks at its single source — the master ad kill ----------
// Netflix migrated clone ads to DYNAMIC server-side insertion — ad videos stitched as separate
// "playgraph" viewables (type:"ad", s0:ad-0-x -> padend -> content). ALL ad-break stitchers
// (applyDaiPrefetch, mergeReplacedAds, enrichAds, the VOD StatefulAdBreak map) read ONE upstream
// source: the manifest->adverts normaliser builds
//   T.adverts=__assign(__assign({},T.manifest.adverts),{adBreaks:(null===(ba=T.manifest.adverts.
//     adBreaks)||void 0===ba ? void 0 : ba.map(function(a,b){var c=ea.normalize(a.location...)})) })
// Change `ba.map` -> `[].map` (2 bytes, length-preserving): when ads ARE present this yields an
// EMPTY array, so every downstream `.adverts.adBreaks.length` is 0 and the ad-break orchestrator
// hits its `else return` (no StatefulAdBreaks built, enrichers get nothing) — one edit closes all
// ad paths at the source. The no-ads branch (ternary `void 0`) is untouched -> no crash on ad-free
// content. On-device verified (v13.0.1): pre-roll + mid-roll gone across movies, no crash.
var ADV_ANCHOR=':ba.map(function(a,b){var c=ea.normalize';  // unique source site
var ADV_OFF=1, ADV_EXP='ba';
var advDone=false;
function patchADV(rs){ if(advDone)return; var p=pat(ADV_ANCHOR);
  for(var i=0;i<rs.length;i++){var r=rs[i];if(r.size>128*1024*1024)continue;
    try{var h=Memory.scanSync(r.base,r.size,p);for(var j=0;j<h.length;j++){var t=h[j].address.add(ADV_OFF);var cur=null;try{cur=t.readCString(2);}catch(e){}if(cur!==ADV_EXP)continue;Memory.protect(t,2,'rw-');t.writeByteArray([0x5b,0x5d]);advDone=true;L('PATCH ADV: adverts.adBreaks source ba.map->[].map (empty all ad breaks) @'+t);}}catch(e){}}
}
// ---------- (ADVw) wildcard-tolerant ADV fallback (2026-09-13, experimental — #166) ----------
// The adverts.adBreaks normaliser re-minified alongside getAdMetadata, so the exact ADV anchor
// (:ba.map(...ea.normalize) scan-misses. Closing this matters: getAdMetadata's NEW middle branch
// `else if(a.adverts&&a.adverts.adBreaks.length)b=a.adverts.adBreaks.map(...)` rebuilds ad breaks
// from adverts.adBreaks when M1 forces if(0) — emptying adverts.adBreaks at the normaliser makes
// that guard false so the branch is skipped (-> else b=[]). Re-anchor by the STABLE tokens
// (.map(function( ... .normalize) and wildcard the churny map-source var. Only the ORIGINAL
// `<2char>.map->[].map` shape is safe to write length-preservingly; any other layout -> dump, no write.
var advwDone=false, advDumped=false;
function patchADVw(rs){ if(advDone||advwDone)return;
  // Anchor on the ad-normaliser's DISTINCTIVE callback shape: <var>.map(function(a,b){var
  // The adverts.adBreaks normaliser is `la.map(function(a,b){var c=ma.normalize(a.locationMs),
  // e=(0,v.getAdBreakDuration)(a.ads)...` — arity (a,b). The earlier false positive was the
  // normalizedPrograms getter `.map(function(c){return a.toNormalizedProgram(c)` — arity (c), and it
  // only matched because the old disambiguator keyed on ".normalize" (also in toNormalizedProgram).
  // Fix (2026-09-14, from adam8833's #166 dumps): anchor on `.map(function(a,b){var ` (excludes the
  // (c) getter) AND require a `locationMs`/`getAdBreakDuration` token in the window (ad-break-only).
  // <var> = the 2 bytes immediately before `.map`.
  var mp=pat('.map(function(a,b){var ');
  for(var i=0;i<rs.length;i++){var r=rs[i];if(r.size>128*1024*1024)continue;
    try{var h=Memory.scanSync(r.base,r.size,mp);
      for(var j=0;j<h.length;j++){ var mAddr=h[j].address, vAddr=mAddr.sub(2); // 2-char var before .map
        var v0=-1,v1=-1;try{v0=vAddr.readU8();v1=vAddr.add(1).readU8();}catch(e){continue;}
        if(!isAlpha(v0)||!isAlpha(v1))continue;
        var fwd=null;try{fwd=mAddr.readCString(180);}catch(e){}
        if(fwd==null||(fwd.indexOf('locationMs')<0&&fwd.indexOf('getAdBreakDuration')<0))continue;
        Memory.protect(vAddr,2,'rw-');vAddr.writeByteArray([0x5b,0x5d]);advwDone=true;
        L('PATCH ADVw: adverts.adBreaks source "'+String.fromCharCode(v0)+String.fromCharCode(v1)+'".map->[].map (empty all ad breaks, rename-tolerant) @'+vAddr);
        return;
      }
    }catch(e){}}
  // not found -> dump the normaliser region once (anchored on the ad-only locationMs) for re-anchor.
  if(!advDumped){ var mk='locationMs',mkp=pat(mk),hit=0;
    for(var i2=0;i2<rs.length&&hit<2;i2++){var r2=rs[i2];if(r2.size>128*1024*1024)continue;
      try{var h2=Memory.scanSync(r2.base,r2.size,mkp);for(var j2=0;j2<h2.length&&hit<2;j2++){var a2=h2[j2].address,ctx=null;try{ctx=a2.sub(180).readCString(260);}catch(e){}if(ctx==null||ctx.indexOf('.map(function')<0)continue;hit++;advDumped=true;L('ADVw DUMP@'+a2+' ctx='+JSON.stringify(ctx));}}catch(e){}}
  }
}
// ---------- (DAI) dynamic ad-insertion bypass — belt-and-suspenders alongside ADV ----------
//   a.prototype.applyDaiPrefetch=function(a,b){ b=this.getDaiPrefetcher(b);
//     var e=(b==null)?void 0:b.getAds();
//     return e&&0!==e.size ? a.map(function(a){...map break->ad if adBreakTriggerId in e...}) : a }
// `a` = the content breaks; the map INSERTS the prefetched DAI ads. Flipping the guard
// `0!==e.size` -> `0===e.size` (one byte, `!`->`=`) makes it return `a` UNCHANGED whenever ads
// ARE present -> no DAI ads stitched. Length-preserving, verify-before-write.
var DAI_ANCHOR='return e&&0!==e.size?a.map';   // '!' at index 11 (return e&&0[!]==e.size...)
var DAI_OFF=11, DAI_EXP='!';
var daiDone=false;
function patchDAI(rs){ if(daiDone)return; var p=pat(DAI_ANCHOR);
  for(var i=0;i<rs.length;i++){var r=rs[i];if(r.size>128*1024*1024)continue;
    try{var h=Memory.scanSync(r.base,r.size,p);for(var j=0;j<h.length;j++){var t=h[j].address.add(DAI_OFF);var cur=null;try{cur=t.readCString(1);}catch(e){}if(cur!==DAI_EXP)continue;Memory.protect(t,1,'rw-');t.writeByteArray([0x3d]);daiDone=true;L('PATCH DAI: applyDaiPrefetch 0!==->0=== (bypass DAI ad stitch) @'+t);}}catch(e){}}
}
// ---------- (A2) legacy metadata.ads presentation gate (2026-08-14 re-anchor) ----------
// Netflix moved the legacy pre/mid-roll off the compiled-away prepareAdBreakStates hydration
// reducer (which killed patch-A's source anchor -> A=false) but the ad DATA still lands in each
// StatefulAdBreak's `metadata.ads`. The single source-resident gate that turns that data into
// PRESENTABLE ad objects is `_syncAdsLength` (the `ads` getter delegates to it):
//   {..e=this._statefulAdBreak;e.syncAdStates();
//    var f=null!==(b=null===(a=e.metadata.ads)||void 0===a?void 0:a.length)&&void 0!==b?b:0;
//    this._ads.length=f;for(a=0;a<f;a++)(c=this._ads)[a]||(c[a]=new n.AseAd(e,a,this.config));..}
// Flipping the read `e.metadata.ads` -> `e.metadata.axs` (nonexistent prop) makes a=undefined ->
// f=0 -> _ads emptied -> zero AseAd objects instantiated for EVERY break, whatever manifest path
// populated metadata.ads. Length-preserving (3 bytes), verify-before-write. Covers the leaky
// legacy titles that bypass adverts.adBreaks (ADV) entirely.
var A2_ANCHOR='e.metadata.ads)||void 0===a?void 0:a.length)&&void 0!==b?b:0;this._ads.length';
var A2_OFF=11, A2_EXP='ads';   // 'ads' at index 11 of the anchor (e.metadata.[ads])
var a2Done=false;
function patchA2(rs){ if(a2Done)return; var p=pat(A2_ANCHOR);
  for(var i=0;i<rs.length;i++){var r=rs[i];if(r.size>128*1024*1024)continue;
    try{var h=Memory.scanSync(r.base,r.size,p);for(var j=0;j<h.length;j++){var t=h[j].address.add(A2_OFF);var cur=null;try{cur=t.readCString(3);}catch(e){}if(cur!==A2_EXP)continue;Memory.protect(t,3,'rw-');t.writeByteArray([0x61,0x78,0x73]);a2Done=true;L('PATCH A2: _syncAdsLength metadata.ads->axs (empty legacy ad pods) @'+t);}}catch(e){}}
}
// ---------- (MASTER) getAdMetadata source kill — 13.0.1+ re-anchor (2026-08-24, STABLE v2) ----------
// On 13.0.1 build 25028 the ad path was REFACTORED: A2/ADV/DAI source strings drifted (their
// patchers scan-miss and no-op). ALL ad breaks now flow through ONE builder:
//   a.prototype.getAdMetadata=function(a){ var b,c,d=this.mediaEventsManager.getAds(a);
//     if(d){ var e=...; b=d.map(function(a){return new r.StatefulAdBreak(a,...)}) } else return;
//     b=this.adBreakHydrator.enrichAds(b); b=this.adErrorHandler.enrichAds(a,b);
//     b=this.enrichAdsWithEmbeddedExtension(a,...); return ...b... }
// v1 (SHIPPED-CRASH, reverted): flipped only if(d)->if(0), which hits `else return;` -> returns
// UNDEFINED even for ad-titles while getAds() still returned real ads -> app-state inconsistency
// -> CRASH on Back/teardown. Fix: return a VALID EMPTY ARRAY, never undefined. TWO length-preserving
// edits, both verify-before-write:
//   M1: if(d) -> if(0)         (skip building real StatefulAdBreaks)
//   M2: else return; -> else b=[]  ;   (b becomes []; every enrichAds() is array.map over [] -> [];
//       enrichAdsWithEmbeddedExtension iterates [] -> attaches nothing -> function returns valid [])
// Source-dumped + both bodies confirmed 2026-08-24 (experimental/netflix-native-adstrip/REANCHOR_13.0.1.md).
// Supersedes drifted A2/ADV/DAI on 13.0.1+; older anchors kept (scan-miss here, cover pre-refactor).
var M1_ANCHOR='getAds(a);if(d){var e=', M1_OFF=13, M1_EXP='d';         // the 'd' inside if(d)
var M2_ANCHOR='else return;b=this.adBreakHydrator', M2_OLD='else return;', M2_NEW='else b=[]  ;'; // 12->12
var m1Done=false, m2Done=false, masterDone=false;
function patchMASTER(rs){ if(masterDone)return;
  if(!m1Done){ var p1=pat(M1_ANCHOR);
    for(var i=0;i<rs.length;i++){var r=rs[i];if(r.size>128*1024*1024)continue;
      try{var h=Memory.scanSync(r.base,r.size,p1);for(var j=0;j<h.length;j++){var t=h[j].address.add(M1_OFF);var cur=null;try{cur=t.readCString(1);}catch(e){}if(cur!==M1_EXP)continue;Memory.protect(t,1,'rw-');t.writeByteArray([0x30]);m1Done=true;L('PATCH M1: getAdMetadata if(d)->if(0) @'+t);}}catch(e){}}
  }
  if(!m2Done){ var p2=pat(M2_ANCHOR);
    for(var i2=0;i2<rs.length;i2++){var r2=rs[i2];if(r2.size>128*1024*1024)continue;
      try{var h2=Memory.scanSync(r2.base,r2.size,p2);for(var j2=0;j2<h2.length;j2++){var t2=h2[j2].address;var cur2=null;try{cur2=t2.readCString(M2_OLD.length);}catch(e){}if(cur2!==M2_OLD)continue;Memory.protect(t2,M2_NEW.length,'rw-');t2.writeByteArray(bytesOf(M2_NEW));m2Done=true;L('PATCH M2: getAdMetadata else return;->else b=[] (valid empty, no crash) @'+t2);}}catch(e){}}
  }
  if(m1Done&&m2Done){ masterDone=true; L('PATCH MASTER: getAdMetadata neutralised (empty ad-break list) — stable v2'); }
}
// Tight early MASTER scanner — win the FIRST-TITLE race. getAdMetadata builds ALL breaks (pre+mid)
// for a title in ONE call at playback start; the 2s apply() poll can land AFTER that call on a fast
// start, so the first title keeps its ads. This 120ms loop lands MASTER within ~120ms of the source
// materialising (~+25s), before the first getAdMetadata runs. Write-once (masterDone guard) — stops
// as soon as both edits land. Mirrors fastHH.
var _fastMn=0;
function fastMASTER(){ if(masterDone)return; if(hhYield()||adkDefer()){ setTimeout(fastMASTER,hhYield()?250:1000); return; } _fastMn++;
  var _rm=null; try{ _rm=Process.enumerateRanges('rw-'); }catch(e){}
  runSteps(_rm?[function(){ patchMASTER(_rm); }, function(){ if(!masterDone) patchMASTERw(_rm); }]:[], function(){
    if(masterDone){ L('fastMASTER: applied by pass '+_fastMn+(mwDone?' (wildcard fallback)':'')); return; }
    // household builds: MASTER cannot land on the current 13.0.1 JS (M2-MISS) and each pass is several
    // synchronous scans, so do not hammer it every 120ms (it starved the household patches).
    if(_fastMn<500) setTimeout(fastMASTER, HH_ENABLED?ADK_HH_PERIOD:120);   // household builds: slow
  }, true);
}
// ---------- (MASTERw) wildcard-tolerant MASTER fallback (2026-09-13, experimental — issue #166) --
// Most Netflix "server-side" ad drift is just a re-minify that RENAMES single-char locals, which
// makes the exact-string MASTER anchors scan-miss and the kill silently no-op (#166: KILLMARK=0
// while rawRealPods>0). This fallback re-matches getAdMetadata by its STABLE API tokens (getAds /
// adBreakHydrator) and WILDCARDS the churny locals, so a pure rename no longer breaks us. Additive:
// only runs when the exact patchMASTER missed (masterDone=false), so builds where the exact anchors
// still hit are unchanged. Reads the REAL accumulator var before writing (never hardcodes 'b') to
// avoid the v1 wrong-var crash. Length-preserving, verify-before-write.
function isAlpha(cc){ return (cc>=97&&cc<=122)||(cc>=65&&cc<=90); }   // a-z A-Z (minified local)
var mwDone=false, mwDumped=false;
// ATOMIC: locate BOTH the M1 (if-guard) and M2 (else-return) edit sites BEFORE writing EITHER, so we
// can never leave M1 flipped without M2 (that is the v1 `if(0)...else return;`->undefined crash).
// If M1 is found but M2 is not, we write NOTHING (getAdMetadata stays intact = crash-safe; A2/DAI
// still provide ad coverage) and dump the region after M1 ONCE so M2 can be re-anchored precisely.
function patchMASTERw(rs){ if(masterDone||mwDone)return;
  // --- locate M1: getAds( <arg> );if( <cond> ){var  -> the <cond> byte (offset 13) ---
  var p1=pat('getAds(')+' ?? '+pat(');if(')+' ?? '+pat('){var '), m1off=13;
  var m1addr=null,m1cc=-1;
  for(var i=0;i<rs.length&&!m1addr;i++){var r=rs[i];if(r.size>128*1024*1024)continue;
    try{var h=Memory.scanSync(r.base,r.size,p1);for(var j=0;j<h.length;j++){var t=h[j].address.add(m1off);var cc=-1;try{cc=t.readU8();}catch(e){}if(!isAlpha(cc))continue;m1addr=t;m1cc=cc;break;}}catch(e){}}
  if(!m1addr)return;   // getAdMetadata body not resident yet — try again next pass
  // M1-ONLY recovery (2026-09-27, #212 build 25028): if the EXACT patchMASTER already landed M2
  // (else return;->else b=[]) but its M1 missed because this build renamed the getAds local
  // (if(d)->if(c) etc.), the else already yields a VALID [] — so flipping M1 alone is crash-safe
  // (no v1 undefined). The atomic M2 search below would MISS here anyway (exact M2 consumed the
  // 'else return;' string -> the 25028 'MASTERw M2-MISS' with rawRealPods leaking from the still-live
  // if(<cond>) first branch). Flip M1 and finish.
  if(m2Done){
    Memory.protect(m1addr,1,'rw-'); m1addr.writeByteArray([0x30]);
    var vb=-1; try{vb=m1addr.readU8();}catch(e){}   // read-back: confirm the flip actually took
    mwDone=true; masterDone=true;
    L('PATCH MASTERw: getAdMetadata if('+String.fromCharCode(m1cc)+')->if(0) @'+m1addr+' (M1-only; exact M2 already landed else b=[]) verify='+(vb===0x30?'OK(now 0)':'FAIL(byte='+vb+')')+' — rename-drift recovered, v2.1');
    return;
  }
  // --- locate M2: else return; [gap] <acc> =this.adBreakHydrator ---
  // The accumulator sits just before '=this.adBreakHydrator'. Older builds had NO gap
  // (else return;b=this...); the 2026-09 build inserted a newline (else return;\nb=this...). Try
  // gap sizes 1 and 2 so both layouts match; <acc> is the alpha byte right before '=this.'.
  // Overwrite the 12-byte 'else return;' with 'else <acc>=[]  ;' so the else path yields a VALID
  // empty array (never undefined) that flows through the enrich chain -> returns [] (no v1 crash).
  var m2addr=null,m2vc=-1;
  var gaps=[1,2];
  for(var gi=0;gi<gaps.length&&!m2addr;gi++){ var gap=gaps[gi];
    var p2=pat('else return;'); for(var gg=0;gg<gap;gg++) p2+=' ??'; p2+=' '+pat('=this.adBreakHydrator');
    var accOff=12+gap-1;   // the <acc> byte = last wildcard, immediately before '=this.'
    for(var i2=0;i2<rs.length&&!m2addr;i2++){var r2=rs[i2];if(r2.size>128*1024*1024)continue;
      try{var h2=Memory.scanSync(r2.base,r2.size,p2);for(var j2=0;j2<h2.length;j2++){var vc=-1;try{vc=h2[j2].address.add(accOff).readU8();}catch(e){}if(!isAlpha(vc))continue;m2addr=h2[j2].address;m2vc=vc;break;}}catch(e){}}
  }
  if(m2addr){
    var vch=String.fromCharCode(m2vc), neu='else '+vch+'=[]  ;';
    if(neu.length===12){
      Memory.protect(m1addr,1,'rw-');m1addr.writeByteArray([0x30]);
      Memory.protect(m2addr,12,'rw-');m2addr.writeByteArray(bytesOf(neu));
      mwDone=true;masterDone=true;
      L('PATCH MASTERw: getAdMetadata if('+String.fromCharCode(m1cc)+')->if(0) @'+m1addr+' + else return;->else '+vch+'=[] @'+m2addr+' (atomic, rename-tolerant) — string-drift recovered');
    }
    return;
  }
  // M1 found, M2 not -> CRASH-SAFE: write nothing; dump the region after M1 once for re-anchor.
  if(!mwDumped){ mwDumped=true; var ctx=null; try{ctx=m1addr.sub(24).readCString(700);}catch(e){}
    L('MASTERw M2-MISS (no write, crash-safe) dump@'+m1addr+' cond="'+String.fromCharCode(m1cc)+'" ctx='+JSON.stringify(ctx)); }
}
// ---------- (MASTERdump) read-only recon: dump CURRENT getAdMetadata body on drift ----------
// If BOTH the exact and wildcard MASTER matches miss, the drift is a real REFACTOR, not a rename —
// we need the new source to re-anchor. This dumps ~500 chars from the getAdMetadata token to logcat
// ONCE so the new body can be read off-device. Runs only if masterDone stays false ~34s in (ads
// would already be leaking by then). Read-only; no writes.
var _mdumpN=0, mdumpDone=false;
function dumpMASTER(){ if(masterDone||mdumpDone)return; if(HH_ENABLED){ mdumpDone=true; return; }   // household builds: the dump is already in hand (M2-MISS), skip its synchronous scan
  _mdumpN++;
  if(_mdumpN<17){ setTimeout(dumpMASTER,2000); return; }   // wait ~34s for appboot JS to materialise
  var rs=Process.enumerateRanges('rw-'), mk='getAdMetadata', mp=pat(mk), hits=0;
  for(var i=0;i<rs.length;i++){var r=rs[i];if(r.size>128*1024*1024)continue;
    try{var h=Memory.scanSync(r.base,r.size,mp);for(var j=0;j<h.length&&hits<4;j++){var addr=h[j].address,ctx=null;try{ctx=addr.readCString(520);}catch(e){}if(ctx==null||ctx.indexOf(mk)<0)continue;hits++;L('MASTER-DUMP hit@'+addr+' ctx='+JSON.stringify(ctx));}}catch(e){}}
  mdumpDone=true; L('MASTER-DUMP: '+hits+' getAdMetadata source hit(s) — re-anchor from these bodies (or 0 = token itself renamed)');
}
// ---------- (B) pause patch ----------
var B_ANCHOR='void 0:e.displayAd',B_OLD='e.displayAd',B_NEW='void 0     ';
var bDone=false;
function patchB(rs){ if(bDone)return; var p=pat(B_ANCHOR);
  for(var i=0;i<rs.length;i++){var r=rs[i];if(r.size>128*1024*1024)continue;
    try{var h=Memory.scanSync(r.base,r.size,p);for(var j=0;j<h.length;j++){var t=h[j].address.add(7);var cur=null;try{cur=t.readCString(B_OLD.length);}catch(e){}if(cur!==B_OLD)continue;Memory.protect(t,B_NEW.length,'rw-');t.writeByteArray(bytesOf(B_NEW));bDone=true;L('PATCH B: pause z() displayAd->void0 @'+t);}}catch(e){}}
}
// ---------- (FP) local network fingerprint minimization (OPT-IN; default OFF) ----------
// Blanks ip/ipv6/mac/ssid in the c() interface map that feeds the nrdp device signal
// (u.ifList). ONLY changes what is REPORTED to Netflix, not the device's actual
// networking (keeps ifname/type). Does NOT stop the server-side "traveling" prompt
// (that's driven by your public IP). The "Minimize Network Fingerprint" opt-in Morphe
// patch flips FP_ENABLED to true in this bundled script.
var FP_ENABLED=false;
var FP_ANCH='ip:e.ipAddress,ipv6:i(e),mac:e.macAddress,name:e.ifname,ssid:e.ssid';
var FP_NEW ='ip:""         ,ipv6:[]  ,mac:""          ,name:e.ifname,ssid:""    ';
var fpDone=false;
function patchFP(rs){ if(fpDone||!FP_ENABLED)return; if(FP_NEW.length!==FP_ANCH.length){L('FP length mismatch — ABORT');fpDone=true;return;}
  var p=pat(FP_ANCH);
  for(var i=0;i<rs.length;i++){var r=rs[i];if(r.size>128*1024*1024)continue;
    try{var h=Memory.scanSync(r.base,r.size,p);for(var j=0;j<h.length;j++){Memory.protect(h[j].address,FP_NEW.length,'rw-');h[j].address.writeByteArray(bytesOf(FP_NEW));fpDone=true;L('PATCH FP: blank ip/ipv6/mac/ssid @'+h[j].address);}}catch(e){}}
}
// ---------- (GAID) advertising-ID (GAID) minimization (OPT-IN; default OFF) ----------
// nrdp.device.getSystemValue("advertisingIdDetails", function(e){
//   var t=!!e&&"advertisingId"in e, a=(null==e?void 0:e.advertisingId)||"",
//       o="true"===...limitAdTracking, i=o?"":a;
//   logEvent("AdvertisingIdCollectionEvent","netflix",{advertisingId:i,...}) })
// We overwrite the property read `e.advertisingId` (15 bytes) with `void 0` (pad to
// 15) so a="" -> i="" and the actual GAID is never reported in the collection event.
// Length-preserving; keeps advertisingIdSupported/limitAdTracking booleans truthful.
// Folded under the "Minimize Network Fingerprint" opt-in (flips GAID_ENABLED true).
var GAID_ENABLED=false;
var GAID_ANCH='null==e?void 0:e.advertisingId)';
var GAID_OFF=15;                 // offset of 'e.advertisingId' within anchor ("null==e?void 0:")
var GAID_OLD='e.advertisingId';
var GAID_NEW='void 0         ';  // 15 chars: 'void 0' + 9 spaces
var gaidDone=false;
function patchGAID(rs){ if(gaidDone||!GAID_ENABLED)return; if(GAID_NEW.length!==GAID_OLD.length){L('GAID length mismatch — ABORT');gaidDone=true;return;}
  var p=pat(GAID_ANCH);
  for(var i=0;i<rs.length;i++){var r=rs[i];if(r.size>128*1024*1024)continue;
    try{var h=Memory.scanSync(r.base,r.size,p);for(var j=0;j<h.length;j++){var t=h[j].address.add(GAID_OFF);var cur=null;try{cur=t.readCString(GAID_OLD.length);}catch(e){}if(cur!==GAID_OLD)continue;Memory.protect(t,GAID_NEW.length,'rw-');t.writeByteArray(bytesOf(GAID_NEW));gaidDone=true;L('PATCH GAID: e.advertisingId->void0 @'+t);}}catch(e){}}
}
// ---------- (HH) household / "traveling" misdetection + ownership prompt suppression (OPT-IN) ----------
// Default OFF; the "Suppress Household Prompt" Morphe patch flips HH_ENABLED to true.
// The account-sharing redux-saga stores the server's misdetection challenge, then dispatches
//   put(setAccountSharingFlags({isActiveMisdetectionSession:!0}))  to ACTIVATE the challenge.
// The consumer hook computes  "ready"===status && (y=f, w=h)  ->  {misdetectionAvailable:y,
// netflixHouseholdAvailable:w}, where f=isActiveMisdetectionSession ("you're traveling") and
// h=isNetflixHouseholdAvailable ("This is my account / Create an account" ownership screen — a
// SEPARATE gate). We flip BOTH dispatch flags !0 -> !1 (WRITE side) AND force the render outputs
// f/h -> 0 (READ side); all length-preserving 1-byte edits. On a fresh launch these land (+~11s)
// before the gate materialises (~+30s) so the app proceeds with no prompt.
// HONEST SCOPE: client-side prompt suppression only; household detection is server-side/public-IP.
// CREDIT: CLCS-interstitial enforcement seam identified with reference to Nikflix
// (github.com/YidirK/Nikflix, GPL-3.0) — author YidirK and API-block contributor Buckibarnes17
// (github.com/Buckibarnes17), credited in the Nikflix v2.0.1 release notes. No code shared —
// independent native-app implementation (appboot-heap byte edit, not fetch/XHR override). See NOTICE.
var HH_ENABLED=false;
var HH_ANCHORS=[
  {a:'setAccountSharingFlags)({isActiveMisdetectionSession:!0', chr:'0', to:'1', lbl:'flag:isActiveMisdetectionSession'},
  {a:'setAccountSharingFlags)({isNetflixHouseholdAvailable:!0', chr:'0', to:'1', lbl:'flag:isNetflixHouseholdAvailable'},
  {a:'(y=null!=f&&f,', off:12, chr:'f', to:'0', lbl:'render:misdetectionAvailable(y)'},
  {a:'w=null!=h&&h)',  off:11, chr:'h', to:'0', lbl:'render:netflixHouseholdAvailable(w)'}
];
var hhFlipped={},hhDone=false;
// Async household anchors (replaces the sync patchHH/fastHH, which blocked the JS thread ~39s per pass).
// Anchors are the UNPATCHED text, so an already-patched copy never matches again: rescanning a flipped
// anchor only ever finds fresh copies (a re-evaluated module). Cycle plan: until hhDone, every unflipped
// anchor; afterwards the 'w' read gate alone is the cheap detector for a fresh copy of the consumer
// module, and finding one forces a full recheck of all four next cycle (the other module copies arrive
// together); never-seen anchors are retried every 5th cycle.
var HH_W_LBL='render:netflixHouseholdAvailable(w)', _hhCyc=0, _hhLogged=false, _hhForceAll=false;
function hhAnchorAt(a,AN){ var off=(AN.off!=null?AN.off:AN.a.length-1), exp=(AN.chr||'0'), nb=(AN.to||'1').charCodeAt(0);
  var t=a.add(off), cur=null; try{ cur=t.readCString(1); }catch(e){}
  if(cur!==exp) return 0; Memory.protect(t,1,'rw-'); t.writeByteArray([nb]);
  if(hhDone&&AN.lbl===HH_W_LBL) _hhForceAll=true;      // a fresh copy of the module appeared
  hhFlipped[AN.lbl]=true;
  L('PATCH HH: '+AN.lbl+' '+exp+'->'+(AN.to||'1')+' @'+t); return 1; }
function patchHHAsync(rs,done){ _hhCyc++;
  var jobs=[], all=_hhForceAll; _hhForceAll=false;
  for(var ai=0;ai<HH_ANCHORS.length;ai++){ var AN=HH_ANCHORS[ai];
    if(all) jobs.push(AN);
    else if(!hhDone){ if(!hhFlipped[AN.lbl]) jobs.push(AN); }
    else if(AN.lbl===HH_W_LBL) jobs.push(AN);
    else if(!hhFlipped[AN.lbl]&&_hhCyc%5===0) jobs.push(AN); }
  if(!jobs.length){ done(); return; }
  var left=jobs.length;
  function one(AN){ aScanAll(rs,pat(AN.a),function(a){ hhAnchorAt(a,AN); },
      function(){ if(--left===0){ if(hhFlipped[HH_W_LBL]) hhDone=true; done(); } }); }
  for(var ji=0;ji<jobs.length;ji++) one(jobs[ji]); }
// fastHH: persistent async household loop. No yielding to the ad-kill any more (it cannot land on this
// build, and async scans do not block it); cadence is light for the whole session because the household
// modules can load (or re-load) at any time.
var _fastHHn=0;
function fastHH(){ if(!HH_ENABLED)return; _fastHHn++;
  var rs=null; try{ rs=Process.enumerateRanges('rw-'); }catch(e){}
  if(!rs){ setTimeout(fastHH,2000); return; }
  var pend=2;
  function fin(){ if(--pend>0) return;
    if(hhDone&&!_hhLogged){ _hhLogged=true; L('fastHH: all HH anchors flipped by pass '+_fastHHn+' at +'+(Date.now()-_fcT0)+'ms'); }
    setTimeout(fastHH, _hhForceAll?300:((hhDone&&mhuHits>0)?8000:(_fastHHn<60?1000:4000))); }   // 300ms: a fresh module copy was just found, finish its other anchors now
  patchHHAsync(rs,fin); neuterMhuAsync(rs,fin); }
// ---------- (MHU) household-screen render neuter — belt-and-suspenders (follows HH opt-in) ----------
// LAYER 2 of household suppression. LAYER 1 (HH_ANCHORS/fastHH) neuters the DECISION so the app
// PROCEEDS — the actual fix. This layer is a fallback: if the decision flip loses the ~30s race,
// null the household screens' render() so the prompt shows BLANK instead of the ownership UI.
// Each CLCS screen is registered as <PATTERN>,render:function(e){<DECLS>\nreturn(0,u.j)(...)}; we
// overwrite <DECLS> (just after '{' up to the first newline) with 'return null;' + spaces, leaving
// the original '\nreturn(...)' as valid unreachable code -> render() returns null, module parses.
// Newline located at RUNTIME (resilient across the household screens). Household (Mhu*) patterns
// only — the profile picker ("who's watching") is a different, non-Mhu screen and is never touched.
var MHU_ENABLED=HH_ENABLED;   // ships with the "Suppress Household Prompt" opt-in (flips HH_ENABLED).
var MHU_PATS=[
  'MHU_RESOLUTION_LANDING','MHU_MANAGE_HOUSEHOLD',
  'MHU_SET_PRIMARY_HOUSEHOLD_CONTEXT','MHU_SET_PRIMARY_HOUSEHOLD_EMAIL_CONFIRM',
  'MHU_SET_PRIMARY_HOUSEHOLD_TEXT_CONFIRM','MHU_SET_PRIMARY_HOUSEHOLD_VERIFY',
  'MHU_SET_PRIMARY_HOUSEHOLD_LATER','MHU_SET_PRIMARY_HOUSEHOLD_SUCCESS',
  'MHU_CREATE_ACCOUNT_PARTNER','MHU_CREATE_ACCOUNT_RENDEZVOUS_CONTEXT',
  'MHU_CREATE_ACCOUNT_RENDEZVOUS_EMAIL','MHU_CREATE_ACCOUNT_RENDEZVOUS_EMAIL_CONFIRM',
  'MHU_CREATE_ACCOUNT_RENDEZVOUS_PHONE','MHU_CREATE_ACCOUNT_RENDEZVOUS_PHONE_CONFIRM',
  'MHU_VERIFY_TRAVEL','MHU_CHALLENGE_ERROR'
];
var MHU_PREFIX='return null;';        // 12 bytes; padded with spaces to the decls length
var mhuDoneSet={}, mhuHits=0;
// Neuter ONE MHU render hit (addr = start of '<NAME>,render:function(e){'). Returns 1 if written,
// 0 if already neutered / unexpected layout. Shared by the heap sweep and the eval load-hook.
function mhuNeuterAt(addr, anchorLen, nm, how){
  var body=addr.add(anchorLen);                        // first byte after '{'
  var head=null; try{head=body.readCString(4);}catch(e){}
  if(head==='retu') return 0;                          // already neutered
  if(head!=='var ') return 0;                          // unexpected layout — abort this hit
  var bytes=null; try{bytes=body.readByteArray(400);}catch(e){return 0;}
  var u8=new Uint8Array(bytes), nlIdx=-1;
  for(var k=0;k<u8.length;k++){ if(u8[k]===0x0a){ nlIdx=k; break; } }
  if(nlIdx<MHU_PREFIX.length) return 0;                // no newline in range / decls too short
  var repl=MHU_PREFIX; while(repl.length<nlIdx) repl+=' ';
  Memory.protect(body,nlIdx,'rw-'); body.writeByteArray(bytesOf(repl));
  L('PATCH MHU'+(how||'')+': '+nm+' render->null ('+nlIdx+'B decls) @'+body);
  return 1;
}
// ONE async scan for the short seed 'MHU_' finds every screen registration (16 names in one block on
// the device); each hit is matched against the known '<NAME>,render:function(e){' anchors and neutered
// in place. Replaces 16 separate full-heap scans per pass (~40s of scanSync). Persistent: a re-evaluated
// module is neutered again (mhuNeuterAt skips already-neutered renders).
function mhuSeedAt(a,how){ var s=null; try{ s=a.readCString(90); }catch(e){ return 0; }
  for(var i=0;i<MHU_PATS.length;i++){ var nm=MHU_PATS[i], anc=nm+',render:function(e){';
    if(s.indexOf(anc)!==0) continue;
    var head=null; try{ head=a.add(anc.length).readCString(4); }catch(e){}
    if(head==='retu'){ mhuDoneSet[nm]=true; return 0; }
    if(mhuNeuterAt(a,anc.length,nm,how)){ mhuDoneSet[nm]=true; mhuHits++; return 1; }
    return 0; }
  return 0; }
function neuterMhuAsync(rs,done){ if(!MHU_ENABLED){ done(); return; }
  var seen=0;
  aScanAll(rs,pat('MHU_'),function(a){ if(++seen>1500) return; mhuSeedAt(a); }, done); }

// ---------- (CLCS) EXPERIMENTAL runtime interstitial-enforcement neuter — Nikflix seam ----------
// Nikflix (web) shows household enforcement is a PER-/watch RUNTIME GraphQL call, not a boot flag:
//   op "CLCSInterstitialPlaybackAndPostPlayback" @ web.prod.cloud.netflix.com/graphql -> they return
//   {"data":{}} and the prompt never fires. On ATV the net stack is native (Gibbon), not fetch/XHR,
//   so we can't override fetch. Instead we target the JS that CONSUMES the CLCS response, the same
//   memory-scan+byte-edit way fastMASTER neuters getAdMetadata — a race-free play-time seam that
//   beats the ~30s appboot HH/MHU flag race. See killads.js:175 credit + NOTICE.
//
// STATUS: the ATV consumer string is UNKNOWN. clcsProbe (read-only) locates every heap hit of the
// op name and dumps the surrounding source to logcat so we can read the real anchor off-device on
// .211. Once identified, add the exact {a,off,chr,to,lbl} to CLCS_ANCHORS and the neuter goes live.
// Gated behind HH_ENABLED (household opt-in) so nothing runs unless the user enabled suppression.
// Nikflix's web op is PascalCase CLCSInterstitialPlaybackAndPostPlayback, but prior ATV heap recon
// (2026-08-13) found the ATV JS heap carries the camelCase `clcsInterstitialPlaybackAndPostPlayback`
// and — crucially — the HOUSEHOLD gate is a DIFFERENT op: `clcsInterstitialProfileGate`
// (QueryType.ProfileGate), which also drives legit profile-select, so any neuter must discriminate
// the MHU/household variant (see neuterMhuRenders). We probe the whole family + the ProfileGate router
// site so the on-device dump shows exactly which consumer string to anchor.
// FOCUSED probe (2026-08-30): the 4-marker sweep already told us the only JS-SOURCE anchor is
// `pushClcsInterstitialGate` (0x50c/0x53); the op names live only in network/telemetry buffers.
// Narrow to that one marker and dump WIDE context (before+after) to capture the router push fn AND
// its `d(e,t)` builder, so we can design a discriminating length-preserving neuter of the
// ProfileGate/MHU branch without touching generic profile-select.
var CLCS_MARKERS=[
  'pushClcsInterstitialGate'                       // router push seam — the JS-source anchor
];
// CLCS gate-dispatcher neuter (2026-08-30, from focused probe @0x5334054e). The gate router matches
// the server interstitial `type` against case labels; household ownership arrives as type
// "clcsInterstitialGate" and is pushed to the CLCS_INTERSTITIAL_GATE screen via pushClcsInterstitialGate.
// We flip the LEADING 'c' of that ONE case string literal ("clcsInterstitialGate"->"xlcsInterstitialGate",
// 1 byte, length-preserving) so the type never matches -> falls through to default = NO navigation, no
// household screen. Scope is precise: the sibling label "clcsInterstitialPreProfileGate" shares the body
// so it still fires via its OWN label, and "who's watching" profile-select is a DIFFERENT case
// (profileSelectionTransitionAnimation) — neither is touched. Write-once via apply() (NO scan loop, so
// no fastMASTER starvation). NOTE: also drops other clcsInterstitialGate-typed interstitials
// (price-change/upsell — desired); verify no load-bearing gate (maturity/PIN) shares the type on-device.
var CLCS_ANCHORS=[
  {a:'case"clcsInterstitialGate":case"clcsInterstitialPreProfileGate"', off:5, chr:'c', to:'x',
   lbl:'dispatch:clcsInterstitialGate-case-break'},
  // 2026-09-24 (.210, live challenge): the HOUSEHOLD prompt raised at profile select is fetched with
  // QueryType.ProfileGate, and the fetch builder labels it componentName:"clcsInterstitialPreProfileGate"
  // (not "clcsInterstitialGate"), so the label above never saw it. Break this label too, same 1-byte flip.
  {a:'case"clcsInterstitialPreProfileGate":', off:5, chr:'c', to:'x',
   lbl:'dispatch:clcsInterstitialPreProfileGate-case-break'}
];
var clcsFlipped={},clcsDone=false;
// fastCLCS (2026-09-24): race-win for the gate dispatcher. On .210 both labels were broken at +55s via
// apply() (which runs ~15 full scans per pass) and the household gate STILL routed — the ProfileGate
// interstitial is fetched + pushed while the profile screen loads, before apply() lands. This loop scans
// ONE combined pattern every 150ms from launch and flips both case-label bytes the instant the dispatcher
// source is resident, so V8 compiles the already-broken labels on the first call. Write-once.
var FC_ANCHOR='case"clcsInterstitialGate":case"clcsInterstitialPreProfileGate":', FC_OFFS=[5,32];
// ROUTE 2 (2026-09-24): clicking PLAY re-fetches an interstitial (the ATV twin of Nikflix's
// CLCSInterstitialPlaybackAndPostPlayback) and doRouteOnFetchedInterstitial pushes the household gate
// DIRECTLY (pushClcsInterstitialGate / replaceWithClcsInterstitialGate), never touching the dispatcher.
// Its first guard is `...fetchDgsData"}),!v){p.next=24;break}` = "no interstitial -> exit to playback".
// Flip the var byte to '0' (`!v` -> `!0`, always true) so every fetched playback interstitial is
// treated as absent -> straight to playback. Same effect as Nikflix returning {data:{}}.
// Anchored on Netflix's own debug string (stable across re-minify); verify var+`){` before writing.
// NOTE: also skips UMS notices fetched at playback (payment-hold etc.) — acceptable for this opt-in.
var FR_ANCHOR='doRouteOnFetchedInterstitial:fetchDgsData"}),!';
var frDone=false;
var _fcN=0, _fcT0=Date.now();
// _lastEvalT: stamped by the eval load-hook (below) whenever Netflix evals a real script (diagnostic).
var _lastEvalT=0;
// Cold-start priority (2026-09-24): on a cold boot every full-memory scanner (fastMASTER, apply, observe)
// queued ahead of fastCLCS and its 2nd pass slipped to +52s — after the profile gate had already routed.
// While the household dispatcher is still unpatched (household opt-in only, max 30s), the other scanners
// step aside so fastCLCS owns the JS thread. Nothing can play before profile select, so the ad-kill loses
// no coverage; the 30s cap bounds the delay if the dispatcher anchor ever drifts.
function hhYield(){ return HH_ENABLED && !clcsDone && (Date.now()-_fcT0)<30000; }
// 2026-10 (fork): this used to stop for good once each anchor had been flipped once, and gave up
// entirely after 1400 passes (~20-30 min). But the playback household module is evaluated ON PLAY,
// and a re-eval produces a FRESH unpatched copy (V8 compiles it as a new script because its source no
// longer matches our patched copy) — so the 2nd episode, or any play after the cap, got the prompt
// ~1-2s into playback. It now keeps re-sweeping for unpatched copies for the whole session
// (idempotent: already-flipped bytes are skipped) at a light 2s cadence.
// ASYNC sweep (2026-10): see the scheduling helpers at the top. Two async scans per cycle (dispatcher
// labels, route-2 guard) over every range, results applied from the match callback. Persistent: it keeps
// rescanning for unpatched copies for the whole session (a re-evaluated module is a fresh copy).
var _frSeen=false, _frBad=false;
// Match handlers shared by the heap loop (fastCLCS) and the eval hook (hhPatchSource).
function clcsPairAt(a){ var w=0;
  for(var k=0;k<FC_OFFS.length;k++){ var t=a.add(FC_OFFS[k]); if(t.readU8()!==0x63) continue; Memory.protect(t,1,'rw-'); t.writeU8(0x78); w++; }
  return w; }
function clcsMarkDone(){ clcsDone=true; for(var ai=0;ai<CLCS_ANCHORS.length;ai++) clcsFlipped[CLCS_ANCHORS[ai].lbl]=true; }
function route2At(a){ var t2=a.add(FR_ANCHOR.length);       // 1 = wrote, 0 = already patched, -1 = guard shape unexpected
  var vc=t2.readU8(), c1=t2.add(1).readU8(), c2=t2.add(2).readU8();
  if(!_frSeen){ _frSeen=true; L('DIAG route2 anchor RESIDENT @'+t2+' next='+JSON.stringify(t2.readCString(24))+' at +'+(Date.now()-_fcT0)+'ms'); }
  if(vc===0x30) return 0;                                      // already '0'
  if(!isAlpha(vc)||c1!==0x29||c2!==0x7b){ if(!_frBad){ _frBad=true; L('DIAG route2 anchor found but guard shape UNEXPECTED: '+JSON.stringify(t2.sub(120).readCString(200))); } return -1; }   // expect <var>){
  Memory.protect(t2,1,'rw-'); t2.writeU8(0x30);
  L('PATCH CLCS(route2): doRouteOnFetchedInterstitial !'+String.fromCharCode(vc)+'->!0 (playback interstitial -> exit) @'+t2); return 1; }
function fastCLCS(){ if(!HH_ENABLED)return; _fcN++;
  var rs=null; try{ rs=Process.enumerateRanges('rw-'); }catch(e){}
  if(!rs){ setTimeout(fastCLCS,2000); return; }
  logRangeStats(rs);
  var hit=0, wrote=0, hit2=0, wrote2=0, left=2;
  function fin(){ if(--left>0) return;
    if(hit&&!clcsDone) clcsMarkDone();
    if(wrote) L('PATCH CLCS(fast): gate case-labels broken x'+hit+' at +'+(Date.now()-_fcT0)+'ms (pass '+_fcN+')');
    if(hit2) frDone=true;
    if(wrote2) L('PATCH CLCS(route2): wrote x'+wrote2+' at +'+(Date.now()-_fcT0)+'ms (pass '+_fcN+')');
    // tight while the dispatcher is pending (~2 min), otherwise a light 2s sweep for the session.
    if(!clcsDone&&_fcN<800) setTimeout(fastCLCS,150);
    else setTimeout(fastCLCS,2000); }
  aScanAll(rs,pat(FC_ANCHOR),function(a){ hit++; wrote+=clcsPairAt(a); }, fin);
  aScanAll(rs,pat(FR_ANCHOR),function(a){ var r=route2At(a); if(r>=0) hit2++; if(r===1) wrote2++; }, fin);
}
// ---------- (HHDIAG) household diagnostics — read-only, sliced (2026-10) ----------
// 1) HHSTATUS every 5s (~5 min): which household layers have landed. Cheap; the old ANCHOR MAP never
//    printed in 49s because the full-heap scans starved its timer.
// 2) Context dumps of the REAL household routing JS from the TV heap (the repo has none on file), so the
//    route that still shows the household screen after profile select can be found and neutered
//    precisely. Same sliced scan style as fastCLCS; each marker dumped at most HHD_MAX times, only where
//    the surrounding text looks like JS source (not network/telemetry buffers).
var HH_DIAG=true;
var HH_DUMPS=false;   // household routing JS dumps (already captured in killlog5; they only queued 2000 jobs behind the sweeps)
var HHD_MARKERS=['pushClcsInterstitialGate','doRouteOnFetchedInterstitial','lcsInterstitialPreProfileGate','isNetflixHouseholdAvailable'];
var HHD_BEFORE=360, HHD_AFTER=840, HHD_MAX=5;
var hhdSeen={}, hhdCount={}, _hhdN=0, _hhdDone=false;
function hhStatus(){ if(!HH_DIAG) return;
  L('HHSTATUS +'+Math.round((Date.now()-_fcT0)/1000)+'s clcs='+clcsDone+' route2='+frDone+' hh='+hhDone+' mhu='+mhuHits+'/'+MHU_PATS.length+' ads[adv='+advDone+' master='+masterDone+' b='+bDone+' dai='+daiDone+'] fcPass='+_fcN+' hhPass='+_fastHHn+' scans='+_asRun+'+'+_asQ[1].length+'/'+_asQ[2].length+'/'+_asQ[3].length+' (household/ads/diag) eval='+_evalN+'/'+_evalSrcCalls+'src adk='+(_adkStarted?'on':(adkHold()?'held':'idle')));
  if(Date.now()-_fcT0<300000) setTimeout(hhStatus,5000); }
function looksLikeJs(c){ var n=0; for(var i=0;i<c.length&&n<8;i++){ var ch=c.charCodeAt(i); if(ch===59||ch===123||ch===125||ch===40) n++; } return n>=8; }
function hhDiag(){ if(!HH_DIAG||_hhdDone) return; _hhdN++;
  var rs=null; try{ rs=Process.enumerateRanges('rw-'); }catch(e){}
  if(!rs){ setTimeout(hhDiag,4000); return; }
  var left=0;
  function after(){ var all=true; for(var q=0;q<HHD_MARKERS.length;q++) if((hhdCount[HHD_MARKERS[q]]||0)<HHD_MAX) all=false;
    if(all||_hhdN>=25){ _hhdDone=true; L('HHDIAG done after '+_hhdN+' passes'); return; }
    setTimeout(hhDiag,5000); }
  function one(mk){ left++;
    aScanAll(rs,pat(mk),function(a){ if((hhdCount[mk]||0)>=HHD_MAX) return;
        var key=mk+'@'+a; if(hhdSeen[key]) return; var ctx=null;
        try{ ctx=a.sub(HHD_BEFORE).readCString(HHD_BEFORE+mk.length+HHD_AFTER); }catch(e){}
        if(ctx==null||ctx.indexOf(mk)<0||!looksLikeJs(ctx)) return;
        hhdSeen[key]=true; hhdCount[mk]=(hhdCount[mk]||0)+1;
        L('HHDIAG '+mk+' #'+hhdCount[mk]+' @'+a+' +'+Math.round((Date.now()-_fcT0)/1000)+'s ctx='+JSON.stringify(ctx)); },
      function(){ if(--left===0) after(); }, true); }
  for(var mi=0;mi<HHD_MARKERS.length;mi++) if((hhdCount[HHD_MARKERS[mi]]||0)<HHD_MAX) one(HHD_MARKERS[mi]);
  if(left===0) after(); }

// ---------- (ADK) async ad-kill for household builds, re-anchored to the 13.0.1 JS served in 2026-10 ----------
// killlog5 (device): ads leaked through. Two causes. (1) the sync ad-kill (apply/fastMASTER) was deferred
// by my own household gate and barely ran. (2) Netflix's served JS drifted: the manifest->adverts normaliser
// is now `null==(h=r.manifest.adverts.adBreaks)?void 0:h.map(function(e,t){var i=c.normalize(e.locationMs)`
// (1-char local, args (e,t); the old anchors need a 2-char local and (a,b)), and getAdMetadata's else branch
// is now `else{if(!e.adverts||!e.adverts.adBreaks.length)return;i=e.adverts.adBreaks.map(function(e){...` (old
// M2 looked for a bare `else return;` -> 'MASTERw M2-MISS').
// Same two kills as before, re-expressed; each is verify-before-write, length-preserving, rename-tolerant
// (locals are matched by regex, not hardcoded) and runs on the async pool, persistently, so a re-evaluated
// (fresh, unpatched) copy is caught too:
//  ADV2   adverts.adBreaks source:  h=r.manifest.adverts.adBreaks  ->  h=[]<spaces>   (OPT-IN, ADK_ADV_ENABLED)
//  MASTER2 getAdMetadata: `if(t){`->`if(0){` (skip the legacy getAds branch), the else branch's early
//         `return;` -> a no-op and its `i=e.adverts.adBreaks.map(` -> `i=[]<spaces>.map(`, so EVERY title yields
//         a VALID empty array (the documented device-verified M1+M2 shape: `else b=[]`). killlog8: the first
//         version kept the `if(!e.adverts||!e.adverts.adBreaks.length)return;` guard, and with ADV2 applied
//         adBreaks.length is always 0, so getAdMetadata returned UNDEFINED for every title (the half-emptied
//         state the design notes forbid) and ads still played. Order: map source, guard, then M1 last.
//  B, DAI exact anchors still match on 13.0.1 (B landed in earlier logs) and are kept.
var ADK_ADV_ENABLED=false;   // ADV empties the manifest-level adBreaks (breaks removed, not just ads); the proven
                             // config killed ads with MASTER alone and left the normaliser intact. Opt in to re-test.
var ADK_ADV_ANCH='.manifest.adverts.adBreaks)?void 0:', ADK_ADV_SRC='.manifest.adverts.adBreaks';
var ADK_M1_PAT=pat('getAds(')+' ?? '+pat(');if(')+' ?? '+pat('){var ');
// groups: 1 local, 2 guard ('return;' original | 6 spaces+';' neutralised), 3 accumulator, 4 map source (original | '[]'+spaces)
var ADK_M2_RE=/else\{if\(!([A-Za-z_$][\w$]*)\.adverts\|\|!\1\.adverts\.adBreaks\.length\)(return;| {6};)([A-Za-z_$][\w$]*)=(\1\.adverts\.adBreaks|\[\] *)\.map\(function\(/;
var _adkN=0, _adkLogged={};
function adkPad(txt,len){ while(txt.length<len) txt+=' '; return txt; }
// Per-match handlers (return 1 if they wrote). Shared by the async heap loop below and by the eval hook
// (hhPatchSource), which feeds them matches found inside one just-evaluated script string.
function adkAdvAt(a){
  var pre=null,fwd=null; try{ pre=a.sub(40).readCString(40); fwd=a.add(ADK_ADV_ANCH.length).readCString(220); }catch(e){ return 0; }
  var m=/null==\(([A-Za-z_$][\w$]*)=([A-Za-z_$][\w$]*)$/.exec(pre); if(!m) return 0;
  if(fwd.indexOf(m[1]+'.map(function(')!==0||fwd.indexOf('locationMs')<0) return 0;   // the ad-break normaliser only
  var len=m[2].length+ADK_ADV_SRC.length, t=a.sub(m[2].length);
  Memory.protect(t,len,'rw-'); t.writeByteArray(bytesOf(adkPad('[]',len))); advDone=true;
  L('PATCH ADK ADV: adverts.adBreaks source '+m[2]+ADK_ADV_SRC+'->[] (empty all ad breaks) @'+t+' now='+JSON.stringify(t.sub(8).readCString(len+40)));
  return 1; }
var _adkBodyLogged=false;
function adkMasterAt(a){
  var ctx=null; try{ ctx=a.readCString(1100); }catch(e){ return 0; }
  var m1=/^getAds\(([A-Za-z_$][\w$]*)\);if\(([A-Za-z_$]|0)\)\{var /.exec(ctx); if(!m1) return 0;
  var m2=ADK_M2_RE.exec(ctx);
  if(!m2){ if(!_adkLogged.m2){ _adkLogged.m2=true; L('ADK master: getAdMetadata else-branch shape UNEXPECTED, no write: '+JSON.stringify(ctx.slice(0,700))); } return 0; }
  var X=m2[1], G=m2[2], Y=m2[3], S=m2[4];
  var gIdx=m2.index+('else{if(!'+X+'.adverts||!'+X+'.adverts.adBreaks.length)').length, sIdx=gIdx+G.length+Y.length+1, wrote=0;
  if(S.charAt(0)!=='['){                                   // 1) map source -> [] (alone it is harmless)
    var t2=a.add(sIdx), tl=S.length; if(ctx.substr(sIdx,tl)!==S) return 0;
    Memory.protect(t2,tl,'rw-'); t2.writeByteArray(bytesOf(adkPad('[]',tl))); wrote++;
    L('PATCH ADK MASTER: else-branch '+S+'.map -> [].map @'+t2); }
  if(G==='return;'){                                       // 2) the early return would give undefined -> no-op
    var tg=a.add(gIdx); if(ctx.substr(gIdx,7)!=='return;') return 0;
    Memory.protect(tg,7,'rw-'); tg.writeByteArray(bytesOf('      ;')); wrote++;
    L('PATCH ADK MASTER: else-branch early return -> no-op (getAdMetadata yields [] for every title, never undefined) @'+tg); }
  if(m1[2]!=='0'){                                         // 3) M1 last: skip the legacy getAds branch
    var t1=a.add(13); Memory.protect(t1,1,'rw-'); t1.writeByteArray([0x30]); wrote++;
    var vb=-1; try{ vb=t1.readU8(); }catch(e){}
    L('PATCH ADK MASTER: getAdMetadata if('+m1[2]+')->if(0) @'+t1+' verify='+(vb===0x30?'OK':'FAIL('+vb+')')); }
  masterDone=true; m1Done=true; m2Done=true;
  if(wrote&&!_adkBodyLogged){ _adkBodyLogged=true; try{ L('ADK MASTER body (patched) @'+a+' '+JSON.stringify(a.readCString(2300))); }catch(e){} }   // recon: the full return expression
  return wrote?1:0; }
function adkBAt(a){ var t=a.add(7), cur=null; try{ cur=t.readCString(B_OLD.length); }catch(e){}
  if(cur!==B_OLD) return 0; Memory.protect(t,B_NEW.length,'rw-'); t.writeByteArray(bytesOf(B_NEW)); bDone=true;
  L('PATCH ADK B: pause z() displayAd->void0 @'+t); return 1; }
function adkDaiAt(a){ var t=a.add(DAI_OFF), cur=null; try{ cur=t.readCString(1); }catch(e){}
  if(cur!==DAI_EXP) return 0; Memory.protect(t,1,'rw-'); t.writeByteArray([0x3d]); daiDone=true;
  L('PATCH ADK DAI: applyDaiPrefetch 0!==->0=== @'+t); return 1; }
// Ad-kill scans run on queue 2 (below household, sharing the pool with it; see the pool comment at the top).
function adkAdv(rs,done){ aScanAll(rs,pat(ADK_ADV_ANCH),adkAdvAt,done,2); }
function adkMaster(rs,done){ aScanAll(rs,ADK_M1_PAT,adkMasterAt,done,2); }
function adkB(rs,done){ aScanAll(rs,pat(B_ANCHOR),adkBAt,done,2); }
function adkDai(rs,done){ aScanAll(rs,pat(DAI_ANCHOR),adkDaiAt,done,2); }
// HOLD: killlog6/7 showed fastADK (armed at +300ms) delaying every household layer by ~10s, which pushed the
// household prompt past the profile select. The ad modules are not needed until a title plays, so wait until
// the household layers have FIRST landed (dispatcher labels, HH flags, route 2), then start.
// ADK_HH_WAIT_MS is only a safety net so a drifted household anchor cannot keep the ad-kill off for good.
var ADK_HH_WAIT_MS=30000, ADK_LIGHT_MS=8000, _adkStarted=false;
// MHU is NOT required: it is the blank-screen fallback layer, and killlog8 ran the whole session at mhu=0/16 with no prompt.
function hhLanded(){ return clcsDone && hhDone && frDone; }
function adkHold(){ return HH_ENABLED && !hhLanded() && (Date.now()-_fcT0)<ADK_HH_WAIT_MS; }
// Persistent loop. Until the kills have landed once: ADV + MASTER every cycle (B until it lands), quickly.
// Afterwards a cheap detector for fresh (re-evaluated, unpatched) copies: ADV + MASTER every ADK_LIGHT_MS,
// B every 4th cycle. DAI never matched in any device log, so it only gets the first two cycles, then every 12th.
function fastADK(){ if(!HH_ENABLED) return;
  if(adkHold()){ setTimeout(fastADK,500); return; }
  if(!_adkStarted){ _adkStarted=true; L('fastADK: starting at +'+(Date.now()-_fcT0)+'ms (household landed='+hhLanded()+' clcs='+clcsDone+' hh='+hhDone+' route2='+frDone+' mhu='+mhuHits+')'); }
  _adkN++;
  var rs=null; try{ rs=Process.enumerateRanges('rw-'); }catch(e){}
  if(!rs){ setTimeout(fastADK,2000); return; }
  var jobs=ADK_ADV_ENABLED?[adkAdv,adkMaster]:[adkMaster];
  if(!bDone||_adkN%4===0) jobs.push(adkB);
  if(_adkN<=2||_adkN%12===0) jobs.push(adkDai);
  var pend=jobs.length;
  function fin(){ if(--pend>0) return;      // evaluated when the cycle ends: the scans above may have just landed the kills
    setTimeout(fastADK, ((advDone||!ADK_ADV_ENABLED)&&masterDone&&bDone)?ADK_LIGHT_MS:(_adkN<60?2500:8000)); }
  for(var ji=0;ji<jobs.length;ji++) jobs[ji](rs,fin); }

// ---------- (ADDIAG) ad-path recon — read-only, starts once the ad-kill has started (killlog8) ----------
// killlog8: every ad patch landed before the first play and no fresh player copy appeared, yet pre-roll and
// mid-roll still played. The repo has no dump of the CURRENT ad consumers, so dump them: the getAdMetadata
// callers/definition, the empty-break handler, the embedded-extension enricher, the playgraph builder and the
// legacy pod seams. JS-source hits are dumped whole (up to ADD_MAX each); non-source hits (telemetry/network
// buffers) are dumped as short ADDIAG-DATA windows, which also show whether a runtime event such as
// emptyAdBreakComplete fired. Sliced on the ad queue (2), so it never delays the household sweeps.
var AD_DIAG=true;
var ADD_MARKERS=['getAdMetadata','emptyAdBreakComplete','enrichAdsWithEmbeddedExtension','createAdsPlaygraph','_syncAdsLength','prepareAdBreakStates','StatefulAdBreak'];
var ADD_BEFORE=300, ADD_AFTER=1100, ADD_MAX=3, ADD_DATA_MAX=2, addSeen={}, addCount={}, addData={}, _addN=0;
function adDiag(){ if(!AD_DIAG||!HH_ENABLED) return;
  if(!_adkStarted){ setTimeout(adDiag,2000); return; }
  _addN++;
  var rs=null; try{ rs=Process.enumerateRanges('rw-'); }catch(e){}
  if(!rs){ setTimeout(adDiag,5000); return; }
  var left=0;
  function after(){ var all=true; for(var q=0;q<ADD_MARKERS.length;q++) if(!addCount[ADD_MARKERS[q]]) all=false;
    if(all||_addN>=4){ L('ADDIAG done after '+_addN+' passes'); return; }
    setTimeout(adDiag,15000); }
  function one(mk){ left++;
    aScanAll(rs,pat(mk),function(a){
        var key=mk+'@'+a; if(addSeen[key]) return; addSeen[key]=true; var ctx=null;
        try{ ctx=a.sub(ADD_BEFORE).readCString(ADD_BEFORE+mk.length+ADD_AFTER); }catch(e){}
        if(ctx==null||ctx.indexOf(mk)<0) return;
        var t=Math.round((Date.now()-_fcT0)/1000);
        if(looksLikeJs(ctx)){ if((addCount[mk]||0)>=ADD_MAX) return; addCount[mk]=(addCount[mk]||0)+1;
          L('ADDIAG '+mk+' #'+addCount[mk]+' @'+a+' +'+t+'s ctx='+JSON.stringify(ctx)); }
        else { if((addData[mk]||0)>=ADD_DATA_MAX) return; addData[mk]=(addData[mk]||0)+1;
          L('ADDIAG-DATA '+mk+' #'+addData[mk]+' @'+a+' +'+t+'s ctx='+JSON.stringify(ctx.slice(Math.max(0,ADD_BEFORE-160),ADD_BEFORE+mk.length+240))); } },
      function(){ if(--left===0) after(); }, 2); }
  for(var mi=0;mi<ADD_MARKERS.length;mi++) if(!addCount[ADD_MARKERS[mi]]) one(ADD_MARKERS[mi]);   // markers already dumped are not rescanned
  if(left===0) after(); }

// Read-only diagnostic: find each CLCS_MARKERS string in the JS heap and dump ~100 chars of context
// per hit so the runtime consumer site can be identified from logcat. Runs only while HH_ENABLED and
// stops once ANY marker is seen resident (per-marker recon showed household loads ~+30-44s in), to
// avoid log spam. Household family is JS-only (2026-08-13: libnetflix.so had 0 hits), so heap-scan
// is the correct surface — do NOT expect these in native memory.
// DEV-ONLY recon flag, decoupled from HH_ENABLED. The probe is a heavy multi-marker heap scan that
// competes with fastMASTER (the getAdMetadata pre-roll kill) on the single JS thread; leaving it on
// in a household build starves the ad-kill race and lets a pre-roll slip. It has ALREADY captured its
// target (2026-08-29: anchor = `pushClcsInterstitialGate` in JS source @0x50c/0x53; the ProfileGate /
// Playback op names appear only in network+telemetry buffers, not anchorable). Keep OFF unless re-recon.
// Run this build WITHOUT the household opt-in: pushClcsInterstitialGate is the GENERIC gate router
// (resident on any appboot), so fastHH never runs and the probe doesn't compete with fastMASTER —
// protecting the ad-kill race that the last (household+probe) build starved.
var CLCS_PROBE_ENABLED=false;
var CLCS_CTX_BEFORE=220, CLCS_CTX_AFTER=460;   // wide window: capture push fn + d(e,t) builder
var _clcsProbeN=0, clcsProbeDone=false;
function clcsProbe(){ if(!CLCS_PROBE_ENABLED||clcsProbeDone)return; _clcsProbeN++;
  var rs=Process.enumerateRanges('rw-'), found=0;
  for(var mi=0;mi<CLCS_MARKERS.length;mi++){ var mk=CLCS_MARKERS[mi], mp=pat(mk), mhits=0;
    for(var i=0;i<rs.length;i++){var r=rs[i];if(r.size>128*1024*1024)continue;
      try{var h=Memory.scanSync(r.base,r.size,mp);
        for(var j=0;j<h.length&&mhits<6;j++){
          var addr=h[j].address, ctx=null;
          try{ctx=addr.sub(CLCS_CTX_BEFORE).readCString(CLCS_CTX_BEFORE+mk.length+CLCS_CTX_AFTER);}catch(e){}
          // JS source only: readable dumps contain the marker name; binary/network buffers won't.
          if(ctx==null||ctx.indexOf(mk)<0) continue;
          mhits++; found++;
          L('CLCS-PROBE hit@'+addr+' ctx='+JSON.stringify(ctx));
        }
      }catch(e){}
    }
  }
  if(found>0){ clcsProbeDone=true; L('CLCS-PROBE: '+found+' JS-source hit(s) on pass '+_clcsProbeN+' — design ProfileGate/MHU neuter from the d(e,t) builder'); return; }
  if(_clcsProbeN<240) setTimeout(clcsProbe, 250);   // ~60s, lighter cadence (no fastHH competing)
}

// ---------- (EVAL) household load-hook — patch each script's SOURCE before V8 compiles it ----------
// 2026-10 (fork). WHY: every household edit above rewrites JS source bytes sitting in the heap, and
// that only works if it lands before V8 lazily compiles the function. The playback household gate
// (route 2) lives in a module Netflix loads ON PLAY: loadScript -> nrdp.gibbon.eval -> the gate runs
// when the interstitial reply arrives ~1-2s later and compiles from the still-unpatched source. A
// polling heap sweep (full memory, competing with apply/observe on one Frida thread) loses that race,
// which is exactly the "prompt pops a second or two into the episode" symptom.
//
// HOW: hook the Gibbon2Bridge `eval` callback prologue (0x137626c on 13.0.1/25028 — proven live on
// .211, see experimental/netflix-household-loadhook/ABI_DECODE_2026-09-15.md §7) and, in onEnter,
// apply the SAME verified, length-preserving household edits directly to the script String's chars
// (V8 13.2, 32-bit, no pointer compression: length @+8, Latin1 chars @+12) before the call proceeds.
// The search is confined to that one string (no whole-memory scanSync inside the callback — that is
// what stalled appboot before). Every edit is verify-before-write, so an unexpected layout is a no-op.
// The source String is found by a short bounded walk from r0/r1/r2 (one hop), as the §7 probe did.
//
// SCRIPT CACHE: Netflix's bootstrap JS (embedded in libnetflix.so) code-caches every script —
//   nr.script.addEventListener("script",(e=>{0!==e.version&&e.usedCache||e.cache(1)}))  and, on
//   uiLoaded, e.cache(100) for each script (bytecode compiled SO FAR, i.e. including functions that
//   already ran). V8 accepts a cache whose source has the same LENGTH, and all our edits are
//   length-preserving, so a stale cache built from unpatched source would silently win on warm launches.
// HH_NOCACHE=1 removes that listener and turns the uiLoaded e.cache(100) into a no-op (both
// length-preserving, in the bootstrap source); =2 additionally calls nr.script.clearScriptCache() once
// at bootstrap. Default 0 (off): the first device build (=2, scanning inside the eval callback) hung at
// the splash screen, so these stay opt-in until a device run shows which one is safe.
var EVALHOOK_ENABLED=false;   // opt-in: unverified on device (first builds hung at the splash; see EVALHOOK_2026-10.md)
var HH_NOCACHE=0;            // 0 = leave Netflix's script cache alone (default), 1 = stop producing new
                             // caches, 2 = also clearScriptCache() at bootstrap (suspected boot stall)
// EVAL_DEFER: do the anchor scan on Frida's thread right after the eval call, NOT inside Netflix's eval
// thread. onEnter only does a few hundred pointer reads to find the source String and queues it; the
// targeted scan of that one string then runs within milliseconds — long before the play-time gate runs
// (~1-2s later). Scanning inside the callback (8 MB appboot x several patterns, while waiting on the
// Frida JS lock) stalled boot at the splash screen.
var EVAL_DEFER=true;
// EVAL_ARM_DLOPEN: also arm via an android_dlopen_ext hook. OFF: builds with it hung at the splash on
// device (Interceptor's onLeave rewrites the return address libdl uses to pick the caller's linker
// namespace — a known way to break library loading on Android 7+). Arming by polling is enough: the
// play-time household module loads long after libnetflix.so.
var EVAL_ARM_DLOPEN=false;
// EVAL_ARM_DELAY_MS: do not attach the hook during boot. Netflix's eval callback fires hundreds of
// times while appboot loads, and every call has to wait for the Frida JS lock; the repo's original
// note (LATE-ARM, "+40s") said the same and I wrongly deleted it. The play-time household module loads
// long after this, and the sliced sweeps above cover the first minute (profile select).
var EVAL_ARM_DELAY_MS=60000;
// EVAL_ONENTER_NOOP: diagnostic only — attach the hook but do nothing in onEnter except count.
var EVAL_ONENTER_NOOP=false;
var EVAL_PROLOGUE=0x137626c;                 // Gibbon2Bridge eval callback prologue (13.0.1 build 25028)
var EVAL_SIG=[[0x0,0xe92d48f0],[0x14,0xe1a07002],[0x18,0xe1a04001]];  // push{r4-r7,fp,lr}; mov r7,r2; mov r4,r1
var CACHE_A_OLD='nr.script.addEventListener("script",(e=>{0!==e.version&&e.usedCache||e.cache(1)}))';
var CACHE_A_NEW=(HH_NOCACHE>=2)?'(()=>{try{nr.script.clearScriptCache()}catch(e){}})()':'void 0';
var CACHE_B_OLD='e&&(e.version<100||!e.usedCache)&&e.cache(100)';
var CACHE_B_NEW='e&&(e.version<100||!e.usedCache)&&void 0';
while(CACHE_A_NEW.length<CACHE_A_OLD.length) CACHE_A_NEW+=' ';
while(CACHE_B_NEW.length<CACHE_B_OLD.length) CACHE_B_NEW+=' ';
var _evalN=0, _evalPatched=0, evalHooked=false;

function wr1(t,b){ try{ t.writeU8(b); }catch(e){ Memory.protect(t,1,'rw-'); t.writeU8(b); } }
function wrS(t,str){ var b=bytesOf(str); try{ t.writeByteArray(b); }catch(e){ Memory.protect(t,b.length,'rw-'); t.writeByteArray(b); } }
function scanIn(base,size,s){ try{ return Memory.scanSync(base,size,pat(s)); }catch(e){ return []; } }
function scanRaw(base,size,hexPat){ try{ return Memory.scanSync(base,size,hexPat); }catch(e){ return []; } }

// Bootstrap script-cache producers (see header). Returns sites written.
function noCachePatchRange(base,size,how){
  var n=0, j, h;
  h=scanIn(base,size,CACHE_A_OLD);
  for(j=0;j<h.length;j++){ wrS(h[j].address,CACHE_A_NEW); n++; L('PATCH EVAL'+how+': script cache listener removed'+(HH_NOCACHE>=2?' (+clearScriptCache)':'')+' @'+h[j].address); }
  h=scanIn(base,size,CACHE_B_OLD);
  for(j=0;j<h.length;j++){ wrS(h[j].address,CACHE_B_NEW); n++; L('PATCH EVAL'+how+': uiLoaded e.cache(100) -> no-op @'+h[j].address); }
  return n;
}
// Patch ONE just-evaluated source string [base, base+size) with every household + ad edit, using the same
// match handlers as the heap loops. Async (worker-thread scans, top priority) so Netflix's eval thread and
// Frida's JS thread are never blocked by a multi-MB source; done(n) gets the number of edits written.
function hhHookJobs(){
  var jobs=[], i;
  jobs.push([pat(FC_ANCHOR), function(a){ var w=clcsPairAt(a); clcsMarkDone(); return w; }]);
  jobs.push([pat(FR_ANCHOR), function(a){ var r=route2At(a); if(r>=0) frDone=true; return r===1?1:0; }]);
  for(i=0;i<HH_ANCHORS.length;i++) (function(AN){ jobs.push([pat(AN.a), function(a){ var w=hhAnchorAt(a,AN); if(hhFlipped[HH_W_LBL]) hhDone=true; return w; }]); })(HH_ANCHORS[i]);
  if(MHU_ENABLED) jobs.push([pat('MHU_'), function(a){ return mhuSeedAt(a,' EVAL'); }]);
  if(ADK_ADV_ENABLED) jobs.push([pat(ADK_ADV_ANCH), adkAdvAt]);
  jobs.push([ADK_M1_PAT, adkMasterAt]);
  jobs.push([pat(B_ANCHOR), adkBAt]); jobs.push([pat(DAI_ANCHOR), adkDaiAt]);
  if(HH_NOCACHE>0){ jobs.push([pat(CACHE_A_OLD), function(a){ wrS(a,CACHE_A_NEW); return 1; }]); jobs.push([pat(CACHE_B_OLD), function(a){ wrS(a,CACHE_B_NEW); return 1; }]); }
  return jobs; }
function hhPatchSource(base,size,tag,done){
  var jobs=hhJobs0||(hhJobs0=hhHookJobs()), left=jobs.length, n=0;
  for(var i=0;i<jobs.length;i++) (function(j){
    aScanRange({base:base,size:size},j[0],function(a){ try{ n+=j[1](a); }catch(e){ L('hook handler ERR '+e); } },
      function(){ if(--left===0&&done) done(n); }, 0); })(jobs[i]); }
var hhJobs0=null;

// Is p (untagged) a V8 SeqOneByteString holding readable script text? Returns its length or 0.
function seqStrLen(p){
  try{
    var len=p.add(8).readU32(); if(len<1024||len>32*1024*1024) return 0;
    var u8=new Uint8Array(p.add(12).readByteArray(48));
    for(var k=0;k<u8.length;k++){ var c=u8[k]; if(!(c===9||c===10||c===13||(c>=32&&c<127))) return 0; }
    p.add(12+len-1).readU8();               // whole body mapped
    return len;
  }catch(e){ return 0; }
}
// Bounded walk: r0/r1/r2, the first 16 words behind each, one more hop of 8 words. Collects every
// distinct tagged pointer that resolves to a readable one-byte script String.
function findEvalSources(ctx){
  var out=[], seen={};
  function tryTagged(v){
    if(v.isNull()||v.and(1).toInt32()!==1) return;
    var p=v.and(ptr(1).not()), key=p.toString(); if(seen[key]) return; seen[key]=1;
    var len=seqStrLen(p); if(len) out.push({p:p,len:len});
  }
  var regs=[ctx.r0,ctx.r1,ctx.r2];
  for(var r=0;r<regs.length;r++){ var base=regs[r]; tryTagged(base);
    for(var i=0;i<16;i++){ var w; try{ w=base.add(i*4).readPointer(); }catch(e){ break; }
      tryTagged(w);
      if(w.and(1).toInt32()===1) continue;  // tagged object: already tried as a String
      for(var k=0;k<8;k++){ var w2; try{ w2=w.add(k*4).readPointer(); }catch(e){ break; } tryTagged(w2); }
    }
  }
  return out;
}

var _evalQ=[], _evalDrainArmed=false;
function patchEvalSrc(src,tag){
  if(seqStrLen(src.p)!==src.len) return;     // moved/collected since queued: fallback sweep covers it
  var t0=Date.now();
  hhPatchSource(src.p.add(12), src.len, tag, function(n){ if(n){ _evalPatched+=n; L('EVAL'+tag+': '+n+' edit(s) applied (len='+src.len+', '+(Date.now()-t0)+'ms)'); } });
}
function drainEvalQ(){ _evalDrainArmed=false;
  while(_evalQ.length){ var q=_evalQ.shift(); try{ patchEvalSrc(q.src,q.tag); }catch(e){ L('EVAL drain ERR '+e); } } }
// Hook diagnostics (killlog7: 186 evals, 0 edits, and nothing said whether the String walk found any script).
// _evalSrcCalls = evals where the walk located >=1 script String; first 24 located sources and every source
// >=1MB (max 12) are logged with length + head, and the first 6 evals with NO source log their r0-r2.
var _evalSrcCalls=0, _evalSrcN=0, _evalLogN=0, _evalBigN=0, _evalNoSrcLog=0;
function evalNote(ctx,srcs){
  if(!srcs.length){ if(_evalNoSrcLog++<6) L('EVALSRC#'+_evalN+' none located r0='+ctx.r0+' r1='+ctx.r1+' r2='+ctx.r2); return; }
  _evalSrcCalls++; _evalSrcN+=srcs.length;
  for(var i=0;i<srcs.length;i++){ var big=srcs[i].len>=1048576;
    if(_evalLogN<24||(big&&_evalBigN<12)){ _evalLogN++; if(big) _evalBigN++; var head=''; try{ head=srcs[i].p.add(12).readCString(48); }catch(e){}
      L('EVALSRC#'+_evalN+' len='+srcs[i].len+' head='+JSON.stringify(head)+' +'+(Date.now()-_fcT0)+'ms'); } } }
function onEvalEnter(ctx){
  _evalN++;
  var srcs=findEvalSources(ctx);
  try{ evalNote(ctx,srcs); }catch(e){}
  if(srcs.length) _lastEvalT=Date.now();
  for(var i=0;i<srcs.length;i++){
    if(EVAL_DEFER){ _evalQ.push({src:srcs[i],tag:'#'+_evalN}); }
    else patchEvalSrc(srcs[i],'#'+_evalN);
  }
  if(EVAL_DEFER&&_evalQ.length&&!_evalDrainArmed){ _evalDrainArmed=true; setTimeout(drainEvalQ,0); }
}

function netflixModule(){ return Process.findModuleByName('libnetflix.so')||Process.findModuleByName('libandroid_netflix.so'); }
function armEvalHook(){
  if(evalHooked||!EVALHOOK_ENABLED) return evalHooked;
  var m=netflixModule(); if(!m) return false;
  evalHooked=true;                           // one attempt per process, whatever the outcome
  var at=m.base.add(EVAL_PROLOGUE);
  for(var i=0;i<EVAL_SIG.length;i++){ var got=-1; try{ got=at.add(EVAL_SIG[i][0]).readU32()>>>0; }catch(e){}
    if(got!==EVAL_SIG[i][1]){ L('EVALHOOK: prologue signature mismatch @+0x'+EVAL_SIG[i][0].toString(16)+' (got 0x'+(got>>>0).toString(16)+') — different Netflix build, hook NOT armed; heap-scan fallback only'); return true; } }
  // Bootstrap JS also sits verbatim in libnetflix.so's data: neuter the cache producers there too,
  // in case the bootstrap is evaluated from that buffer before/outside the hooked eval.
  if(HH_NOCACHE>0){ try{ var rr=m.enumerateRanges('rw-');
    for(var q=0;q<rr.length;q++) noCachePatchRange(rr[q].base, rr[q].size, '(so)'); }catch(e){ L('EVALHOOK: so-data cache patch error '+e); } }
  try{
    Interceptor.attach(at, { onEnter:EVAL_ONENTER_NOOP ? function(){ _evalN++; }
                                                       : function(){ try{ onEvalEnter(this.context); }catch(e){ L('EVALHOOK onEnter ERR '+e); } } });
    L('EVALHOOK armed @'+at+' (household edits applied to each evaluated source; defer='+EVAL_DEFER+' nocache='+HH_NOCACHE+' noop='+EVAL_ONENTER_NOOP+')');
    if(EVAL_ONENTER_NOOP) setInterval(function(){ L('EVALHOOK noop: '+_evalN+' eval calls so far'); },15000);
  }catch(e){ L('EVALHOOK: attach failed '+e+' — heap-scan fallback only'); }
  return true;
}
// libnetflix.so is loaded after the gadget (gadget loads first thing in Application.onCreate): arm by
// a light 100ms poll (optionally also on its dlopen — see EVAL_ARM_DLOPEN).
function startEvalHook(){
  if(!EVALHOOK_ENABLED) return;
  setTimeout(startEvalHookNow, EVAL_ARM_DELAY_MS);
}
function startEvalHookNow(){
  if(armEvalHook()) return;
  if(EVAL_ARM_DLOPEN) try{ var dl=Module.findGlobalExportByName('android_dlopen_ext');
    if(dl) Interceptor.attach(dl,{
      onEnter:function(a){ try{ this.nf=a[0].readCString().indexOf('netflix')>=0; }catch(e){ this.nf=false; } },
      onLeave:function(){ if(this.nf&&!evalHooked) armEvalHook(); } });
  }catch(e){ L('EVALHOOK: dlopen hook failed '+e); }
  var polls=0; (function poll(){ if(armEvalHook()||++polls>3000) return; setTimeout(poll,1000); })();
}

var tries=0;
function apply(){ if(hhYield()||adkDefer()){ setTimeout(apply,hhYield()?500:1000); return; } tries++; var rs=Process.enumerateRanges('rw-');
  var loaded=false,gp=pat('nrdp.gibbon');
  for(var i=0;i<rs.length&&!loaded;i++){if(rs[i].size>128*1024*1024)continue;try{if(Memory.scanSync(rs[i].base,rs[i].size,gp).length)loaded=true;}catch(e){}}
  // One patch function per timer tick (they are several synchronous full-heap scans each) so the async
  // household callbacks and timers interleave. The household patches no longer run from here: fastHH /
  // fastCLCS own them (async, persistent).
  runSteps(loaded?[function(){patchA(rs);},function(){patchA2(rs);},function(){patchADV(rs);},function(){if(!advDone)patchADVw(rs);},function(){patchDAI(rs);},function(){patchMASTER(rs);},function(){if(!masterDone)patchMASTERw(rs);},function(){patchB(rs);},function(){patchFP(rs);},function(){patchGAID(rs);}]:[], applyDone, true);
}
function applyDone(){
  // Keep polling until applied. The ad-insertion source (ADV/DAI) and prepareAdBreakStates (A)
  // can load LATER than the pause module (B) — sometimes only once playback is exercised — so we
  // must NOT give up early. WRITE-ONCE per patch (done guards) — not a re-patch loop.
  var fpOk=(!FP_ENABLED||fpDone);
  var gaidOk=(!GAID_ENABLED||gaidDone);
  var hhOk=(!HH_ENABLED||hhDone);
  if((aDone||a2Done||masterDone)&&bDone&&fpOk&&gaidOk&&hhOk){ L('apply DONE: A='+aDone+' A2='+a2Done+' ADV='+advDone+' DAI='+daiDone+' MASTER='+masterDone+'(m1='+m1Done+',m2='+m2Done+') B='+bDone+' FP='+(FP_ENABLED?fpDone:'off')+' GAID='+(GAID_ENABLED?gaidDone:'off')+' HH='+(HH_ENABLED?hhDone:'off')+' tries='+tries); return; }
  if(tries%15===0) L('apply waiting: A='+aDone+' A2='+a2Done+' ADV='+advDone+' DAI='+daiDone+' MASTER='+masterDone+'(m1='+m1Done+',m2='+m2Done+') B='+bDone+' HH='+(HH_ENABLED?hhDone:'off')+' tries='+tries);
  if(tries<3600) setTimeout(apply, HH_ENABLED?ADK_HH_PERIOD:2000);   // up to ~2h of find-and-apply polling (household builds: slow)
}

// ---------- monitor (read-only) ----------
var KILLMARK=pat('__adkill'),REALPOD=pat('ads":[{'),DISPAD=pat('displayAd":{'),BM=pat('"bookmark":');
function readNumAfter(addr,skip){ try{var s=addr.add(skip).readCString(14);var m=/^([0-9]{1,12})/.exec(s);return m?parseInt(m[1],10):-1;}catch(e){return -1;} }
var cyc=0;
function observe(){ if(hhYield()){ setTimeout(observe,1000); return; } cyc++;
  var rs=Process.enumerateRanges('rw-');var kill=0,real=0,disp=0;var bset={};
  for(var i=0;i<rs.length;i++){var r=rs[i];if(r.size>64*1024*1024||r.size<256)continue;
    try{ kill+=Memory.scanSync(r.base,r.size,KILLMARK).length; real+=Memory.scanSync(r.base,r.size,REALPOD).length; disp+=Memory.scanSync(r.base,r.size,DISPAD).length;
      var bh=Memory.scanSync(r.base,r.size,BM); for(var k=0;k<bh.length&&k<40;k++){var v=readNumAfter(bh[k].address,11);if(v>0)bset[v]=1;}
    }catch(e){}
  }
  var bks=Object.keys(bset).map(Number).sort(function(a,b){return b-a}).slice(0,6);
  var tag=(kill>1?'  <<<MANIFEST-KILL':'')+(disp>0?'  <<<server-pauseAd(x'+disp+')':'')+(real>0?'  <<<rawRealPod(x'+real+')':'');
  // Drift alarm: raw pods present but nothing killed -> report which anchors installed so we can tell
  // string-drift (MASTER=0: anchor scan-missed) from semantic-drift (MASTER=1: matched but ineffective).
  if(real>0 && kill===0){ tag+='  <<<DRIFT[A='+(aDone?1:0)+' A2='+(a2Done?1:0)+' ADV='+(advDone?1:0)+' DAI='+(daiDone?1:0)+' MASTER='+(masterDone?1:0)+(mwDone?'w':'')+']'; }
  L('OBS'+cyc+': KILLMARK='+kill+' rawRealPods='+real+' rawDisplayAd='+disp+' bookmarks='+JSON.stringify(bks)+tag);
  if(cyc<560) setTimeout(observe,3000);   // ~28 min coverage
}

L('killads ready (A/A2/ADV/DAI/MASTER ad-kill + B pause, single-shot; ad+resume monitor)');
if(!HH_ENABLED) setTimeout(apply,5000);   // household builds: ad-kill runs async (fastADK)
if(!HH_ENABLED) setTimeout(observe,9000);
else L('OBS monitor off in household builds (4 synchronous full-heap scans per cycle starved the household patches)');
// ANCHOR MAP (drift self-detection) — periodic at-a-glance hook state on its OWN timer, so the summary
// ALWAYS appears (apply()'s DONE line is gated on the whole loop completing and can be missed on some
// builds — reported on 1.36.0). Shows which anchors installed and whether MASTER/ADV used the wildcard
// fallback ('w'). ~8 snapshots over ~2.5 min covers the appboot settle window.
var _amN=0;
function anchorMap(){ _amN++;
  L('ANCHOR MAP: A='+(aDone?1:0)+' A2='+(a2Done?1:0)+' ADV='+(advDone?1:(advwDone?'w':0))+' DAI='+(daiDone?1:0)+' MASTER='+(masterDone?(mwDone?'1w':1):0)+' B='+(bDone?1:0)+' FP='+(FP_ENABLED?(fpDone?1:0):'off')+' GAID='+(GAID_ENABLED?(gaidDone?1:0):'off')+' HH='+(HH_ENABLED?(hhDone?1:0):'off')+' pass='+_amN);
  if(_amN<8) setTimeout(anchorMap,20000);
}
setTimeout(anchorMap,15000);
if(!HH_ENABLED){
L('fastMASTER armed (getAdMetadata early race-win scanner — beat first-title pre/mid-roll)');
setTimeout(fastMASTER,200);
L('dumpMASTER armed (recon: dump getAdMetadata body if both exact+wildcard MASTER miss — #166)');
setTimeout(dumpMASTER,2000);
}
if(HH_ENABLED){ L('fastADK armed (async ad-kill: ADV2 + MASTER2 + B + DAI, rename-tolerant)'); setTimeout(fastADK,300); }
if(HH_ENABLED){ L('fastHH armed (household prompt suppression, early race-win scanner)'); setTimeout(fastHH,200);
}
if(CLCS_PROBE_ENABLED){ L('clcsProbe armed (DEV recon: locate runtime CLCS interstitial consumer — Nikflix seam)'); setTimeout(clcsProbe,200); }
if(HH_ENABLED){ L('fastCLCS armed (gate dispatcher race-win)'); setTimeout(fastCLCS,100); }
if(EVALHOOK_ENABLED){ L('evalHook arming (household pre-compile source patch)'); startEvalHook(); }
if(HH_ENABLED&&HH_DIAG){ L('HHDIAG armed (status every 5s'+(HH_DUMPS?' + household routing JS dumps':'')+')'); setTimeout(hhStatus,3000); if(HH_DUMPS) setTimeout(hhDiag,12000); }
if(HH_ENABLED&&AD_DIAG){ L('ADDIAG armed (ad-path recon once the ad-kill has started)'); setTimeout(adDiag,4000); }


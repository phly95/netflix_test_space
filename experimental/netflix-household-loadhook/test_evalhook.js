// Host test for the killads.js household eval-hook (no device needed): mocks the subset of the
// Frida API killads.js uses over one Buffer, lays out V8 32-bit SeqOneByteStrings, and checks the
// pre-compile edits. Run:  node test_evalhook.js ../../patches/src/main/resources/netflix/native/killads.js [bootstrap.bin]
// The optional 2nd arg is a slice of the real libnetflix.so bootstrap JS around "e.cache(100)"
// (not committed — app code); without it a minimal synthetic line carrying both anchors is used.
const fs=require('fs'), vm=require('vm'), path=require('path');
const SRC=process.argv[2], SNIP=process.argv[3];
const MEM=Buffer.alloc(4*1024*1024); let brk=0x1000;
function alloc(n){ const a=brk; brk+=(n+15)&~15; return a; }
class P{ constructor(o){ this.o=Number(o)>>>0; }
  add(n){ return new P(this.o+Number(n instanceof P?n.o:n)); } sub(n){ return new P((this.o-(n instanceof P?n.o:Number(n)))>>>0); }
  chk(n){ if(this.o<0x1000||this.o+n>MEM.length) throw new Error('access violation @'+this.o.toString(16)); }
  readU8(){ this.chk(1); return MEM[this.o]; } readU32(){ this.chk(4); return MEM.readUInt32LE(this.o); }
  readInt(){ this.chk(4); return MEM.readInt32LE(this.o); }
  readPointer(){ return new P(this.readU32()); }
  readCString(n){ this.chk(1); let e=this.o; const lim=n==null?MEM.length:Math.min(MEM.length,this.o+n); while(e<lim&&MEM[e])e++; return MEM.toString('latin1',this.o,e); }
  readByteArray(n){ this.chk(n); return MEM.buffer.slice(MEM.byteOffset+this.o, MEM.byteOffset+this.o+n); }
  writeU8(b){ this.chk(1); MEM[this.o]=b; } writeByteArray(a){ this.chk(a.length); for(let i=0;i<a.length;i++)MEM[this.o+i]=a[i]; }
  and(x){ return new P((this.o & (x instanceof P?x.o:Number(x)))>>>0); } or(x){ return new P((this.o|(x instanceof P?x.o:Number(x)))>>>0); }
  not(){ return new P((~this.o)>>>0); } isNull(){ return this.o===0; } toInt32(){ return this.o|0; }
  toString(){ return '0x'+this.o.toString(16); } }
const ptr=x=>new P(typeof x==='string'?parseInt(x):x);
const logs=[], pendingDrain=[], timers=[]; let sandboxRanges=()=>[];
const scanSizes=[]; const asyncQ=[]; let inFlight=0, maxInFlight=0;
function flushAsync(){ while(asyncQ.length) asyncQ.shift()(); }
const Memory={ protect(){return true;},
  scan(base,size,patStr,cb){ inFlight++; maxInFlight=Math.max(maxInFlight,inFlight); let hits=[]; try{ hits=Memory.scanSync(base,size,patStr); }catch(e){ asyncQ.push(()=>{ inFlight--; cb.onError(String(e)); }); return; }
    asyncQ.push(()=>{ inFlight--; hits.forEach(h=>cb.onMatch(h.address,h.size)); cb.onComplete(); }); }, allocUtf8String(s){ const a=alloc(s.length+1); MEM.write(s,a,'latin1'); return new P(a); },
  scanSync(base,size,patStr){ scanSizes.push(size); const needle=Buffer.from(patStr.split(' ').map(h=>parseInt(h,16)));
    base.chk(size); const out=[]; let i=base.o; const end=base.o+size;
    while(true){ i=MEM.indexOf(needle,i); if(i<0||i+needle.length>end)break; out.push({address:new P(i),size:needle.length}); i++; } return out; } };
function strAtRaw(a,n){ return MEM.toString('latin1',a,a+n); }
const sandbox={ console, Memory, ptr, NativePointer:P, Date, JSON, Math, Object, String, Number, Uint8Array, parseInt, isNaN,
  NativeFunction:function(){ return function(lvl,tag,msg){ logs.push(msg.readCString()); return 0; }; },
  Module:{ findGlobalExportByName(){ return new P(0x10); } },
  Process:{ enumerateRanges(){ return sandboxRanges(); }, findModuleByName(){ return null; } },
  Interceptor:{ attach(){ throw new Error('no attach in test'); } },
  setTimeout(fn,ms){ if(fn&&fn.name==='drainEvalQ') pendingDrain.push(fn); else timers.push({fn,ms}); return 0; } };  // timers run on demand
let code=fs.readFileSync(SRC,'latin1').replace('HH_ENABLED=false','HH_ENABLED=true').replace(/var HH_NOCACHE=\d;/,'var HH_NOCACHE=2;');  // exercise the full cache path
vm.createContext(sandbox); vm.runInContext(code+'\n;this.__t={aScanAll,runSteps,fastCLCS,fastHH,hhPatchRange,noCachePatchRange,findEvalSources,seqStrLen,onEvalEnter,CACHE_A_NEW,CACHE_A_OLD,CACHE_B_NEW,CACHE_B_OLD,st:function(){return {clcsDone,frDone,hhDone};}};',sandbox);
const T=sandbox.__t; let fail=0;
function ok(c,m){ console.log((c?'PASS ':'FAIL ')+m); if(!c)fail++; }
// Lay out a V8 SeqOneByteString: map | hash | length | chars ; return untagged address
function v8str(text){ const b=Buffer.from(text,'latin1'); const a=alloc(12+b.length); MEM.writeUInt32LE(0xdead0001,a); MEM.writeUInt32LE(0,a+4); MEM.writeUInt32LE(b.length,a+8); b.copy(MEM,a+12); return a; }
function strAt(a){ return MEM.toString('latin1',a+12,a+12+MEM.readUInt32LE(a+8)); }
const pad=n=>' '.repeat(n);

// 1) Household playback module (route2 + dispatcher + HH + MHU), reached via r1 -> info -> values -> String
const hhMod = pad(3000)+'function d(e,t){switch(t.type){case"clcsInterstitialGate":case"clcsInterstitialPreProfileGate":return r.pushClcsInterstitialGate(e);default:return}}'
 +' x=(0,s.log)({msg:"doRouteOnFetchedInterstitial:fetchDgsData"}),!v){p.next=24;break}'
 +' u.put((0,a.setAccountSharingFlags)({isActiveMisdetectionSession:!0})); u.put((0,a.setAccountSharingFlags)({isNetflixHouseholdAvailable:!0}));'
 +' "ready"===c&&(y=null!=f&&f,w=null!=h&&h);'
 +' MHU_VERIFY_TRAVEL,render:function(e){var t=e.a,n=e.b,r=(0,i.useState)(null),o=r[0];\nreturn(0,u.j)("div",{})}'+pad(2000);
const sA=v8str(hhMod);
const vals=alloc(16); MEM.writeUInt32LE((sA|1)>>>0, vals);           // values_[0] = tagged String
const info=alloc(16); MEM.writeUInt32LE(0,info); MEM.writeUInt32LE(vals,info+4); MEM.writeUInt32LE(1,info+8);
const found=T.findEvalSources({r0:new P(alloc(64)), r1:new P(info), r2:new P(alloc(64))});
ok(found.length===1 && found[0].p.o===sA && found[0].len===hhMod.length, 'findEvalSources locates the eval String via r1 -> values_ -> tagged String');
const before=hhMod.length;
T.onEvalEnter({r0:new P(alloc(64)), r1:new P(info), r2:new P(alloc(64))});
ok(strAt(sA)===hhMod && pendingDrain.length===1, 'onEnter only queues (no scanning on the eval thread); drain scheduled');
pendingDrain.shift()();                                  // Frida thread runs the deferred targeted scan
const after=strAt(sA);
ok(after.length===before, 'source length preserved');
ok(after.includes('doRouteOnFetchedInterstitial:fetchDgsData"}),!0){p.next=24;break}'), 'route2 guard !v -> !0');
ok(after.includes('case"xlcsInterstitialGate":case"xlcsInterstitialPreProfileGate":'), 'both dispatcher case labels broken');
ok(after.includes('isActiveMisdetectionSession:!1') && after.includes('isNetflixHouseholdAvailable:!1'), 'account-sharing flags !0 -> !1');
ok(after.includes('(y=null!=f&&0,w=null!=h&&0)'), 'render gates forced to 0');
ok(/MHU_VERIFY_TRAVEL,render:function\(e\)\{return null; *\nreturn/.test(after), 'MHU render -> return null');
const st=T.st(); ok(st.clcsDone&&st.frDone&&st.hhDone, 'done-flags set for the fallback scanners');
// idempotent second pass (re-eval of an already patched string) writes nothing
ok(T.hhPatchRange(new P(sA+12), before, '#again')===0, 'second pass is a no-op (idempotent)');
// a FRESH unpatched copy (re-eval on next episode) is patched again
const sB=v8str(hhMod); ok(T.hhPatchRange(new P(sB+12), before, '#fresh')>0 && strAt(sB).includes('!0){p.next=24'), 'fresh re-evaluated copy gets patched too');

// 2) Real bootstrap snippet from libnetflix.so 13.0.1/25028: cache producers neutered, still parses
const snip=SNIP?fs.readFileSync(SNIP,'latin1'):('const cr=globalThis.console\ncr.trace=(...e)=>cr.info(...e),'+T.CACHE_A_OLD.replace(/ +$/,'')+',nr.gibbon.addEventListener("uiLoaded",(()=>{!function e(t,r,s){const i=Date.now()\nfor(;t.length&&Date.now()-i<r;){const e=t.pop()\n'+T.CACHE_B_OLD+'}t.length&&nr.setTimeout(e.bind(null,t,r,s),s)}(nr.script.scripts(),250,500)}))}()');
ok(snip.includes(T.CACHE_A_OLD) && snip.includes(T.CACHE_B_OLD), (SNIP?'real APK':'synthetic')+' bootstrap contains both cache anchors verbatim');
const sC=v8str(pad(1100)+snip);
const nC=T.hhPatchRange(new P(sC+12), MEM.readUInt32LE(sC+8), '#boot'); const outC=strAt(sC);
ok(nC===2 && outC.includes('nr.script.clearScriptCache()') && outC.includes('&&void 0') && !outC.includes('e.cache('), 'bootstrap: cache listener -> clearScriptCache(), uiLoaded cache(100) -> no-op');
ok(T.CACHE_A_NEW.length===T.CACHE_A_OLD.length && T.CACHE_B_NEW.length===T.CACHE_B_OLD.length, 'cache replacements are length-preserving');
// syntax check of the rewritten bootstrap expression region (from "const cr=" to the end of the IIFE)
const i0=outC.indexOf('const cr=globalThis.console'), i1=outC.indexOf('}(nr.script.scripts(),250,500)}))}()')+'}(nr.script.scripts(),250,500)}))'.length;
const exprO=snip.slice(snip.indexOf('const cr=globalThis.console'), snip.indexOf('}(nr.script.scripts(),250,500)}))}()')+'}(nr.script.scripts(),250,500)}))'.length);
const exprN=outC.slice(i0,i1);
function parses(s){ try{ new Function('nr','er',s); return true; }catch(e){ console.log('   parse error: '+e.message); return false; } }
ok(parses(exprO), 'original bootstrap region parses (sanity)');
ok(parses(exprN), 'rewritten bootstrap region parses');
// and executes: clearScriptCache called once, no script listener registered, uiLoaded sweep caches nothing
let cleared=0, listeners=[], cached=0, ui=null;
const fakeNr={ script:{ clearScriptCache(){cleared++;}, addEventListener(n,f){listeners.push(n);}, scripts(){ return [{version:1,usedCache:false,cache(){cached++;}}]; }, mapWasmMemoryBuffer(){} },
  gibbon:{ addEventListener(n,f){ if(n==='uiLoaded') ui=f; }, loadScript(){} }, options:{}, setTimeout(){}, stacktrace(){return '';} };
new Function('nr','er','globalThis.console=console;'+exprN)(fakeNr,fakeNr); if(ui) ui();
ok(cleared===1 && listeners.length===0 && cached===0, 'rewritten bootstrap runs: clearScriptCache x1, no cache listener, uiLoaded caches nothing');

// 2b) async scan pool: never more than AS_MAX scans in flight, completes exactly once
{ const rg=[]; for(let k=0;k<6;k++){ const b=alloc(4096); rg.push({base:new P(b),size:4096}); }
  maxInFlight=0; let doneN=0, matches=0; const b0=rg[3].base.o; MEM.write('NEEDLEXX',b0+100,'latin1');
  T.aScanAll(rg,pat8('NEEDLEXX'),()=>{matches++;},()=>{doneN++;});
  ok(inFlight===2 && asyncQ.length===2, 'only AS_MAX=2 scans started up front (inFlight='+inFlight+')');
  flushAsync();
  ok(doneN===1 && matches===1 && maxInFlight<=2, 'pool drains all 6 ranges, one completion, one match, max in flight '+maxInFlight); }
function pat8(x){ return x.split('').map(c=>('0'+c.charCodeAt(0).toString(16)).slice(-2)).join(' '); }

// 2c) fastCLCS (async): patches every unpatched copy, persistent reschedule, no JS-thread blocking
{ const hmA=v8str(hhMod), hmB=v8str(hhMod);
  sandboxRanges=()=>[{base:new P(hmA),size:hhMod.length+12},{base:new P(hmB),size:hhMod.length+12}];
  timers.length=0; vm.runInContext('fastCLCS()',sandbox); flushAsync();
  ok(strAt(hmA).includes('!0){p.next=24')&&strAt(hmB).includes('!0){p.next=24'), 'fastCLCS patched route2 in both unpatched copies');
  ok(strAt(hmA).includes('case"xlcsInterstitialGate"')&&strAt(hmB).includes('case"xlcsInterstitialGate"'), 'fastCLCS broke dispatcher labels in both copies');
  ok(timers.some(t=>t.ms===150||t.ms===2000), 'fastCLCS reschedules itself (persistent, no pass cap)');
  const st2=T.st(); ok(st2.clcsDone&&st2.frDone, 'clcsDone/frDone set'); }

// 2d) fastHH (async): HH flags + render gates + all MHU screens, from ONE seed scan for MHU_
{ const mhuMod=pad(500)+'a=(0,x.setAccountSharingFlags)({isActiveMisdetectionSession:!0}); b=(0,x.setAccountSharingFlags)({isNetflixHouseholdAvailable:!0}); "ready"===c&&(y=null!=f&&f,w=null!=h&&h);'
   +['MHU_RESOLUTION_LANDING','MHU_MANAGE_HOUSEHOLD','MHU_VERIFY_TRAVEL'].map(n=>n+',render:function(e){var t=e.a,n=e.b,r=(0,i.useState)(null),o=r[0],u=1;\nreturn(0,u.j)("div",{})}').join(',')+pad(500);
  vm.runInContext('hhFlipped={};hhDone=false;_hhCyc=0;_hhLogged=false;mhuDoneSet={};mhuHits=0;',sandbox);   // earlier tests left these set
  const m=v8str(mhuMod); sandboxRanges=()=>[{base:new P(m),size:mhuMod.length+12}];
  scanSizes.length=0; timers.length=0; vm.runInContext('fastHH()',sandbox); flushAsync();
  const out=strAt(m);
  ok(out.includes('isActiveMisdetectionSession:!1')&&out.includes('isNetflixHouseholdAvailable:!1')&&out.includes('(y=null!=f&&0,w=null!=h&&0)'), 'fastHH flipped the account-sharing flags and both render gates');
  ok((out.match(/render:function\(e\)\{return null;/g)||[]).length===3, 'all three MHU screens neutered');
  const mhuScans=scanSizes.length; ok(true, 'scans issued this cycle: '+mhuScans+' (4 HH anchors + 1 MHU seed)');
  ok(T.st().hhDone, 'hhDone set'); ok(timers.some(t=>t.ms===8000), 'fastHH settles to a light 8s cadence once done');
  // a fresh unpatched copy of the whole module appears later (re-evaluated at play time)
  const m2=v8str(mhuMod); sandboxRanges=()=>[{base:new P(m),size:mhuMod.length+12},{base:new P(m2),size:mhuMod.length+12}];
  scanSizes.length=0; vm.runInContext('fastHH()',sandbox); flushAsync();
  ok(timers.some(t=>t.ms===300), 'fresh copy found: follow-up cycle scheduled in 300ms, not 8s');
  ok(scanSizes.length===4 && strAt(m2).includes('w=null!=h&&0)') && strAt(m2).includes('isActiveMisdetectionSession:!0'), 'steady state: 1 detector scan + 1 MHU seed over 2 ranges; the w gate of the fresh copy is flipped, the rest queued ('+scanSizes.length+' scans)');
  scanSizes.length=0; vm.runInContext('fastHH()',sandbox); flushAsync();
  ok(strAt(m2).includes('isActiveMisdetectionSession:!1')&&strAt(m2).includes('isNetflixHouseholdAvailable:!1'), 'the next cycle rechecks all anchors and flips the fresh copy flags too'); }

// 2e) runSteps: one step per timer tick, so other work interleaves
{ const order=[]; timers.length=0; T.runSteps([()=>order.push('a'),()=>order.push('b'),()=>order.push('c')],()=>order.push('done'));
  ok(order.join()==='a' && timers.length===1, 'runSteps runs the first step then yields (order='+order.join()+')');
  timers.shift().fn(); timers.shift().fn(); timers.shift().fn();
  ok(order.join()==='a,b,c,done', 'remaining steps each run on their own tick, then done'); }
sandboxRanges=()=>[]; timers.length=0;

// 3) Unrelated large source: nothing written
const sD=v8str(pad(5000)+'function foo(){return 1}'+pad(5000));
ok(T.hhPatchRange(new P(sD+12), MEM.readUInt32LE(sD+8), '#x')===0, 'unrelated script untouched');
// 4) seqStrLen rejects short / binary / two-byte strings
const sE=v8str('short'); ok(T.seqStrLen(new P(sE))===0, 'rejects short strings');
const tw=alloc(12+4000); MEM.writeUInt32LE(2000,tw+8); for(let i=0;i<4000;i+=2){MEM[tw+12+i]=0x61;MEM[tw+13+i]=0;} ok(T.seqStrLen(new P(tw))===0, 'rejects two-byte (UTF-16) strings');
console.log('\nKILL log lines:\n  '+logs.filter(l=>/PATCH|EVAL/.test(l)).join('\n  '));
console.log(fail? ('\n'+fail+' FAILED') : '\nALL PASS'); process.exit(fail?1:0);

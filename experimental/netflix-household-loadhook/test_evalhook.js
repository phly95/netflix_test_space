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
const scanSizes=[];
const Memory={ protect(){return true;}, allocUtf8String(s){ const a=alloc(s.length+1); MEM.write(s,a,'latin1'); return new P(a); },
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
vm.createContext(sandbox); vm.runInContext(code+'\n;this.__t={neuterMhuRenders,hhPatchRange,noCachePatchRange,findEvalSources,seqStrLen,onEvalEnter,CACHE_A_NEW,CACHE_A_OLD,CACHE_B_NEW,CACHE_B_OLD,st:function(){return {clcsDone,frDone,hhDone};}};',sandbox);
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

// 2b) Sliced heap sweep (fastCLCS): yields between ranges, patches every unpatched copy, repeats forever
{ const hmA=v8str(hhMod), hmB=v8str(hhMod);                 // two fresh unpatched copies (e.g. re-evals)
  const rg=[{base:new P(hmA),size:hhMod.length+12},{base:new P(hmB),size:hhMod.length+12}];
  sandboxRanges=()=>rg; vm.runInContext('FC_SLICE_MS=-1;',sandbox);   // force a yield after every range
  timers.length=0; vm.runInContext('fastCLCS()',sandbox);
  let yields=0, guard=0;
  while(timers.length&&guard++<50){ const t=timers.shift(); if(t.ms>=1000||t.ms===150) { timers.unshift(t); break; } yields++; t.fn(); }
  ok(yields>=1, 'sweep yields the Frida thread between ranges (setTimeout slices), yields='+yields);
  ok(timers.length===1 && (timers[0].ms===150||timers[0].ms===2000), 'sweep reschedules itself afterwards (persistent, no pass cap)');
  ok(strAt(hmA).includes('!0){p.next=24')&&strAt(hmB).includes('!0){p.next=24'), 'sweep patched route2 in both unpatched copies');
  ok(strAt(hmA).includes('case"xlcsInterstitialGate"')&&strAt(hmB).includes('case"xlcsInterstitialGate"'), 'sweep broke dispatcher labels in both copies');
  sandboxRanges=()=>[]; timers.length=0; }

// 2c) MHU hot windows: after the first MHU anchor is seen, later passes only scan +-1MB around it
{ const decl='var t=e.a,n=e.b,r=(0,i.useState)(null),o=r[0],u=(0,i.useRef)(null),w=1;\nreturn(0,u.j)("div",{})}';
  const base=alloc(4*1024*1024-0x10000)-0; const A=base+0x1000, B=base+0x1000+100*1024;
  const put=(a,txt)=>MEM.write(txt,a,'latin1');
  put(A,'MHU_RESOLUTION_LANDING,render:function(e){'+decl);
  const range=[{base:new P(base),size:3*1024*1024}];
  scanSizes.length=0; vm.runInContext('MHU_ENABLED=true;',sandbox); sandbox.__t.neuterMhuRenders(range);
  ok(strAtRaw(A,60).includes('return null;'), 'MHU first hit patched by the full pass');
  put(B,'MHU_MANAGE_HOUSEHOLD,render:function(e){'+decl);   // a second screen appears next to it later
  scanSizes.length=0; sandbox.__t.neuterMhuRenders(range);
  ok(strAtRaw(B,60).includes('return null;'), 'second MHU screen near the first is patched on the next call');
  ok(scanSizes.length>0 && Math.max(...scanSizes)<=2*1024*1024+4, 'that call only scanned small windows (max '+Math.max(...scanSizes)+' bytes, not the 3MB range)'); }

// 3) Unrelated large source: nothing written
const sD=v8str(pad(5000)+'function foo(){return 1}'+pad(5000));
ok(T.hhPatchRange(new P(sD+12), MEM.readUInt32LE(sD+8), '#x')===0, 'unrelated script untouched');
// 4) seqStrLen rejects short / binary / two-byte strings
const sE=v8str('short'); ok(T.seqStrLen(new P(sE))===0, 'rejects short strings');
const tw=alloc(12+4000); MEM.writeUInt32LE(2000,tw+8); for(let i=0;i<4000;i+=2){MEM[tw+12+i]=0x61;MEM[tw+13+i]=0;} ok(T.seqStrLen(new P(tw))===0, 'rejects two-byte (UTF-16) strings');
console.log('\nKILL log lines:\n  '+logs.filter(l=>/PATCH|EVAL/.test(l)).join('\n  '));
console.log(fail? ('\n'+fail+' FAILED') : '\nALL PASS'); process.exit(fail?1:0);

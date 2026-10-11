import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {createGateway,MAX_REQUEST_BYTES,MAX_RESPONSE_BYTES,UPSTREAM,UPSTREAM_TIMEOUT_MS,validateQuery} from './gateway';
import policy from '../apps/web/public/data/trust-policy.json';
const creator=policy.trusted_creators[0]!.toLowerCase();
const stranger=`0x${'f'.repeat(40)}`;
const hash=`0x${'a'.repeat(64)}`;
const query=`app_id = str('scamsignal-v1') AND schema_version = u64(1) AND $expiresAt > u64(100) AND $creator = addr(${creator})`;
const timing=(block=100)=>({current_block:String(block),current_block_time:1791710000,duration:2});
const record=(patch:Record<string,unknown>={})=>({key:hash,creator,expiresAt:'0xc8',payload:'0x1234',attributes:[{name:'app_id',type:'str',value:'scamsignal-v1'},{name:'schema_version',type:'u64',value:'0x1'}],...patch});
const envelope=(result:unknown,id:number|string|null=7)=>new Response(JSON.stringify({jsonrpc:'2.0',id,result}),{headers:{'content-type':'application/json'}});
const rpc=(method='arkiv_query',params:unknown[]=[query,{limit:'0x64',select:{key:true,payload:true,attributes:true}}])=>({jsonrpc:'2.0',id:7,method,params});
const request=(body:unknown=rpc(),headers:Record<string,string>={})=>new Request('https://scamsignal.ajnasnb.com/api/arkiv-rpc',{method:'POST',headers:{'content-type':'application/json',...headers},body:JSON.stringify(body)});
function environment(allowed=true,key='fixture-key') {
  return {ARKIV_API_KEY:key,RPC_RATE_LIMITER:{limit:vi.fn(async()=>({success:allowed}))},ASSETS:{fetch:vi.fn(async()=>new Response('static asset'))}};
}
function setup() {
  const fetcher=vi.fn<typeof fetch>();
  fetcher.mockResolvedValueOnce(envelope(timing())).mockResolvedValueOnce(envelope({data:[record()],blockNumber:'0x64',cursor:'next-page'}));
  return {fetcher,worker:createGateway(fetcher),env:environment()};
}
beforeEach(()=>vi.useRealTimers());
afterEach(()=>{vi.useRealTimers();vi.restoreAllMocks();});

describe('restricted Arkiv gateway',()=>{
  it('forwards SDK reads using only the server key and adds an unavoidable outer scope',async()=>{
    const {worker,fetcher,env}=setup();
    const response=await worker.fetch(request(rpc(),{'x-api-key':'attacker-key','cookie':'private=example'}),env);
    expect(response.status).toBe(200);
    expect((await response.json()).result.data).toHaveLength(1);
    expect(fetcher).toHaveBeenCalledTimes(2);
    for(const [url,init] of fetcher.mock.calls){expect(url).toBe(UPSTREAM);expect(init?.headers).toEqual({'content-type':'application/json','X-API-KEY':'fixture-key'});expect(init?.redirect).toBe('manual');}
    const upstreamBody=JSON.parse(String(fetcher.mock.calls[1]![1]?.body));
    expect(upstreamBody.params[0]).toBe(`app_id = str('scamsignal-v1') AND schema_version = u64(1) AND ($creator = addr(${creator})) AND (${query})`);
    expect(upstreamBody.params[1].select.creator).toBe(true);expect(upstreamBody.params[1].select.expiresAt).toBe(true);
    expect(response.headers.get('x-api-key')).toBeNull();expect(response.headers.get('cache-control')).toBe('no-store');
  });
  it('supports the timing RPC and a string JSON-RPC id without leaking headers',async()=>{
    const fetcher=vi.fn<typeof fetch>().mockResolvedValue(envelope(timing(),'client-1'));
    const response=await createGateway(fetcher).fetch(request({...rpc('arkiv_getBlockTiming',[]),id:'client-1'}),environment());
    expect((await response.json()).result.current_block).toBe('100');expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('serves static assets without consuming RPC quota',async()=>{
    const {worker,env,fetcher}=setup();
    const response=await worker.fetch(new Request('https://scamsignal.ajnasnb.com/feed'),env);
    expect(await response.text()).toBe('static asset');expect(fetcher).not.toHaveBeenCalled();expect(env.RPC_RATE_LIMITER.limit).not.toHaveBeenCalled();
  });
  it.each(['eth_sendRawTransaction','arkiv_createEntity','eth_call','arkiv_getEntityCount','arkiv_getEntity'])('blocks method %s before calling upstream',async(method)=>{
    const {worker,fetcher,env}=setup();expect((await worker.fetch(request(rpc(method,[])),env)).status).toBe(403);expect(fetcher).not.toHaveBeenCalled();
  });
  it.each([[],[rpc(),rpc()],{...rpc(),id:undefined},{...rpc(),jsonrpc:'1.0'},{...rpc(),params:{}}])('rejects batches, notifications, and malformed envelopes',async(body)=>{
    const {worker,fetcher,env}=setup();expect((await worker.fetch(request(body),env)).status).toBe(400);expect(fetcher).not.toHaveBeenCalled();
  });
  it.each([undefined,'0x65',101,0,-1,1.1,'all'])('rejects missing or unbounded page size %s',async(limit)=>{
    const {worker,env,fetcher}=setup();expect((await worker.fetch(request(rpc('arkiv_query',[query,{limit,select:{key:true}}])),env)).status).toBe(400);expect(fetcher).not.toHaveBeenCalled();
  });
  it.each([
    `kind = str('passport')`,query.replace('scamsignal-v1','other-app'),query.replace('u64(1) AND','u64(2) AND'),query.replace(creator,stranger),
    `${query}) OR app_id = str('other-app')`,`${query} OR true`,`${query} /* comment */`,`${query}; SELECT *`,`${query} AND $owner = addr(${creator})`,
    query.replace('$expiresAt > u64(100) AND ',''),`${query} AND ${'('.repeat(10)}kind = str('passport')${')'.repeat(10)}`,
  ])('rejects non-product scopes and grammar escape attempts',async(expression)=>{
    const {worker,env,fetcher}=setup();expect((await worker.fetch(request(rpc('arkiv_query',[expression,{limit:'0x64',select:{key:true}}])),env)).status).toBe(400);expect(fetcher).not.toHaveBeenCalled();
  });
  it('allows the actual SDK hash/package alternatives and exact entity key query',()=>{
    expect(validateQuery(`${query} AND (apk_sha256 = bytes32(${hash}) OR package_digest = bytes32(${hash}))`)).toContain(`AND (${query}`);
    expect(validateQuery(`${query} AND $key = key(${hash})`)).toContain('$key = key(');
  });
  it('cannot let an OR branch bypass the namespace or creator guard',()=>{
    const wrapped=validateQuery(`${query} OR kind = str('passport')`);
    expect(wrapped).toBe(`app_id = str('scamsignal-v1') AND schema_version = u64(1) AND ($creator = addr(${creator})) AND (${query} OR kind = str('passport'))`);
  });
  it('filters expiry at the current head and ignores forged creator/payload namespaces',async()=>{
    const fetcher=vi.fn<typeof fetch>().mockResolvedValueOnce(envelope(timing(150))).mockResolvedValueOnce(envelope({data:[record(),record({expiresAt:'0x96'}),record({expiresAt:'invalid'}),record({creator:stranger}),record({attributes:[{name:'app_id',type:'str',value:'other'},{name:'schema_version',type:'u64',value:'0x1'}]}),record({attributes:[]})],blockNumber:'0x96'}));
    const result=await (await createGateway(fetcher).fetch(request(),environment())).json();expect(result.result.data).toEqual([record()]);
  });
  it('preserves the stable query and cursor when the current head advances',async()=>{
    const fetcher=vi.fn<typeof fetch>().mockResolvedValueOnce(envelope(timing(120))).mockResolvedValueOnce(envelope({data:[record()],blockNumber:'0x78',cursor:'opaque'})).mockResolvedValueOnce(envelope(timing(121))).mockResolvedValueOnce(envelope({data:[record({expiresAt:'0x79'})],blockNumber:'0x78'}));
    const worker=createGateway(fetcher),env=environment();await worker.fetch(request(),env);
    const second=await worker.fetch(request(rpc('arkiv_query',[query,{limit:'0x64',select:{key:true,payload:true,attributes:true},cursor:'opaque',atBlock:'0x78'}])),env);
    const a=JSON.parse(String(fetcher.mock.calls[1]![1]?.body)),b=JSON.parse(String(fetcher.mock.calls[3]![1]?.body));
    expect(a.params[0]).toBe(b.params[0]);expect(a.params[1].select).toEqual(b.params[1].select);expect(b.params[1].cursor).toBe('opaque');expect((await second.json()).result.data).toEqual([]);
  });
  it('rejects historic snapshots without a cursor and future cursor blocks',async()=>{
    const {worker,env}=setup();expect((await worker.fetch(request(rpc('arkiv_query',[query,{limit:'0x64',select:{key:true},atBlock:'0x1'}])),env)).status).toBe(400);
    const other=setup();expect((await other.worker.fetch(request(rpc('arkiv_query',[query,{limit:'0x64',select:{key:true},cursor:'x',atBlock:'0xff'}])),other.env)).status).toBe(400);expect(other.fetcher).toHaveBeenCalledTimes(1);
  });
  it('rejects oversized request streams even without a Content-Length',async()=>{
    const {worker,env,fetcher}=setup();const response=await worker.fetch(request({...rpc(),extra:'x'.repeat(MAX_REQUEST_BYTES)}),env);expect(response.status).toBe(413);expect(fetcher).not.toHaveBeenCalled();
  });
  it('rejects cross-origin posts, query strings, and non-JSON content',async()=>{
    const {worker,env,fetcher}=setup();expect((await worker.fetch(request(rpc(),{origin:'https://elsewhere.example'}),env)).status).toBe(403);
    expect((await worker.fetch(new Request('https://scamsignal.ajnasnb.com/api/arkiv-rpc?secret=x',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(rpc())}),env)).status).toBe(403);
    expect((await worker.fetch(request(rpc(),{'content-type':'text/plain'}),env)).status).toBe(415);expect(fetcher).not.toHaveBeenCalled();
  });
  it('fails closed when key is unavailable or rate limit is reached',async()=>{
    const {worker,fetcher}=setup();expect((await worker.fetch(request(),environment(true,''))).status).toBe(503);
    const response=await worker.fetch(request(),environment(false));expect(response.status).toBe(429);expect(response.headers.get('retry-after')).toBe('60');expect(fetcher).not.toHaveBeenCalled();
  });
  it('bounds chunked upstream bodies and sanitizes upstream error messages',async()=>{
    const large=vi.fn<typeof fetch>().mockResolvedValue(new Response('x'.repeat(MAX_RESPONSE_BYTES+1)));
    expect((await createGateway(large).fetch(request(rpc('arkiv_getBlockTiming',[])),environment())).status).toBe(502);
    const error=vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({jsonrpc:'2.0',id:7,error:{code:-1,message:'fixture-key',data:{key:'fixture-key'}}})));
    const response=await createGateway(error).fetch(request(rpc('arkiv_getBlockTiming',[])),environment());expect(response.status).toBe(502);expect(await response.text()).not.toContain('fixture-key');
  });
  it('aborts a stalled upstream within the shared 14 second deadline',async()=>{
    vi.useFakeTimers();const fetcher=vi.fn<typeof fetch>().mockImplementation((_url,init)=>new Promise((_resolve,reject)=>{init?.signal?.addEventListener('abort',()=>reject(new Error('aborted')),{once:true});}));
    const pending=createGateway(fetcher).fetch(request(rpc('arkiv_getBlockTiming',[])),environment());
    await vi.advanceTimersByTimeAsync(UPSTREAM_TIMEOUT_MS+1);
    expect((await pending).status).toBe(504);expect(fetcher.mock.calls[0]![1]?.signal?.aborted).toBe(true);
  });
  it('preserves the global fetch receiver for the default Workers adapter',async()=>{
    const fetcher=vi.spyOn(globalThis,'fetch').mockImplementation(function(this:unknown,_url,init){
      expect(this).toBe(globalThis);
      const body=JSON.parse(String(init?.body));
      return Promise.resolve(envelope(body.method==='arkiv_getBlockTiming'?timing():{data:[record()],blockNumber:'0x64'}));
    });
    expect((await createGateway().fetch(request(),environment())).status).toBe(200);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
  it('rejects upstream redirects without forwarding the server key to another destination',async()=>{
    const logger=vi.spyOn(console,'warn').mockImplementation(()=>{});
    const fetcher=vi.fn<typeof fetch>().mockResolvedValue(new Response(null,{status:302,headers:{location:'https://elsewhere.example'}}));
    expect((await createGateway(fetcher).fetch(request(),environment())).status).toBe(502);
    expect(fetcher).toHaveBeenCalledTimes(1);expect(fetcher.mock.calls[0]![1]?.redirect).toBe('manual');
    expect(logger).toHaveBeenCalledWith('arkiv_upstream_status',{method:'arkiv_getBlockTiming',status:302});
  });
  it('keeps secret-bearing exception text out of diagnostics',async()=>{
    const logger=vi.spyOn(console,'warn').mockImplementation(()=>{}),env=environment();
    env.RPC_RATE_LIMITER.limit.mockRejectedValue(new Error('private-secret-and-query'));
    const response=await createGateway(vi.fn<typeof fetch>()).fetch(request(),env);
    expect(response.status).toBe(502);expect(await response.text()).not.toContain('private-secret-and-query');
    expect(logger).toHaveBeenCalledWith('arkiv_gateway_failure',{stage:'rate_limit',error_type:'unexpected'});
    expect(JSON.stringify(logger.mock.calls)).not.toContain('private-secret-and-query');
  });
});

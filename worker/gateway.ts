import reviewerPolicy from '../apps/web/public/data/trust-policy.json';

export const RPC_PATH = '/api/arkiv-rpc';
export const UPSTREAM = 'https://rpc.tiramisu.db-chain.testnet.arkiv.network';
export const MAX_REQUEST_BYTES = 8192;
export const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
export const UPSTREAM_TIMEOUT_MS = 14000;
const APP_ID = 'scamsignal-v1';
const creators = Object.freeze(reviewerPolicy.trusted_creators.map(value => value.toLowerCase()));
const ATTRIBUTE_NAMES = new Set(['app_id','schema_version','kind','apk_sha256','package_digest','version_code','signer_sha256','severity','target_key']);
const SELECT_NAMES = new Set(['key','owner','creator','createdAt','updatedAt','expiresAt','creationFlags','contentType','payload','attributeSchema','attributes']);
const U64_MAX = 18446744073709551615n;
type JsonObject = Record<string, unknown>;
type RpcId = string | number | null;
type GatewayEnv = Pick<Env,'ARKIV_API_KEY' | 'RPC_RATE_LIMITER'> & {ASSETS: Pick<Env['ASSETS'],'fetch'>};
type UpstreamFetch = typeof fetch;

class GatewayError extends Error {
  constructor(readonly status: number, readonly code: number, message: string) { super(message); }
}
function object(value: unknown): value is JsonObject { return typeof value === 'object' && value !== null && !Array.isArray(value); }
function fail(message = 'This RPC request is not permitted.'): never { throw new GatewayError(400,-32602,message); }
function quantity(value: unknown): bigint | null {
  if(typeof value === 'string' && /^(?:0x[0-9a-fA-F]{1,16}|[0-9]{1,20})$/.test(value)) {
    const n=BigInt(value); return n<=U64_MAX?n:null;
  }
  if(typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  return null;
}
function reply(id: RpcId, error: GatewayError): Response {
  const headers: Record<string,string> = {'content-type':'application/json','cache-control':'no-store','x-content-type-options':'nosniff'};
  if(error.status === 429) headers['retry-after']='60';
  return new Response(JSON.stringify({jsonrpc:'2.0',id,error:{code:error.code,message:error.message}}),{status:error.status,headers});
}
function success(id: RpcId, result: unknown): Response {
  return new Response(JSON.stringify({jsonrpc:'2.0',id,result}),{headers:{'content-type':'application/json','cache-control':'no-store','x-content-type-options':'nosniff'}});
}

/** Parse only the finite typed predicate grammar emitted by this product's SDK queries. */
export function validateQuery(query: unknown): string {
  if(typeof query !== 'string' || !query.length || query.length>4096) fail();
  let position=0, atoms=0;
  const scopes=new Set<string>();
  const ws=()=>{while(position<query.length && /\s/.test(query[position]!))position++;};
  const take=(pattern:RegExp):string=>{ws();const m=pattern.exec(query.slice(position));if(!m)fail();position+=m[0].length;return m[0];};
  const word=(value:string):boolean=>{ws();if(query.slice(position,position+value.length)===value && !/[A-Za-z0-9_]/.test(query[position+value.length] || '')){position+=value.length;return true;}return false;};
  const comparison=()=>{
    if(++atoms>64)fail();
    const name=take(/^(?:app_id|schema_version|\$creator|\$expiresAt|apk_sha256|package_digest|kind|\$key|target_key)(?![A-Za-z0-9_])/);
    const operator=take(/^[=>]/);
    const type=take(/^(?:str|u64|addr|bytes32|key)(?![A-Za-z0-9_])/);
    take(/^\(/);
    let value:string;
    if(type==='str')value=take(/^'(?:[^'\r\n]|''){0,128}'/).slice(1,-1).replaceAll("''", "'");
    else if(type==='u64')value=take(/^[0-9]{1,20}/);
    else value=take(/^0x[0-9a-fA-F]{40,64}/).toLowerCase();
    take(/^\)/);
    if(name==='app_id') {if(operator!=='=' || type!=='str' || value!==APP_ID)fail();scopes.add(name);}
    else if(name==='schema_version') {if(operator!=='=' || type!=='u64' || quantity(value)!==1n)fail();scopes.add(name);}
    else if(name==='$creator') {if(operator!=='=' || type!=='addr' || !creators.includes(value))fail();scopes.add(name);}
    else if(name==='$expiresAt') {if(operator!=='>' || type!=='u64' || quantity(value)===null)fail();scopes.add(name);}
    else if(name==='kind') {if(operator!=='=' || type!=='str' || !['passport','advisory','correction'].includes(value))fail();}
    else {const expected=['$key','target_key'].includes(name)?'key':'bytes32';if(operator!=='=' || type!==expected || !/^0x[0-9a-f]{64}$/.test(value))fail();}
  };
  const atom=(depth:number)=>{if(depth>8)fail();ws();if(query[position]==='('){position++;or(depth+1);take(/^\)/);}else comparison();};
  const and=(depth:number)=>{atom(depth);while(word('AND'))atom(depth);};
  const or=(depth:number)=>{and(depth);while(word('OR'))and(depth);};
  or(0);ws();if(position!==query.length || ['app_id','schema_version','$creator','$expiresAt'].some(s=>!scopes.has(s)))fail();
  if(!creators.length || creators.some(value=>!/^0x[0-9a-f]{40}$/.test(value)))throw new GatewayError(503,-32000,'Reviewer policy is unavailable.');
  // Never infer security from mere substring presence: an outer AND enforces every scope even across OR branches.
  const authors=creators.map(value=>`$creator = addr(${value})`).join(' OR ');
  return `app_id = str('${APP_ID}') AND schema_version = u64(1) AND (${authors}) AND (${query})`;
}

export function validateOptions(value: unknown): JsonObject {
  if(!object(value) || Object.keys(value).some(key=>!['limit','select','cursor','atBlock'].includes(key)))fail();
  const limit=quantity(value.limit);
  if(limit===null || limit<1n || limit>100n)fail('A query must declare a limit between 1 and 100.');
  if(value.cursor!==undefined && (typeof value.cursor!=='string' || !value.cursor.length || value.cursor.length>2048))fail();
  if(value.atBlock!==undefined && (value.cursor===undefined || quantity(value.atBlock)===null))fail();
  if(!object(value.select) || Object.keys(value.select).some(key=>!SELECT_NAMES.has(key)))fail();
  const select:JsonObject={...value.select};
  for(const [key,entry] of Object.entries(select)) {
    if(key==='attributes' && object(entry)) {
      if(Object.keys(entry).length>20 || Object.entries(entry).some(([name,v])=>!ATTRIBUTE_NAMES.has(name) || typeof v!=='boolean'))fail();
    } else if(typeof entry!=='boolean')fail();
  }
  // Protocol metadata is mandatory for server-side creator, namespace, schema and current-head expiry checks.
  select.creator=true;select.expiresAt=true;
  select.attributes=select.attributes===true?true:{...(object(select.attributes)?select.attributes:{}),app_id:true,schema_version:true};
  return {...value,limit:`0x${limit.toString(16)}`,select};
}

async function readBounded(stream: ReadableStream<Uint8Array> | null, limit:number, signal?:AbortSignal):Promise<string> {
  if(!stream)return '';
  const reader=stream.getReader();let bytes=0;const chunks:Uint8Array[]=[];
  const abort=()=>{void reader.cancel().catch(()=>{});};
  signal?.addEventListener('abort',abort,{once:true});
  try {
    while(true) {
      if(signal?.aborted)throw new GatewayError(504,-32000,'Arkiv request timed out.');
      const result=await reader.read();
      if(signal?.aborted)throw new GatewayError(504,-32000,'Arkiv request timed out.');
      if(result.done)break;
      bytes+=result.value.byteLength;
      if(bytes>limit){await reader.cancel();throw new GatewayError(limit===MAX_REQUEST_BYTES?413:502,-32000,'RPC body exceeds the permitted size.');}
      chunks.push(result.value);
    }
    const body=new Uint8Array(bytes);let offset=0;for(const chunk of chunks){body.set(chunk,offset);offset+=chunk.byteLength;}
    return new TextDecoder('utf-8',{fatal:true,ignoreBOM:false}).decode(body);
  } finally {signal?.removeEventListener('abort',abort);reader.releaseLock();}
}

async function upstream(method:string,params:unknown[],id:RpcId,key:string,signal:AbortSignal,fetcher:UpstreamFetch):Promise<unknown> {
  const response=await fetcher(UPSTREAM,{method:'POST',headers:{'content-type':'application/json','X-API-KEY':key},body:JSON.stringify({jsonrpc:'2.0',id,method,params}),redirect:'manual',signal});
  if(!response.ok){console.warn('arkiv_upstream_status',{method,status:response.status});await response.body?.cancel();throw new GatewayError(502,-32000,'Arkiv service is unavailable.');}
  const size=response.headers.get('content-length');if(size && Number(size)>MAX_RESPONSE_BYTES){await response.body?.cancel();throw new GatewayError(502,-32000,'RPC body exceeds the permitted size.');}
  const text=await readBounded(response.body,MAX_RESPONSE_BYTES,signal);
  let body:unknown;try{body=JSON.parse(text);}catch{throw new GatewayError(502,-32000,'Arkiv returned an invalid response.');}
  if(!object(body) || body.jsonrpc!=='2.0' || body.id!==id || !Object.hasOwn(body,'result') || Object.hasOwn(body,'error'))throw new GatewayError(502,-32000,'Arkiv could not complete this request.');
  return body.result;
}
function timingBlock(result:unknown):bigint {
  if(!object(result))throw new GatewayError(502,-32000,'Arkiv returned invalid timing.');
  const block=quantity(result.current_block);
  if(block===null || typeof result.current_block_time!=='number' || !Number.isFinite(result.current_block_time) || typeof result.duration!=='number' || result.duration<=0)throw new GatewayError(502,-32000,'Arkiv returned invalid timing.');
  return block;
}
function liveRecord(value:unknown,currentBlock:bigint):boolean {
  if(!object(value) || typeof value.creator!=='string' || !creators.includes(value.creator.toLowerCase()))return false;
  const expires=quantity(value.expiresAt);if(expires===null || expires<=currentBlock || !Array.isArray(value.attributes))return false;
  const namespace=value.attributes.find((a:unknown)=>object(a) && a.name==='app_id');
  const schema=value.attributes.find((a:unknown)=>object(a) && a.name==='schema_version');
  return object(namespace) && namespace.type==='str' && namespace.value===APP_ID && object(schema) && schema.type==='u64' && quantity(schema.value)===1n;
}

export function createGateway(fetcher:UpstreamFetch=(input,init)=>globalThis.fetch(input,init)) {
  return {async fetch(request:Request,env:GatewayEnv):Promise<Response> {
    const url=new URL(request.url);
    if(url.pathname!==RPC_PATH)return env.ASSETS.fetch(request);
    let id:RpcId=null;
    let stage='validation';
    const controller=new AbortController();let timer:ReturnType<typeof setTimeout>|undefined;
    try {
      if(request.method!=='POST')throw new GatewayError(405,-32600,'Use POST for this endpoint.');
      if(url.search || (request.headers.get('origin') && request.headers.get('origin')!==url.origin))throw new GatewayError(403,-32600,'Cross-origin RPC requests are not permitted.');
      if(request.headers.get('content-type')?.split(';')[0]?.trim().toLowerCase()!=='application/json')throw new GatewayError(415,-32600,'Use application/json.');
      const contentLength=request.headers.get('content-length');if(contentLength && (!/^\d+$/.test(contentLength) || Number(contentLength)>MAX_REQUEST_BYTES))throw new GatewayError(413,-32600,'RPC body exceeds the permitted size.');
      timer=setTimeout(()=>controller.abort(),5000);
      let rpc:unknown;try{rpc=JSON.parse(await readBounded(request.body,MAX_REQUEST_BYTES,controller.signal));}catch(error){if(error instanceof GatewayError)throw error;throw new GatewayError(400,-32700,'Invalid JSON-RPC body.');}
      clearTimeout(timer);
      if(!object(rpc) || rpc.jsonrpc!=='2.0' || Object.keys(rpc).some(k=>!['jsonrpc','id','method','params'].includes(k)) || !Object.hasOwn(rpc,'id') || !(rpc.id===null || (typeof rpc.id==='number' && Number.isSafeInteger(rpc.id)) || (typeof rpc.id==='string' && rpc.id.length<=80)))throw new GatewayError(400,-32600,'A single JSON-RPC request is required.');
      id=rpc.id as RpcId;
      if(!['arkiv_getBlockTiming','arkiv_query'].includes(String(rpc.method)))throw new GatewayError(403,-32601,'RPC method is not permitted.');
      if(!Array.isArray(rpc.params))fail();
      let query:string|undefined,options:JsonObject|undefined;
      if(rpc.method==='arkiv_getBlockTiming') {if(rpc.params.length)fail();}
      else {if(rpc.params.length!==2)fail();query=validateQuery(rpc.params[0]);options=validateOptions(rpc.params[1]);}
      if(!env.ARKIV_API_KEY)throw new GatewayError(503,-32000,'Arkiv gateway is not configured.');
      stage='rate_limit';
      const {success:allowed}=await env.RPC_RATE_LIMITER.limit({key:'scamsignal:public-read'});
      if(!allowed)throw new GatewayError(429,-32000,'Too many Arkiv requests. Try again shortly.');
      timer=setTimeout(()=>controller.abort(),UPSTREAM_TIMEOUT_MS);
      stage='timing';
      const timing=await upstream('arkiv_getBlockTiming',[],id,env.ARKIV_API_KEY,controller.signal,fetcher);
      const head=timingBlock(timing);
      if(rpc.method==='arkiv_getBlockTiming')return success(id,timing);
      if(options?.atBlock!==undefined && quantity(options.atBlock)! > head)fail();
      stage='query';
      const result=await upstream('arkiv_query',[query,options],id,env.ARKIV_API_KEY,controller.signal,fetcher);
      if(!object(result) || !Array.isArray(result.data) || result.data.length>100 || quantity(result.blockNumber)===null || (result.cursor!==undefined && (typeof result.cursor!=='string' || result.cursor.length>2048)))throw new GatewayError(502,-32000,'Arkiv returned an invalid query response.');
      // A stable query is necessary for opaque SDK cursors. Enforce live expiry again against the fresh head on every page.
      return success(id,{...result,data:result.data.filter(record=>liveRecord(record,head))});
    } catch(error) {
      if(!(error instanceof GatewayError) || error.status>=500) {
        const errorType=error instanceof GatewayError?'gateway':error instanceof TypeError?(/illegal invocation/i.test(error.message)?'fetch_receiver':/redirect/i.test(error.message)?'redirect_mode':'type_error'):error instanceof SyntaxError?'syntax_error':controller.signal.aborted?'timeout':'unexpected';
        console.warn('arkiv_gateway_failure',{stage,error_type:errorType});
      }
      return reply(id,error instanceof GatewayError?error:new GatewayError(controller.signal.aborted?504:502,-32000,controller.signal.aborted?'Arkiv request timed out.':'Arkiv service is unavailable.'));
    } finally {if(timer!==undefined)clearTimeout(timer);}
  }};
}

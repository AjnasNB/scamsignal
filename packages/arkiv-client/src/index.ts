import { createPublicClient, createWalletClient, ExpirationTime, jsonToPayload } from '@arkiv-network/sdk';
import { addr, bytes32, key as entityKey, str, u64 } from '@arkiv-network/sdk/attr';
import { tiramisu } from '@arkiv-network/sdk/chains';
import { eq, gt, or, type Expression } from '@arkiv-network/sdk/query';
import { custom, http, webSocket, sha256, stringToHex, type Hex } from 'viem';
import { z } from 'zod';

// Avoid Zod's dynamic-code feature probe under the site's strict script policy.
z.config({ jitless: true });

export const APP_ID = 'scamsignal-v1';
export const RPC_URL = 'https://rpc.tiramisu.db-chain.testnet.arkiv.network';
export const WS_URL = 'wss://rpc.tiramisu.db-chain.testnet.arkiv.network';
export const EXPLORER = 'https://tiramisu.explorer.arkiv.network';
const hashSchema = z.string().regex(/^[a-f0-9]{64}$/);
const walletSchema = z.string().regex(/^0x[0-9a-fA-F]{40}$/);
const keySchema = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
const kindSchema = z.enum(['passport', 'advisory', 'correction']);

export const recordPayloadSchema = z.object({
  app_id: z.literal(APP_ID), schema_version: z.literal(1), kind: kindSchema,
  apk_sha256: hashSchema, package_name: z.string().min(1).max(512),
  display_name: z.string().min(1).max(120), version_code: z.number().int().nonnegative().nullable(),
  signer_sha256: z.array(hashSchema).max(12), reviewed_at: z.iso.datetime(),
  title: z.string().max(180), summary: z.string().max(3000),
  evidence: z.array(z.string().max(400)).max(30),
  severity: z.enum(['info', 'review', 'high']),
  classification: z.enum(['open_source_release', 'documented_malware_sample', 'insecure_training_app', 'synthetic_demo']),
  reference_url: z.url().max(1200),
  target_key: keySchema.optional(), action: z.literal('retract').optional(),
}).strict();

export type RecordPayload = z.infer<typeof recordPayloadSchema>;
export interface PublicRecord {
  key: string; creator: string; owner: string; kind: RecordPayload['kind'];
  apk_sha256: string; package_name: string; display_name: string; title: string; summary: string;
  severity: RecordPayload['severity']; signer_sha256: string[];
  reviewed_at: string; expires_at: string; expires_at_block: string;
  created_at_block: string; payload: RecordPayload; explorer_url: string;
  readonly: boolean;
}
export interface ReportIdentity {
  apk_sha256: string; package_name: string;
  signature: {status: 'verified' | 'invalid' | 'unavailable'; signer_sha256: string[]};
}
export interface ArkivConfiguration {
  trusted_creators: string[]; rpc_url?: string; ws_url?: string;
  browser_rpc_url?: string;
  reviewer_labels?: Record<string,string>;
}
export interface ArkivResolution {
  status: 'available' | 'unavailable';
  passport: {status:'exact_match'|'signer_mismatch'|'unknown'|'incomplete';records:PublicRecord[]};
  warnings: PublicRecord[]; ignored_count: number; error?: string;
}
let configuration: ArkivConfiguration = {trusted_creators:[]};
let initialized = false;
const observedRecordKeys = new Set<string>();
export function configureArkiv(config: ArkivConfiguration) {
  const creators = z.array(walletSchema).max(20).parse(config.trusted_creators);
  configuration = {...config, trusted_creators:[...new Set(creators.map(a=>a.toLowerCase()))]};
  observedRecordKeys.clear();
  initialized = true;
}
export function getArkivConfiguration(): ArkivConfiguration { return {...configuration, trusted_creators:[...configuration.trusted_creators]}; }
async function ensureConfiguration() {
  if (initialized) return;
  if (typeof window === 'undefined') throw new Error('Configure trusted reviewer wallets before querying Arkiv.');
  const response = await fetch('/data/trust-policy.json', {cache:'no-cache'});
  if (!response.ok) throw new Error('Reviewer policy could not be loaded.');
  configureArkiv(await response.json());
}
// Retry-After can be hours on an exhausted RPC quota. Surface the failure instead
// of allowing transport retries to keep the consumer waiting indefinitely.
function publicClient() {
  const endpoint = typeof window !== 'undefined' && configuration.browser_rpc_url
    ? configuration.browser_rpc_url : configuration.rpc_url || RPC_URL;
  return createPublicClient({chain:tiramisu, transport:http(endpoint,{timeout:18000,retryCount:0})});
}
export function isTrustedCreator(creator: string, policy = configuration): boolean {
  return policy.trusted_creators.some(a=>a.toLowerCase() === creator.toLowerCase());
}
export async function packageDigest(name: string): Promise<Hex> {
  return sha256(stringToHex(name));
}
function toHash(value:string): Hex { return `0x${hashSchema.parse(value.toLowerCase().replace(/^0x/,''))}`; }
function attributeValue(entity:any,name:string) { return entity.attributes?.[name]?.value; }

/** Accept protocol metadata only. A payload's publisher/issuer field never establishes authorship. */
export function decodePublicRecord(entity:any,timing:{currentBlock:bigint;currentBlockTime:number;blockDuration:number}, policy=configuration): PublicRecord | null {
  try {
  // A transferred mutable record could retain a trusted creator while its new owner edits it.
  if (entity.creationFlags?.readonly !== true) return null;
  if (!entity.creator || !entity.key || !isTrustedCreator(entity.creator,policy)) return null;
  if (entity.expiresAt === undefined || BigInt(entity.expiresAt) <= timing.currentBlock) return null;
  if (attributeValue(entity,'app_id') !== APP_ID || attributeValue(entity,'schema_version') !== 1n) return null;
  let parsed:ReturnType<typeof recordPayloadSchema.safeParse>;
  try { parsed=recordPayloadSchema.safeParse(entity.toJson ? entity.toJson() : entity.payload_json); } catch { return null; }
  if (!parsed.success) return null;
  const payload=parsed.data;
  if (!keySchema.safeParse(entity.key).success || !walletSchema.safeParse(entity.creator).success) return null;
  if (attributeValue(entity,'kind') !== payload.kind || attributeValue(entity,'apk_sha256') !== toHash(payload.apk_sha256)) return null;
  if (attributeValue(entity,'package_digest') !== sha256(stringToHex(payload.package_name))) return null;
  if (payload.version_code !== null && attributeValue(entity,'version_code') !== BigInt(payload.version_code)) return null;
  if (payload.signer_sha256.length && attributeValue(entity,'signer_sha256') !== toHash(payload.signer_sha256[0])) return null;
  if (payload.kind === 'passport' && !payload.signer_sha256.length) return null;
  if (payload.kind === 'advisory' && attributeValue(entity,'severity') !== payload.severity) return null;
  if (payload.kind === 'correction' && (!payload.target_key || !payload.action || attributeValue(entity,'target_key') !== payload.target_key)) return null;
  const expiryMs = timing.currentBlockTime*1000 + Number(BigInt(entity.expiresAt)-timing.currentBlock)*timing.blockDuration*1000;
  return {...payload, payload, key:entity.key,creator:entity.creator,owner:entity.owner || entity.creator,
    expires_at:new Date(expiryMs).toISOString(),expires_at_block:String(entity.expiresAt),
    created_at_block:String(entity.createdAt || 0n),readonly:entity.creationFlags?.readonly === true,
    explorer_url:`${EXPLORER}/entity/${entity.key}`};
  } catch { return null; }
}

function baseFilters(block:bigint): Expression[] {
  if (!configuration.trusted_creators.length) throw new Error('No approved reviewer wallets are configured.');
  return [eq('app_id',str(APP_ID)),eq('schema_version',u64(1)),gt('$expiresAt',u64(block)),
    or(configuration.trusted_creators.map(a=>eq('$creator',addr(a as Hex))))];
}
async function queryRecords(extra:Expression[] = []) {
  await ensureConfiguration();
  const client=publicClient();
  const timing=await client.getBlockTiming();
  const query=client.select().where(...baseFilters(timing.currentBlock),...extra).limit(100);
  let page=await query.fetch();
  const records:PublicRecord[]=[]; let ignored=0; let pages=0;
  while (true) {
    for (const entity of page.entities) {
      const record=decodePublicRecord(entity,timing);
      if (record) {
        records.push(record);
        if (observedRecordKeys.size >= 2000) observedRecordKeys.delete(observedRecordKeys.values().next().value!);
        observedRecordKeys.add(record.key.toLowerCase());
      } else ignored++;
    }
    if (!page.hasNextPage()) break;
    if (++pages >= 10) throw new Error('The record feed is too large to verify completely. Narrow your query.');
    page=await page.next();
  }
  return {records,ignored_count:ignored,query:query.toString(),block:String(page.blockNumber)};
}

export function resolveRecords(report:ReportIdentity, records:PublicRecord[], ignored=0):ArkivResolution {
  const corrections=records.filter(r=>r.kind==='correction');
  const activeRecords=records.filter(w=>!corrections.some(c=>c.payload.action==='retract' && c.payload.target_key===w.key && c.creator.toLowerCase()===w.creator.toLowerCase() && c.apk_sha256===w.apk_sha256 && c.package_name===w.package_name && BigInt(c.created_at_block)>=BigInt(w.created_at_block)));
  const exact=activeRecords.filter(r=>r.kind==='passport' && r.apk_sha256===report.apk_sha256 && r.package_name===report.package_name);
  const references=activeRecords.filter(r=>r.kind==='passport' && r.package_name===report.package_name);
  const scanSigners=[...report.signature.signer_sha256].sort().join(',');
  const exactVerified=exact.filter(r=>[...r.signer_sha256].sort().join(',')===scanSigners);
  let status:ArkivResolution['passport']['status']='unknown';
  if (report.signature.status!=='verified' || !report.signature.signer_sha256.length) status='incomplete';
  else if (exactVerified.length) status='exact_match';
  else if (references.length && !references.some(r=>[...r.signer_sha256].sort().join(',')===scanSigners)) status='signer_mismatch';
  const warnings=activeRecords.filter(r=>r.kind==='advisory' && r.apk_sha256===report.apk_sha256 && r.package_name===report.package_name);
  return {status:'available',passport:{status,records:exact.length?exact:references},warnings,ignored_count:ignored};
}

export async function resolveReport(report:ReportIdentity):Promise<ArkivResolution> {
  try {
    hashSchema.parse(report.apk_sha256);
    const digest=await packageDigest(report.package_name);
    const data=await queryRecords([or(eq('apk_sha256',bytes32(toHash(report.apk_sha256))),eq('package_digest',bytes32(digest)))]);
    return resolveRecords(report,data.records,data.ignored_count);
  } catch {
    return {status:'unavailable',passport:{status:'incomplete',records:[]},warnings:[],ignored_count:0,error:'Arkiv records could not be verified. No safety conclusion can be drawn from this lookup.'};
  }
}
export async function listPublicRecords(options:{kind?:RecordPayload['kind'];apk_sha256?:string}={}) {
  const filters:Expression[]=[];
  if (options.kind) filters.push(eq('kind',str(kindSchema.parse(options.kind))));
  if (options.apk_sha256) filters.push(eq('apk_sha256',bytes32(toHash(options.apk_sha256))));
  return queryRecords(filters);
}

export interface PublishInput {
  kind:RecordPayload['kind']; apk_sha256:string;package_name:string;display_name:string;
  version_code?:number|null;signer_sha256?:string[]; title?:string;summary:string;
  evidence?:string[]; severity?:RecordPayload['severity'];classification:RecordPayload['classification'];
  reference_url:string;target_key?:string;action?:'retract';expires_days?:number;
}
export async function buildEntityInput(input:PublishInput) {
  const payload=recordPayloadSchema.parse({app_id:APP_ID,schema_version:1,kind:input.kind,
    apk_sha256:input.apk_sha256.toLowerCase(),package_name:input.package_name,display_name:input.display_name,
    version_code:input.version_code ?? null,signer_sha256:input.signer_sha256 || [],reviewed_at:new Date().toISOString(),
    title:input.title || input.display_name,summary:input.summary,evidence:input.evidence || [],
    severity:input.severity || 'info',classification:input.classification,reference_url:input.reference_url,
    ...(input.target_key?{target_key:input.target_key}:{}),...(input.action?{action:input.action}:{})});
  if (payload.kind==='passport' && !payload.signer_sha256.length) throw new Error('A passport requires a verified signing certificate.');
  if (payload.kind==='correction' && (!payload.target_key || !payload.action)) throw new Error('A correction requires its target and action.');
  if (!/^https:\/\//.test(payload.reference_url)) throw new Error('Reference URLs must use HTTPS.');
  const attributes:any={app_id:str(APP_ID),schema_version:u64(1),kind:str(payload.kind),apk_sha256:bytes32(toHash(payload.apk_sha256)),package_digest:bytes32(await packageDigest(payload.package_name))};
  if (payload.version_code!==null) attributes.version_code=u64(payload.version_code);
  if (payload.signer_sha256[0]) attributes.signer_sha256=bytes32(toHash(payload.signer_sha256[0]));
  if (payload.target_key) attributes.target_key=entityKey(payload.target_key as Hex);
  if (payload.kind==='advisory') attributes.severity=str(payload.severity);
  const days=input.expires_days ?? (input.kind==='advisory'?14:30);
  if (!Number.isInteger(days) || days<1 || days>90) throw new Error('Lifetime must be 1 to 90 days.');
  return {attributes,payload:jsonToPayload(payload),contentType:'application/json',expires:ExpirationTime.fromDays(days),flags:{readonly:true,permissionlessExtension:false}};
}

export async function connectReviewer():Promise<string> {
  await ensureConfiguration();
  const provider=(globalThis as any).ethereum;
  if (!provider) throw new Error('Install or open a wallet-enabled browser to publish reviewed records.');
  const accounts=await provider.request({method:'eth_requestAccounts'});
  const account=accounts[0] as string;
  if (!isTrustedCreator(account)) throw new Error('This wallet is not an approved reviewer in the published policy.');
  const chain=await provider.request({method:'eth_chainId'});
  if (chain!=='0x7614d1') {
    try { await provider.request({method:'wallet_switchEthereumChain',params:[{chainId:'0x7614d1'}]}); }
    catch (error:any) {
      if (error.code!==4902) throw error;
      await provider.request({method:'wallet_addEthereumChain',params:[{chainId:'0x7614d1',chainName:'Arkiv Tiramisu',rpcUrls:[RPC_URL],nativeCurrency:{name:'GLM',symbol:'GLM',decimals:18},blockExplorerUrls:[EXPLORER]}]});
    }
  }
  return account;
}
export async function publishRecord(input:PublishInput) {
  const account=await connectReviewer();
  if (input.kind==='correction') {
    const targetRecords=await queryRecords([eq('$key',entityKey(input.target_key as Hex))]);
    const verified=targetRecords.records.find(record=>record.key.toLowerCase()===input.target_key?.toLowerCase());
    if (!verified || verified.creator.toLowerCase()!==account.toLowerCase()) throw new Error('Only the original reviewer can correct a live verified record.');
    if (!verified || verified.kind==='correction' || verified.apk_sha256!==input.apk_sha256 || verified.package_name!==input.package_name) throw new Error('The correction must identify the original artifact and a verified passport or advisory.');
    const minimumDays=Math.ceil((Date.parse(verified.expires_at)-Date.now())/86400000)+1;
    input={...input,expires_days:Math.max(input.expires_days||30,minimumDays)};
  }
  const wallet=createWalletClient({chain:tiramisu,transport:custom((globalThis as any).ethereum),account:account as Hex});
  const result=await wallet.createEntity(await buildEntityInput(input));
  return {entity_key:result.entityKey,tx_hash:result.txHash,entityKey:result.entityKey,txHash:result.txHash};
}
export function isRelevantRecordEvent(event:{entityKey:string;owner?:string;previousOwner?:string;newOwner?:string}, knownKeys:ReadonlySet<string> = observedRecordKeys):boolean {
  return knownKeys.has(event.entityKey.toLowerCase()) ||
    [event.owner,event.previousOwner,event.newOwner].some(owner=>!!owner && isTrustedCreator(owner));
}
export function watchRecords(onChange:()=>void,onError?:(error:Error)=>void):()=>void {
  const client=createPublicClient({chain:tiramisu,transport:webSocket(configuration.ws_url || WS_URL)});
  return client.watchEntityEvents({onEvent:event=>{
    // The shared chain contains other applications. Only trusted reviewers or
    // records already verified by this client invalidate our current result.
    if (isRelevantRecordEvent(event)) onChange();
  },onError});
}

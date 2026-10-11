import {describe,it,expect,beforeEach,afterEach,vi} from 'vitest';
import {addr,bytes32,str,u64,key} from '@arkiv-network/sdk/attr';
import {sha256,stringToHex} from 'viem';
import {APP_ID,configureArkiv,decodePublicRecord,resolveRecords,buildEntityInput,isRelevantRecordEvent,listPublicRecords,type RecordPayload,type PublicRecord} from './index';
const reviewer='0x1111111111111111111111111111111111111111';
const stranger='0x2222222222222222222222222222222222222222';
const digest='a'.repeat(64),signer='b'.repeat(64),pkg='dev.scamsignal.fixture';
const timing={currentBlock:100n,currentBlockTime:1791726650,blockDuration:2};
const payload:RecordPayload={app_id:APP_ID,schema_version:1,kind:'passport',apk_sha256:digest,package_name:pkg,display_name:'Synthetic fixture',version_code:1,signer_sha256:[signer],reviewed_at:'2026-10-11T13:00:00.000Z',title:'Reviewed artifact',summary:'Synthetic integration fixture.',evidence:[],severity:'info',classification:'synthetic_demo',reference_url:'https://example.com/fixture'};
function entity(p:RecordPayload=payload){return {key:`0x${'c'.repeat(64)}`,creator:reviewer,owner:reviewer,createdAt:90n,expiresAt:1000n,creationFlags:{readonly:true},payload_json:p,attributes:{app_id:str(APP_ID),schema_version:u64(1),kind:str(p.kind),apk_sha256:bytes32(`0x${p.apk_sha256}`),package_digest:bytes32(sha256(stringToHex(p.package_name))),version_code:u64(1),signer_sha256:bytes32(`0x${signer}`),severity:str(p.severity),...(p.target_key?{target_key:key(p.target_key as `0x${string}`)}:{})}};}
function record(p:RecordPayload=payload):PublicRecord{return decodePublicRecord(entity(p),timing)!;}
const report={apk_sha256:digest,package_name:pkg,signature:{status:'verified' as const,signer_sha256:[signer]}};
beforeEach(()=>configureArkiv({trusted_creators:[reviewer]}));
afterEach(()=>vi.unstubAllGlobals());

describe('Shared network updates and quota failures',()=>{
 it('ignores other projects but retains updates to trusted or transferred records',()=>{
  const entityKey=`0x${'e'.repeat(64)}`;
  expect(isRelevantRecordEvent({entityKey,owner:stranger})).toBe(false);
  expect(isRelevantRecordEvent({entityKey,owner:reviewer})).toBe(true);
  expect(isRelevantRecordEvent({entityKey,previousOwner:reviewer,newOwner:stranger})).toBe(true);
  expect(isRelevantRecordEvent({entityKey,owner:stranger},new Set([entityKey]))).toBe(true);
 });
 it('surfaces exhausted quota without waiting for a long Retry-After',async()=>{
  let queries=0;
  vi.stubGlobal('fetch',vi.fn(async(_url,init)=>{
   const request=JSON.parse(String(init.body));
   if(request.method==='arkiv_getBlockTiming') return Response.json({jsonrpc:'2.0',id:request.id,result:{current_block:100,current_block_time:1791726650,duration:2}});
   queries++;
   return Response.json({error:{code:'ANON_COST_LIMITED',message:'quota exhausted'}},{status:429,headers:{'Retry-After':'3600'}});
  }));
  let deadline:ReturnType<typeof setTimeout>|undefined;
  try {
   const bounded=Promise.race([listPublicRecords({apk_sha256:digest}),new Promise((_,reject)=>{deadline=setTimeout(()=>reject(new Error('RPC quota retry did not finish promptly')),1000);})]);
   await expect(bounded).rejects.not.toThrow('did not finish promptly');
   expect(queries).toBe(1);
  } finally {if(deadline)clearTimeout(deadline);}
 });
});
describe('Protocol-authored trust and indexed artifact binding',()=>{
 it('accepts an approved live record and computes a real expiry',()=>{const r=record();expect(r.creator).toBe(reviewer);expect(Date.parse(r.expires_at)).toBe((timing.currentBlockTime+1800)*1000);});
 it('rejects a forged publisher regardless of identical trusted content',()=>expect(decodePublicRecord({...entity(),creator:stranger},timing)).toBeNull());
 it('rejects mutable records even when a trusted creator transferred them',()=>{expect(decodePublicRecord({...entity(),owner:stranger,creationFlags:{readonly:false}},timing)).toBeNull();expect(decodePublicRecord({...entity(),creationFlags:undefined},timing)).toBeNull();});
 it('rejects expired and malformed protocol expiry values',()=>{expect(decodePublicRecord({...entity(),expiresAt:100n},timing)).toBeNull();expect(decodePublicRecord({...entity(),expiresAt:'invalid'},timing)).toBeNull();});
 it('rejects namespace and indexed artifact mismatches',()=>{for(const [name,value] of Object.entries({app_id:str('other-project'),apk_sha256:bytes32(`0x${'d'.repeat(64)}`),package_digest:bytes32(`0x${'d'.repeat(64)}`),version_code:u64(9),signer_sha256:bytes32(`0x${'d'.repeat(64)}`)})){const e=entity();(e.attributes as Record<string,unknown>)[name]=value;expect(decodePublicRecord(e,timing)).toBeNull();}});
 it('rejects unrecognized personal or author-claim fields',()=>{expect(decodePublicRecord(entity({...payload,publisher:'government'} as RecordPayload),timing)).toBeNull();});
});
describe('Passport and warning decisions',()=>{
 it('matches only a verified exact artifact and certificate set',()=>expect(resolveRecords(report,[record()]).passport.status).toBe('exact_match'));
 it('leaves an unseen version unknown even when its signer matches',()=>expect(resolveRecords({...report,apk_sha256:'d'.repeat(64)},[record()]).passport.status).toBe('unknown'));
 it('detects a signer change and marks unavailable verification incomplete',()=>{expect(resolveRecords({...report,signature:{status:'verified',signer_sha256:['d'.repeat(64)]}},[record()]).passport.status).toBe('signer_mismatch');expect(resolveRecords({...report,signature:{status:'unavailable',signer_sha256:[]}},[record()]).passport.status).toBe('incomplete');});
 it('requires same reviewer, artifact and ordering to retract',()=>{const advisory=record({...payload,kind:'advisory',severity:'high'});const correction={...record({...payload,kind:'correction',target_key:advisory.key,action:'retract'}),key:`0x${'d'.repeat(64)}`,created_at_block:'91'};expect(resolveRecords(report,[advisory,correction]).warnings).toHaveLength(0);for(const patch of [{creator:stranger},{apk_sha256:'d'.repeat(64)},{created_at_block:'89'}])expect(resolveRecords(report,[advisory,{...correction,...patch}]).warnings).toHaveLength(1);expect(resolveRecords(report,[advisory,{...correction,expires_at_block:'999'}]).warnings).toHaveLength(0);});
 it('can retract a passport instead of preserving withdrawn approval',()=>{const passport=record();const c={...record({...payload,kind:'correction',target_key:passport.key,action:'retract'}),created_at_block:'91'};expect(resolveRecords(report,[passport,c]).passport.status).toBe('unknown');});
});
describe('Publication constraints',()=>{
 it('requires HTTPS evidence, signing identity and bounded lifetime',async()=>{const input={kind:'passport' as const,apk_sha256:digest,package_name:pkg,display_name:'Fixture',summary:'Test',classification:'synthetic_demo' as const,reference_url:'https://example.com',signer_sha256:[signer]};await expect(buildEntityInput({...input,signer_sha256:[]})).rejects.toThrow('certificate');await expect(buildEntityInput({...input,reference_url:'http://example.com'})).rejects.toThrow('HTTPS');await expect(buildEntityInput({...input,expires_days:91})).rejects.toThrow('Lifetime');});
});

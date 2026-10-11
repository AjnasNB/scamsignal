import fs from 'node:fs/promises';
import path from 'node:path';
import {privateKeyToAccount} from 'viem/accounts';
import {http} from 'viem';
import {createWalletClient,createPublicClient} from '@arkiv-network/sdk';
import {tiramisu} from '@arkiv-network/sdk/chains';
import {buildEntityInput,RPC_URL,configureArkiv,listPublicRecords,decodePublicRecord,type PublishInput} from '../packages/arkiv-client/src/index';

// This file is an operator tool. Keys must stay outside the checkout and are never printed.
async function main() {
async function privateFile(file:string) {
 const root=await fs.realpath(process.cwd());
 const resolved=await fs.realpath(file);
 const relative=path.relative(root,resolved);
 if(relative===''||(!relative.startsWith('..'+path.sep)&&!path.isAbsolute(relative)))throw new Error('Operator credentials must stay outside the repository.');
 return resolved;
}
const keyFile=process.env.SCAMSIGNAL_WALLET_FILE;
if(!keyFile)throw new Error('Set SCAMSIGNAL_WALLET_FILE to a private testnet wallet JSON outside the repository.');
const wallets=JSON.parse(await fs.readFile(await privateFile(keyFile),'utf8'));
const account=privateKeyToAccount(wallets.find((w:any)=>w.role==='reviewer').private_key);
const policy=JSON.parse(await fs.readFile('apps/web/public/data/trust-policy.json','utf8'));
configureArkiv({...policy,rpc_url:process.env.SCAMSIGNAL_READ_RPC_URL||policy.rpc_url});
const accessKeyFile=process.env.SCAMSIGNAL_ARKIV_KEY_FILE;
const accessKey=accessKeyFile?(await fs.readFile(await privateFile(accessKeyFile),'utf8')).trim():undefined;
if(accessKey!==undefined&&(!accessKey||/[\r\n]/.test(accessKey)))throw new Error('The operator RPC key file is invalid.');
const operatorTransport=()=>http(RPC_URL,{timeout:18000,retryCount:0,...(accessKey?{fetchOptions:{headers:{'X-API-KEY':accessKey}}}:{})});
if(!policy.trusted_creators.some((a:string)=>a.toLowerCase()===account.address.toLowerCase()))throw new Error('The signing wallet does not match the published reviewer policy.');
const publicClient=createPublicClient({chain:tiramisu,transport:operatorTransport()});
if(await publicClient.getBalance({address:account.address})===0n)throw new Error('Fund the dedicated reviewer with free Tiramisu testnet GLM before publishing.');
const wallet=createWalletClient({chain:tiramisu,account,transport:operatorTransport()});
const evaluation=JSON.parse(await fs.readFile('scanner/evaluation.json','utf8'));
await fs.mkdir('arkiv',{recursive:true});
let evidence:any={schema_version:1,network:'Arkiv Tiramisu',chain_id:tiramisu.id,creator_wallet:account.address,records:[]};
try{evidence=JSON.parse(await fs.readFile('arkiv/evidence.json','utf8'));}catch{}
for(const sample of evaluation.samples){
 const r=sample.report;
 if(r.signature.status!=='verified')throw new Error(`Cannot create a passport without verified APK signatures: ${sample.name}`);
 const training=sample.classification==='intentionally-insecure-training-app';
 const malicious=sample.classification==='documented-malware-sample';
 if(malicious&&(sample.evidence_confidence!=='primary-report-hash-match'||!sample.evidence_hash||!sample.evidence_urls?.length))throw new Error('Malware publication requires an exact primary research digest match.');
 const classification=training?'insecure_training_app':malicious?'documented_malware_sample':'open_source_release';
 const base={apk_sha256:r.apk_sha256,package_name:r.package_name,display_name:sample.name,version_code:r.version_code,signer_sha256:r.signature.signer_sha256,classification,reference_url:sample.source_url} as const;
 const inputs:PublishInput[]=[{...base,kind:'passport',title:`${sample.name}: reviewed artifact reference`,summary:`Project-curated reference for this exact public APK release. Signature verification passed. This establishes artifact identity, not publisher endorsement or safety. ${sample.ground_truth_note}`,evidence:[`Release: ${sample.release}`,`Verified schemes: ${r.signature.schemes.join(', ')}`,`Declared permissions: ${r.permissions.length}`,`Analysis: manifest and signing only; no execution or DEX behavior.`,...r.permissions.map((p:any)=>`Declared permission: ${p.name}`),...r.findings.map((f:any)=>`${f.title_en}: ${f.evidence.join('; ')}`.slice(0,400))],expires_days:30}];
 if(training){inputs.push({...base,kind:'advisory',severity:'high',title:`${sample.name}: intentionally insecure training app`,summary:'This public application is designed for security training. Static analysis found unsafe defaults and sensitive capabilities. Use a controlled training environment; do not use it with personal accounts or information. This is a training case, not a confirmed real-world scam.',evidence:r.findings.filter((f:any)=>f.severity!=='info').slice(0,12).map((f:any)=>`${f.title_en}: ${f.evidence.join('; ')}`.slice(0,400)),expires_days:14});}
 if(malicious){inputs.push({...base,kind:'advisory',severity:'high',reference_url:sample.evidence_urls[0],title:`${sample.name}: documented historical malware`,summary:`The exact APK digest matches the original research report's indicator of compromise for ${sample.malware_family}. Treat this specimen as malicious and do not install it. This classification is based on the cited primary research, not a permission score. Our evaluation verified the manifest and cryptographic signature only; it did not execute the APK or reproduce malicious behavior.`,evidence:[`Primary research digest (${sample.evidence_hash.algorithm}): ${sample.evidence_hash.value}`,`Uploaded APK SHA-256: ${r.apk_sha256}`,`Research classification: ${sample.malware_family}`,...sample.evidence_urls.map((url:string)=>`Source: ${url}`),`Static signature: ${r.signature.status}; valid signatures do not establish safety.`,`Sensitive declared permissions: ${r.permissions.filter((p:any)=>p.category==='sensitive').length}`,...r.findings.slice(0,8).map((f:any)=>`${f.title_en}: ${f.evidence.join('; ')}`.slice(0,400))],expires_days:14});}
 for(const input of inputs){
  const existing=evidence.records.find((e:any)=>e.sample_id===sample.id&&e.kind===input.kind);
  if(existing){try{
   const record=decodePublicRecord(await publicClient.getEntity(existing.entity_key),await publicClient.getBlockTiming());
   if(record&&record.creator.toLowerCase()===account.address.toLowerCase()&&record.kind===input.kind&&record.apk_sha256===r.apk_sha256&&record.package_name===r.package_name&&[...record.signer_sha256].sort().join(',')===[...r.signature.signer_sha256].sort().join(',')){
    console.log(JSON.stringify({sample:sample.id,kind:input.kind,reused:true}));continue;
   }
  }catch{}}
  const result=await wallet.createEntity(await buildEntityInput(input));
  const entry={sample_id:sample.id,kind:input.kind,apk_sha256:r.apk_sha256,package_name:r.package_name,creator:account.address,entity_key:result.entityKey,tx_hash:result.txHash,expires_at_block:String(result.expiresAt),tx_url:`https://tiramisu.explorer.arkiv.network/tx/${result.txHash}`};
  evidence.records=evidence.records.filter((e:any)=>!(e.sample_id===sample.id&&e.kind===input.kind));evidence.records.push(entry);
  evidence.published_at=new Date().toISOString();
  await fs.writeFile('arkiv/evidence.json',JSON.stringify(evidence,null,2)+'\n');
  console.log(JSON.stringify({sample:sample.id,kind:input.kind,entity_key:result.entityKey,tx_hash:result.txHash}));
 }
}
const read=await listPublicRecords();
const expected=evaluation.samples.flatMap((s:any)=>[{sample_id:s.id,kind:'passport',hash:s.report.apk_sha256,pkg:s.report.package_name},...(['intentionally-insecure-training-app','documented-malware-sample'].includes(s.classification)?[{sample_id:s.id,kind:'advisory',hash:s.report.apk_sha256,pkg:s.report.package_name}]:[])]);
if(!expected.every((e:any)=>read.records.some(r=>r.kind===e.kind&&r.apk_sha256===e.hash&&r.package_name===e.pkg&&r.creator.toLowerCase()===account.address.toLowerCase())))throw new Error('The required artifact passports and source-backed advisories were not all verified on chain.');
evidence.verified_at=new Date().toISOString();evidence.live_query=read.query;evidence.verified_record_count=read.records.length;evidence.read_block=read.block;
await fs.writeFile('arkiv/evidence.json',JSON.stringify(evidence,null,2)+'\n');
await fs.writeFile('apps/web/public/data/arkiv-evidence.json',JSON.stringify(evidence,null,2)+'\n');
console.log(JSON.stringify({verified_record_count:read.records.length,query:read.query}));
}
main().catch(error=>{
 // RPC exceptions may include request metadata. Never dump credential-bearing objects.
 console.error(JSON.stringify({status:'failed',error_type:error instanceof Error?error.name:'UnknownError'}));
 process.exitCode=1;
});

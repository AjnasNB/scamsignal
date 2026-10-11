import fs from 'node:fs/promises';
import path from 'node:path';
import {http} from 'viem';
import {createPublicClient} from '@arkiv-network/sdk';
import {tiramisu} from '@arkiv-network/sdk/chains';
import {configureArkiv,resolveReport,listPublicRecords,decodePublicRecord,RPC_URL} from '../packages/arkiv-client/src/index';

// The free public gateway keeps its access key on the server. Override this URL
// for another deployment; never put an access key in a URL or the public policy.
const DEFAULT_READ_RPC_URL='https://scamsignal.ajnasnb.com/api/arkiv-rpc';

async function main() {
 const policy=JSON.parse(await fs.readFile('apps/web/public/data/trust-policy.json','utf8'));
 const readRpcUrl=process.env.SCAMSIGNAL_READ_RPC_URL||DEFAULT_READ_RPC_URL;
 configureArkiv({...policy,rpc_url:readRpcUrl});
 const evaluation=JSON.parse(await fs.readFile('scanner/evaluation.json','utf8'));
 const evidence=JSON.parse(await fs.readFile('arkiv/evidence.json','utf8'));
 const results=[];
 for(const sample of evaluation.samples){
  const result=await resolveReport(sample.report);
  const training=sample.classification==='intentionally-insecure-training-app';
  const malware=sample.classification==='documented-malware-sample';
  const expectedWarnings=training||malware?1:0;
  const expectedClassification=training?'insecure_training_app':malware?'documented_malware_sample':'open_source_release';
  const sampleEvidence=evidence.records.filter((record:any)=>record.sample_id===sample.id);
  const resolved=[...result.passport.records,...result.warnings];
  const identityChecked=resolved.every(record=>record.readonly&&record.apk_sha256===sample.report.apk_sha256&&record.package_name===sample.report.package_name&&record.payload.classification===expectedClassification);
  const keysChecked=sampleEvidence.length===1+expectedWarnings&&sampleEvidence.every((record:any)=>resolved.some(actual=>actual.key===record.entity_key&&actual.kind===record.kind));
  const primarySourceChecked=!malware||result.warnings.every(record=>sample.evidence_urls.includes(record.payload.reference_url)&&record.payload.evidence.some(line=>line.includes(sample.evidence_hash.value)));
  const passed=result.status==='available'&&result.passport.status==='exact_match'&&result.warnings.length===expectedWarnings&&identityChecked&&keysChecked&&primarySourceChecked;
  results.push({sample:sample.id,classification:sample.classification,passed,passport:result.passport.status,warning_count:result.warnings.length,expected_warning_count:expectedWarnings,readonly_identity_checked:identityChecked,evidence_keys_checked:keysChecked,primary_source_checked:primarySourceChecked,entity_keys:resolved.map(record=>record.key)});
  console.log(JSON.stringify(results.at(-1)));
 }
 const read=await listPublicRecords();
 const expectedRecordCount=evaluation.samples.reduce((count:number,sample:any)=>count+(['intentionally-insecure-training-app','documented-malware-sample'].includes(sample.classification)?2:1),0);
 const feedChecked=read.records.length===expectedRecordCount&&evidence.records.every((entry:any)=>read.records.some(record=>record.key===entry.entity_key));

 // Optional operator audit of individual entities uses a private header key,
 // rather than sending credentials through the public read-only gateway.
 let directEntityCheck:'not_requested'|'passed'|'failed'='not_requested';
 const keyFile=process.env.SCAMSIGNAL_ARKIV_KEY_FILE;
 if(keyFile){
  const root=await fs.realpath(process.cwd());
  const resolved=await fs.realpath(keyFile);
  const relative=path.relative(root,resolved);
  if(relative===''||(!relative.startsWith('..'+path.sep)&&!path.isAbsolute(relative)))throw new Error('Operator credentials must stay outside the repository.');
  const accessKey=(await fs.readFile(resolved,'utf8')).trim();
  if(!accessKey||/[\r\n]/.test(accessKey))throw new Error('The operator RPC key file is invalid.');
  const client=createPublicClient({chain:tiramisu,transport:http(RPC_URL,{timeout:18000,retryCount:0,fetchOptions:{headers:{'X-API-KEY':accessKey}}})});
  const timing=await client.getBlockTiming();
  directEntityCheck='passed';
  for(const entry of evidence.records){
   const record=decodePublicRecord(await client.getEntity(entry.entity_key),timing);
   if(!record||record.key!==entry.entity_key||record.apk_sha256!==entry.apk_sha256||record.package_name!==entry.package_name||record.creator.toLowerCase()!==entry.creator.toLowerCase())directEntityCheck='failed';
  }
 }
 const output={verified_at:new Date().toISOString(),network:'Arkiv Tiramisu',read_rpc_url:readRpcUrl,live_query:read.query,read_block:read.block,verified_record_count:read.records.length,expected_record_count:expectedRecordCount,feed_checked:feedChecked,direct_entity_check:directEntityCheck,results,passed:results.every(result=>result.passed)&&feedChecked&&directEntityCheck!=='failed'};
 await fs.mkdir('arkiv',{recursive:true});
 await fs.writeFile('arkiv/verification.json',JSON.stringify(output,null,2)+'\n');
 console.log(JSON.stringify({status:output.passed?'passed':'failed',sample_count:results.length,record_count:read.records.length}));
 if(!output.passed)process.exitCode=1;
}
main().catch(error=>{
 // Transport exceptions can contain request headers. Print no exception body.
 console.error(JSON.stringify({status:'failed',error_type:error instanceof Error?error.name:'UnknownError'}));
 process.exitCode=1;
});

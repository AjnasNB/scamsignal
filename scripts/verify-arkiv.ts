import fs from 'node:fs/promises';
import {configureArkiv,resolveReport,listPublicRecords} from '../packages/arkiv-client/src/index';
configureArkiv(JSON.parse(await fs.readFile('apps/web/public/data/trust-policy.json','utf8')));
const evaluation=JSON.parse(await fs.readFile('scanner/evaluation.json','utf8'));
const results=[];
for(const sample of evaluation.samples){
 const result=await resolveReport(sample.report);
 const expectedWarnings=sample.classification==='intentionally-insecure-training-app'?1:0;
 const passed=result.status==='available'&&result.passport.status==='exact_match'&&result.warnings.length===expectedWarnings;
 results.push({sample:sample.id,passed,passport:result.passport.status,warning_count:result.warnings.length,entity_keys:[...result.passport.records,...result.warnings].map(r=>r.key)});
 console.log(JSON.stringify(results.at(-1)));
}
const read=await listPublicRecords();
const output={verified_at:new Date().toISOString(),network:'Arkiv Tiramisu',live_query:read.query,read_block:read.block,results,passed:results.every(r=>r.passed)};
await fs.mkdir('arkiv',{recursive:true});
await fs.writeFile('arkiv/verification.json',JSON.stringify(output,null,2)+'\n');
if(!output.passed)process.exitCode=1;

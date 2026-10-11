import fs from 'node:fs/promises';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {privateKeyToAccount} from 'viem/accounts';
import {http, parseEther, sha256, stringToHex, type Hex} from 'viem';
import {createPublicClient, createWalletClient, ExpirationTime, jsonToPayload} from '@arkiv-network/sdk';
import {addr, str, u64, bytes32} from '@arkiv-network/sdk/attr';
import {eq} from '@arkiv-network/sdk/query';
import {tiramisu} from '@arkiv-network/sdk/chains';
import {APP_ID, RPC_URL, buildEntityInput, configureArkiv, decodePublicRecord, resolveRecords, type PublishInput} from '../packages/arkiv-client/src/index';

// Operator verification only. The explicit wallet file must remain outside this checkout.
// Fixtures contain fictional package names and synthetic hashes, never actual uploaded APKs.
async function main() {
  const walletFile = process.env.SCAMSIGNAL_WALLET_FILE;
  if (!walletFile) throw new Error('SCAMSIGNAL_WALLET_FILE is required.');
  const root = await fs.realpath(process.cwd());
  const walletPath = await fs.realpath(walletFile);
  const relative = path.relative(root, walletPath);
  if (relative === '' || (!relative.startsWith('..' + path.sep) && !path.isAbsolute(relative))) {
    throw new Error('Wallet files must stay outside the repository.');
  }
  const wallets = JSON.parse(await fs.readFile(walletPath, 'utf8'));
  const role = (name: string) => {
    const entry = wallets.find((item: any) => item.role === name);
    if (!entry || !/^0x[0-9a-fA-F]{64}$/.test(entry.private_key)) throw new Error('Required wallet role is unavailable.');
    return privateKeyToAccount(entry.private_key as Hex);
  };
  const reviewer = role('reviewer');
  const observer = role('observer');
  const policy = JSON.parse(await fs.readFile('apps/web/public/data/trust-policy.json', 'utf8'));
  configureArkiv({...policy, rpc_url: process.env.SCAMSIGNAL_READ_RPC_URL || policy.rpc_url});
  let accessKey: string | undefined;
  if (process.env.SCAMSIGNAL_ARKIV_KEY_FILE) {
    const accessPath = await fs.realpath(process.env.SCAMSIGNAL_ARKIV_KEY_FILE);
    const accessRelative = path.relative(root, accessPath);
    if (accessRelative === '' || (!accessRelative.startsWith('..' + path.sep) && !path.isAbsolute(accessRelative))) throw new Error('RPC key files must stay outside the repository.');
    accessKey = (await fs.readFile(accessPath, 'utf8')).trim();
    if (!accessKey || /[\r\n]/.test(accessKey)) throw new Error('Operator RPC key file is invalid.');
  }
  const operatorTransport = () => http(RPC_URL, {timeout: 18000, retryCount: 0, ...(accessKey ? {fetchOptions: {headers: {'X-API-KEY': accessKey}}} : {})});
  if (!policy.trusted_creators.some((value: string) => value.toLowerCase() === reviewer.address.toLowerCase())) throw new Error('Reviewer policy does not approve the signing wallet.');
  if (policy.trusted_creators.some((value: string) => value.toLowerCase() === observer.address.toLowerCase())) throw new Error('Observer must be outside the accepted reviewer policy.');
  const publicClient = createPublicClient({chain: tiramisu, transport: operatorTransport()});
  const reviewerClient = createWalletClient({chain: tiramisu, account: reviewer, transport: operatorTransport()});
  const observerClient = createWalletClient({chain: tiramisu, account: observer, transport: operatorTransport()});
  const run = randomUUID();
  const output: any = {
    schema_version: 1, network: 'Arkiv Tiramisu', chain_id: tiramisu.id, started_at: new Date().toISOString(),
    reviewer_wallet: reviewer.address, observer_wallet: observer.address,
    data_notice: 'Synthetic protocol fixtures only. Hashes do not identify real APKs or personal data. No production records were changed.',
    fixtures: [], checks: {}, transfers: [],
  };
  await fs.mkdir('arkiv', {recursive: true});
  const save = () => fs.writeFile('arkiv/protocol-verification.json', JSON.stringify(output, null, 2) + '\n');
  await save();
  const receiptEntry = (label: string, result: any) => ({label, entity_key: result.entityKey, tx_hash: result.txHash,
    tx_url: `https://tiramisu.explorer.arkiv.network/tx/${result.txHash}`, requested_expiry_block: String(result.expiresAt)});
  const expect = (condition: unknown, message: string) => { if (!condition) throw new Error(message); };

  const expiring = await reviewerClient.createEntity({
    attributes: {app_id: str('scamsignal-fixtures-v1'), schema_version: u64(1), kind: str('expiry-test'), run: str(run)},
    payload: jsonToPayload({synthetic: true, purpose: 'Live expiry verification only', run}), contentType: 'application/json',
    expires: ExpirationTime.fromSeconds(30), flags: {readonly: true, permissionlessExtension: false},
  });
  const liveExpiry = await publicClient.getEntity(expiring.entityKey);
  expect(liveExpiry.creator.toLowerCase() === reviewer.address.toLowerCase(), 'Expiry creator differs.');
  const expiry = {...receiptEntry('short-lived-expiry', expiring), app_id: 'scamsignal-fixtures-v1', creator: liveExpiry.creator,
    created_at_block: String(liveExpiry.createdAt), expires_at_block: String(liveExpiry.expiresAt), live_read_at: new Date().toISOString()};
  output.fixtures.push(expiry);
  output.checks.expiry_live_before_deadline = true;
  await save();
  console.log(JSON.stringify({step: 'expiry-created-and-read', key: expiring.entityKey, expires_at_block: String(liveExpiry.expiresAt)}));

  if (await publicClient.getBalance({address: observer.address}) < parseEther('0.001')) {
    const transfer = await reviewerClient.sendTransaction({to: observer.address, value: parseEther('0.02'), type: 'legacy'});
    const receipt = await publicClient.waitForTransactionReceipt({hash: transfer});
    expect(receipt.status === 'success', 'Test-token transfer failed.');
    output.transfers.push({tx_hash: transfer, from: reviewer.address, to: observer.address, amount_test_glm: '0.02', tx_url: `https://tiramisu.explorer.arkiv.network/tx/${transfer}`});
    await save();
  }
  const syntheticHash = (purpose: string) => sha256(stringToHex(`ScamSignal synthetic protocol fixture ${run} ${purpose}`)).slice(2);
  const forgedHash = syntheticHash('unapproved-author');
  const forgedInput: PublishInput = {
    kind: 'advisory', apk_sha256: forgedHash, package_name: 'dev.scamsignal.synthetic.creator', display_name: 'Synthetic author check',
    title: 'ScamSignal evaluation reviewer — synthetic spoof fixture',
    summary: 'This intentionally approved-looking title is a protocol-author test. The actual creating wallet is unapproved. It is not a warning about a real APK.',
    evidence: ['Synthetic fixture; authorship must come from protocol creator metadata.'], severity: 'info', classification: 'synthetic_demo',
    reference_url: 'https://example.com/scamsignal/synthetic-protocol-fixture', expires_days: 1,
  };
  const forged = await observerClient.createEntity(await buildEntityInput(forgedInput));
  const forgedEntity = await publicClient.getEntity(forged.entityKey);
  const forgedTiming = await publicClient.getBlockTiming();
  const decodedForged = decodePublicRecord(forgedEntity, forgedTiming);
  expect(forgedEntity.creator.toLowerCase() === observer.address.toLowerCase(), 'Protocol did not expose observer creator.');
  expect(decodedForged === null, 'Unapproved creator was accepted.');
  const approvedQuery = publicClient.select().where(eq('app_id', str(APP_ID)), eq('apk_sha256', bytes32(`0x${forgedHash}`)), eq('$creator', addr(reviewer.address)));
  const filtered = await approvedQuery.fetch();
  expect(filtered.entities.length === 0, 'Approved-creator query leaked unapproved entity.');
  output.fixtures.push({...receiptEntry('unapproved-author', forged), app_id: APP_ID, creator: forgedEntity.creator, apk_sha256: forgedHash, package_name: forgedInput.package_name, expires_at_block: String(forgedEntity.expiresAt)});
  output.checks.unapproved_creator_decoder_rejected = true;
  output.checks.approved_creator_query_excluded_forgery = true;
  output.checks.approved_creator_query = approvedQuery.toString();
  await save();
  console.log(JSON.stringify({step: 'creator-forgery-rejected', key: forged.entityKey, creator: forgedEntity.creator}));

  const correctedHash = syntheticHash('authorized-retraction');
  const advisoryInput: PublishInput = {...forgedInput, apk_sha256: correctedHash, package_name: 'dev.scamsignal.synthetic.correction',
    display_name: 'Synthetic retraction check', title: 'Synthetic advisory for protocol verification',
    summary: 'Fictional protocol test. This hash does not identify any real application. The original reviewer retracts it in the following record.'};
  const advisoryBuild = await buildEntityInput(advisoryInput);
  const advisory = await reviewerClient.createEntity({...advisoryBuild, expires: ExpirationTime.fromSeconds(120)});
  const advisoryEntity = await publicClient.getEntity(advisory.entityKey);
  output.fixtures.push({...receiptEntry('synthetic-advisory', advisory), app_id: APP_ID, creator: advisoryEntity.creator,
    apk_sha256: correctedHash, package_name: advisoryInput.package_name, expires_at_block: String(advisoryEntity.expiresAt)});
  await save();
  const correctionInput: PublishInput = {...advisoryInput, kind: 'correction', target_key: advisory.entityKey, action: 'retract',
    title: 'Synthetic advisory retracted by original reviewer', summary: 'The original reviewer retracts this fictional protocol-test advisory. No real APK is affected.'};
  const correctionBuild = await buildEntityInput(correctionInput);
  const correction = await reviewerClient.createEntity({...correctionBuild, expires: ExpirationTime.fromSeconds(180)});
  const correctionEntity = await publicClient.getEntity(correction.entityKey);
  const correctedTiming = await publicClient.getBlockTiming();
  const advisoryRecord = decodePublicRecord(advisoryEntity, correctedTiming);
  const correctionRecord = decodePublicRecord(correctionEntity, correctedTiming);
  expect(advisoryRecord && correctionRecord, 'Approved synthetic records failed decoding.');
  expect(correctionEntity.expiresAt >= advisoryEntity.expiresAt, 'Correction does not cover advisory lifetime.');
  const report = {apk_sha256: correctedHash, package_name: advisoryInput.package_name, signature: {status: 'unavailable' as const, signer_sha256: []}};
  const before = resolveRecords(report, [advisoryRecord!]);
  const after = resolveRecords(report, [advisoryRecord!, correctionRecord!]);
  expect(before.warnings.length === 1 && after.warnings.length === 0, 'Authorized live correction did not suppress advisory.');
  output.fixtures.push({...receiptEntry('synthetic-authorized-retraction', correction), app_id: APP_ID, creator: correctionEntity.creator,
    target_entity_key: advisory.entityKey, apk_sha256: correctedHash, package_name: correctionInput.package_name, expires_at_block: String(correctionEntity.expiresAt)});
  output.checks.original_creator_authorized_retraction = true;
  output.checks.correction_lifetime_covers_target = true;
  output.checks.warning_count_before_retraction = before.warnings.length;
  output.checks.warning_count_after_retraction = after.warnings.length;
  await save();
  console.log(JSON.stringify({step: 'authorized-retraction-verified', advisory_key: advisory.entityKey, correction_key: correction.entityKey}));

  const deadline = Date.now() + 120000;
  let expiryAbsent = false;
  let lastBlock = 0n;
  while (Date.now() < deadline) {
    const timing = await publicClient.getBlockTiming();
    lastBlock = timing.currentBlock;
    if (timing.currentBlock >= liveExpiry.expiresAt) {
      try { await publicClient.getEntity(expiring.entityKey); }
      catch (error) {
        if (error instanceof Error && error.name === 'NoEntityFoundError') {
          expiryAbsent = true;
          break;
        }
        throw error;
      }
    }
    await new Promise(resolve => setTimeout(resolve, 4000));
  }
  expect(expiryAbsent, 'Expired fixture remained live or expiry observation timed out.');
  output.checks.expired_entity_getEntity_throws = true;
  output.checks.expiry_error_type = 'NoEntityFoundError';
  output.checks.expiry_observed_block = String(lastBlock);
  output.completed_at = new Date().toISOString();
  output.status = 'passed';
  await save();
  console.log(JSON.stringify({status: 'passed', checks: output.checks, evidence_file: 'arkiv/protocol-verification.json'}));
}

main().catch(async (error) => {
  // Never dump account objects, wallet contents, or signing/RPC exception details.
  console.error(JSON.stringify({status: 'failed', error_type: error instanceof Error ? error.name : 'UnknownError'}));
  process.exitCode = 1;
});

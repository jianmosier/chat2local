import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { VERSION } from '../src/shared/protocol.mjs';
import { packageEntries } from './archive.mjs';
import { buildPublic, publicDocuments } from './build-public.mjs';
import { checkSource } from './check-source.mjs';
import { buildReleaseInstallers, verifyReleaseInstaller, releaseAssetFiles, RELEASE_TARGETS } from './release-artifacts.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
export function publicationCloneArgs(branch, source, destination) {
  // Set checkout policy BEFORE the first checkout. Windows system Git config
  // may otherwise rewrite LF bytes and invalidate the source SHA-256 manifest.
  // Clone-local settings leave the owner's system/global Git config unchanged.
  return ['clone','--config','core.autocrlf=false','--config','core.eol=lf','--single-branch','--branch',branch,source,destination];
}
export function releaseOptions(args) {
  const value = { publish: false, create: false };
  for (let i=0;i<args.length;i++) {
    const arg=args[i];
    if (arg==='--publish') value.publish=true;
    else if (arg==='--create-repo') value.create=true;
    else if (arg==='--repo' && args[i+1]) value.repo=args[++i];
    else if (arg==='--from' && args[i+1]) value.from=args[++i];
    else if (arg==='--help') value.help=true;
    else throw Error('Usage: npm run release -- [--publish] [--repo OWNER/REPO] [--create-repo] [--from VERIFIED_REPORT]');
  }
  if (value.repo && (!/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(value.repo) || ['.','..'].includes(value.repo.split('/')[1]))) throw Error('Invalid repository name.');
  if (value.create && !value.publish) throw Error('--create-repo requires --publish.');
  return value;
}
export function validateRepository(repo, user, metadata, create) {
  if (repo.split('/')[0] !== user.login) throw Error('Release target must belong to the authenticated owner; no other account is selected.');
  if (!metadata && !create) throw Error('Repository was not found. Use --create-repo explicitly to create this exact public target.');
  if (metadata && (metadata.full_name !== repo || metadata.archived || metadata.visibility !== 'public' || metadata.permissions?.push !== true)) throw Error('Target is not a writable public repository. No visibility or permission was changed.');
}
export async function inputFingerprint(directory = root) {
  const fixed=['package.json','package-lock.json','README.md','SECURITY.md','install.sh','install.ps1','wrangler.jsonc','.gitignore',...publicDocuments];
  const names=[...fixed]; for(const sub of ['src','scripts','tests']) names.push(...await packageEntries(path.join(directory,sub),sub+'/'));
  const hash=createHash('sha256'); for(const name of names.sort()) {hash.update(name+'\0');hash.update(await fs.readFile(path.join(directory,name)));} return hash.digest('hex');
}
export async function syncSnapshot(source, destination, previousManifest) {
  const current=JSON.parse(await fs.readFile(path.join(source,'SOURCE-SHA256.json'),'utf8'));
  const previous=previousManifest?.files || {};
  for(const name of Object.keys(previous)) {
    if (!/^[A-Za-z0-9_.\-/]+$/.test(name) || name.startsWith('/') || name.split('/').some(p=>p==='..'||!p)) throw Error('Unsafe previous publication manifest.');
    if (!Object.hasOwn(current.files,name)) await fs.unlink(path.join(destination,name)).catch(error=>{if(error.code!=='ENOENT')throw error;});
  }
  for(const name of [...Object.keys(current.files),'SOURCE-SHA256.json']) {
    const file=path.join(destination,name);
    let cursor=destination;
    for(const part of name.split('/')) {cursor=path.join(cursor,part);try{if((await fs.lstat(cursor)).isSymbolicLink())throw Error('Publish target contains a link.');}catch(error){if(error.code!=='ENOENT')throw error;}}
    try { const stat=await fs.lstat(file); if(stat.nlink!==1||!stat.isFile())throw Error('Unsafe target file.'); if(name!=='SOURCE-SHA256.json' && !Object.hasOwn(previous,name))throw Error('Unmanaged target file would be overwritten: '+name); } catch(error){if(error.code!=='ENOENT')throw error;}
    await fs.mkdir(path.dirname(file),{recursive:true}); await fs.copyFile(path.join(source,name),file);
  }
  return current;
}
async function run(file,args,{cwd=root,env={},visible=false,missing404=false,timeout=290000}={}) {
  return new Promise((resolve,reject)=>{
    const child=spawn(file,args,{cwd,windowsHide:true,env:{...process.env,...env,GH_PROMPT_DISABLED:'1',GIT_TERMINAL_PROMPT:'0'},stdio:visible?'inherit':['ignore','pipe','pipe']});
    let output='',error='',expired=false;
    if(!visible){child.stdout.on('data',b=>{output+=b;if(output.length>8*1024*1024)child.kill();});child.stderr.on('data',b=>{error+=b;if(error.length>1024*1024)error=error.slice(-1024*1024);});}
    const timer=setTimeout(()=>{expired=true;child.kill();},timeout);
    child.once('error',failure=>{clearTimeout(timer);reject(failure);});
    child.once('close',code=>{clearTimeout(timer);if(code===0&&!expired)resolve(output.trim());else if(missing404 && /HTTP 404/.test(error))resolve(null);else reject(Error(expired?'Release subprocess timed out; inspect stage before retrying.':`${file} ${args[0]} failed: ${error.slice(-1500)}`));});
  });
}
async function verifyReport(file) {
  const report=JSON.parse(await fs.readFile(file,'utf8'));
  if(report.version!==VERSION||report.testsPassed!==true||report.inputFingerprint!==await inputFingerprint()||report.includesPersonalConfig!==false||report.includesPrivateHandoff!==false)throw Error('Release report is stale, untested, or not sanitized. Re-run npm run release.');
  await checkSource(report.directory,path.join(report.directory,'SOURCE-SHA256.json'));
  if(sha(await fs.readFile(report.archive))!==report.sha256)throw Error('Release archive changed.');
  const sidecar=(await fs.readFile(report.archive+'.sha256','utf8')).trim().split(/\s+/);
  if(sidecar[0]!==report.sha256||sidecar[1]!==path.basename(report.archive))throw Error('Release checksum sidecar changed.');
  if (!Array.isArray(report.installers) || report.installers.length !== RELEASE_TARGETS.length || RELEASE_TARGETS.some(t => !report.installers.some(r => r.target === t))) throw Error('Required Windows/Mac installer set is incomplete.');
  for (const installer of report.installers) await verifyReleaseInstaller(installer, report.directory);
  return report;
}
export async function prepareRelease() {
  const pkg=JSON.parse(await fs.readFile(path.join(root,'package.json'),'utf8')),lock=JSON.parse(await fs.readFile(path.join(root,'package-lock.json'),'utf8'));
  if(pkg.version!==VERSION||lock.version!==VERSION||lock.packages[''].version!==VERSION)throw Error('Package/protocol/lock versions disagree.');
  for(const file of ['install.sh','install.ps1'])if(!(await fs.readFile(path.join(root,file),'utf8')).includes(`'${VERSION}'`))throw Error('Bootstrap version does not match '+VERSION);
  const input=await inputFingerprint();
  console.log('Release 1/4: syntax and full regression checks. No GitHub writes.');
  await run(process.execPath,['scripts/check.mjs'],{visible:true});
  for(let group=1;group<=3;group++)await run(process.execPath,['scripts/test-batch.mjs',String(group)],{visible:true,timeout:650000});
  if(await inputFingerprint()!==input)throw Error('Source changed during verification; no release was prepared.');
  console.log('Release 2/4: export only the sanitized source allowlist and verify its manifest.');
  const output=path.join(root,'.artifacts','releases',VERSION+'-'+Date.now());
  const report=await buildPublic(output);
  report.installers = await buildReleaseInstallers(report.directory);
  if (await inputFingerprint() !== input) throw Error('Source changed during installer build; no release was prepared.');
  report.testsPassed=true;report.inputFingerprint=input;report.preparedAt=new Date().toISOString();
  const file=path.join(output,'publication-report.json');await fs.writeFile(file,JSON.stringify(report,null,2));
  await verifyReport(file); console.log('Prepared report: '+file);return {file,report};
}
export async function publishRelease(file,options) {
  const report=await verifyReport(file);
  const user=JSON.parse(await run('gh',['api','user','--jq','{login:.login,id:.id}']));
  if(!/^[A-Za-z0-9-]+$/.test(user.login)||!Number.isInteger(user.id))throw Error('GitHub identity was not verified.');
  const repo=options.repo||user.login+'/chat2local',tag='v'+VERSION;
  const raw=await run('gh',['api','repos/'+repo],{missing404:true}),metadata=raw?JSON.parse(raw):null;
  validateRepository(repo,user,metadata,options.create);
  if(await run('gh',['api',`repos/${repo}/releases/tags/${tag}`],{missing404:true}))throw Error('This release tag already exists. Increment the version; assets are never clobbered.');
  const work=path.join(path.dirname(file),'git-publication');
  try{await fs.lstat(work);throw Error('Publication worktree already exists. Inspect its stage before resuming; it will not be deleted.');}catch(error){if(error.code!=='ENOENT')throw error;}
  console.log('Release 3/4: update the verified public source tree without force-push.');
  const identity={GIT_AUTHOR_NAME:user.login,GIT_COMMITTER_NAME:user.login,GIT_AUTHOR_EMAIL:`${user.id}+${user.login}@users.noreply.github.com`,GIT_COMMITTER_EMAIL:`${user.id}+${user.login}@users.noreply.github.com`};
  const hooks=path.join(path.dirname(file),'empty-hooks');await fs.mkdir(hooks);
  const git=(args)=>run('git',['-c','core.hooksPath='+hooks,'-c','credential.helper=','-c','credential.helper=!gh auth git-credential',...args],{cwd:work,env:identity});
  let branch=metadata?.default_branch||'main',previous=null;
  const branchHead=metadata?await run('gh',['api',`repos/${repo}/git/ref/heads/${branch}`],{missing404:true}):null;
  if(branchHead){
    await run('git',['-c','core.hooksPath='+hooks,...publicationCloneArgs(branch,`https://github.com/${repo}.git`,work)]);
    try{previous=JSON.parse(await fs.readFile(path.join(work,'SOURCE-SHA256.json'),'utf8'));}catch{throw Error('Existing repository is not a managed chat2local release. Inspect history before adopting it.');}
    if(previous.product!=='chat2local-source')throw Error('Existing repository identity differs.');
    await checkSource(work,path.join(work,'SOURCE-SHA256.json')); // Refuse unreviewed upstream edits.
  }else{await fs.mkdir(work);await git(['init','-b',branch]);}
  await syncSnapshot(report.directory,work,previous);
  await checkSource(work,path.join(report.directory,'SOURCE-SHA256.json'));
  await git(['config','core.autocrlf','false']);await git(['add','--all']);
  await git(['-c','commit.gpgsign=false','commit','-m',`Release ${VERSION}: polling isolation, privacy checks and structured documentation`]);
  const commit=await git(['rev-parse','HEAD']);if(!/^[a-f0-9]{40}$/.test(commit))throw Error('Commit was not verified.');
  if(!metadata)await run('gh',['repo','create',repo,'--public','--description','Self-hosted multi-device MCP access with explicit folder and terminal permissions.']);
  if(!branchHead)await git(['remote','add','origin',`https://github.com/${repo}.git`]);
  await git(['push','--set-upstream','origin',branch]);
  const remote=await run('gh',['api',`repos/${repo}/git/ref/heads/${branch}`,'--jq','.object.sha']);
  if(remote!==commit)throw Error('Remote changed or push was not confirmed; no release created.');
  console.log('Release 4/4: upload draft assets, download them back, then publish.');
  const notes=`Alpha preview ${VERSION}. Includes request-budget v2: authenticated device polling is isolated from anonymous setup and authorization. Removes owner-specific literals from public privacy rules, adds read-only public-tree/history audits, and synchronizes structured installation, pairing, reconnection, architecture, permissions and upgrade documentation, including the bundled help page. Matching source, Windows x64, macOS ARM64 and x64 packages; all downloaded assets are verified before publication. No DevSpace runtime dependency or permission expansion. Existing historical references/assets are not rewritten. Cloud deployment and each client's installed version require separate checks. Physical Mac update, full-machine reboot, clean-account setup and independent security review remain separate acceptance items.`;
  const assetFiles = releaseAssetFiles(report);
  await run('gh',['release','create',tag,...assetFiles,'--repo',repo,'--target',commit,'--draft','--prerelease','--title','chat2local '+VERSION,'--notes',notes]);
  const verify=path.join(path.dirname(file),'remote-assets');await fs.mkdir(verify);
  await run('gh',['release','download',tag,'--repo',repo,'--dir',verify]);
  if(sha(await fs.readFile(path.join(verify,path.basename(report.archive))))!==report.sha256)throw Error('Uploaded archive does not match; release remains a draft.');
  if(!Buffer.from(await fs.readFile(path.join(verify,path.basename(report.archive)+'.sha256'))).equals(await fs.readFile(report.archive+'.sha256')))throw Error('Uploaded checksum differs; release remains a draft.');
  for (const file of assetFiles) {
    if (sha(await fs.readFile(path.join(verify, path.basename(file)))) !== sha(await fs.readFile(file))) throw Error('Uploaded release asset differs; release remains a draft: ' + path.basename(file));
  }
  await run('gh',['release','edit',tag,'--repo',repo,'--draft=false','--prerelease']);
  const release=JSON.parse(await run('gh',['api',`repos/${repo}/releases/tags/${tag}`]));
  if(release.draft||!release.prerelease||release.assets.length!==assetFiles.length)throw Error('Publication state or complete artifact set was not confirmed.');
  const result={repository:repo,commit,tag,url:release.html_url,sourceSha256:report.sha256,assets:release.assets.map(a=>({name:a.name,size:a.size})),published:true,prerelease:true};
  await fs.writeFile(path.join(path.dirname(file),'published.json'),JSON.stringify(result,null,2));console.log(JSON.stringify(result,null,2));return result;
}
export async function release(args=process.argv.slice(2)) {
  const options=releaseOptions(args);
  if(options.help){console.log('npm run release prepares a tested, sanitized source snapshot. Add --publish to update GitHub; --create-repo explicitly permits first creation. --from VERIFIED_REPORT resumes publication only when source/tests/hashes still match. No force-push, existing tag overwrite, cloud deployment, credentials in output, or local permission changes.');return;}
  const file=options.from?path.resolve(options.from):(await prepareRelease()).file;
  if(options.publish)return publishRelease(file,options);
  const report=await verifyReport(file);console.log(JSON.stringify({report:file,version:report.version,sha256:report.sha256,published:false},null,2));
}
if(import.meta.main)release().catch(error=>{console.error(error.message);process.exitCode=1;});

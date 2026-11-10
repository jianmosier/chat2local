import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { VERSION } from '../src/shared/protocol.mjs';
import { packageEntries } from './archive.mjs';
import { buildPublic, publicDocuments, rustSourceFiles } from './build-public.mjs';
import { checkSource } from './check-source.mjs';
import { buildReleaseInstallers, verifyReleaseInstaller, releaseAssetFiles, RELEASE_TARGETS } from './release-artifacts.mjs';
import { readNativeAgentArtifact } from './native-agent-artifact.mjs';
import { TEST_GROUPS } from './test-groups.mjs';

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
    else if (arg==='--commit' && args[i+1]) value.commit=args[++i];
    else if (arg==='--help') value.help=true;
    else throw Error('Usage: npm run release -- [--publish] [--repo OWNER/REPO] [--commit REVIEWED_SHA] [--from VERIFIED_REPORT]');
  }
  if (value.repo && (!/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(value.repo) || ['.','..'].includes(value.repo.split('/')[1]))) throw Error('Invalid repository name.');
  if (value.create && !value.publish) throw Error('--create-repo requires --publish.');
  if (value.commit && !/^[a-f0-9]{40}$/.test(value.commit)) throw Error('An exact reviewed source commit is required.');
  return value;
}
export function validateRepository(repo, user, metadata, create) {
  if (repo.split('/')[0] !== user.login) throw Error('Release target must belong to the authenticated owner; no other account is selected.');
  if (!metadata && !create) throw Error('Repository was not found. Use --create-repo explicitly to create this exact public target.');
  if (metadata && (metadata.full_name !== repo || metadata.archived || metadata.visibility !== 'public' || metadata.permissions?.push !== true)) throw Error('Target is not a writable public repository. No visibility or permission was changed.');
}
export async function inputFingerprint(directory = root) {
  const fixed=['package.json','package-lock.json','install.sh','install.ps1','start-chat2local.cmd','start-chat2local.sh','LICENSE','tsconfig.json','wrangler.jsonc','.gitignore',...publicDocuments,...rustSourceFiles];
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
  const native = process.env.CHAT2LOCAL_NATIVE_AGENT_RELEASE_EXECUTABLE;
  if (!native) throw Error('Prepare the formal Windows native release first and set CHAT2LOCAL_NATIVE_AGENT_RELEASE_EXECUTABLE.');
  await readNativeAgentArtifact(native);
  const nativeTests = { CHAT2LOCAL_NATIVE_AGENT_TEST_REQUIRED: '1', CHAT2LOCAL_NATIVE_AGENT_TEST_EXECUTABLE: native };
  const pkg=JSON.parse(await fs.readFile(path.join(root,'package.json'),'utf8')),lock=JSON.parse(await fs.readFile(path.join(root,'package-lock.json'),'utf8'));
  if(pkg.version!==VERSION||lock.version!==VERSION||lock.packages[''].version!==VERSION)throw Error('Package/protocol/lock versions disagree.');
  for(const file of ['install.sh','install.ps1'])if(!(await fs.readFile(path.join(root,file),'utf8')).includes(`'${VERSION}'`))throw Error('Bootstrap version does not match '+VERSION);
  const input=await inputFingerprint();
  console.log('Release 1/4: syntax and full regression checks. No GitHub writes.');
  await run(process.execPath,['scripts/check.mjs'],{visible:true});
  for(let group=1;group<=TEST_GROUPS;group++)await run(process.execPath,['scripts/test-batch.mjs',String(group)],{visible:true,env:nativeTests,timeout:650000});
  if(await inputFingerprint()!==input)throw Error('Source changed during verification; no release was prepared.');
  console.log('Release 2/4: export only the sanitized source allowlist and verify its manifest.');
  const output=path.join(root,'.artifacts','releases',VERSION+'-'+Date.now());
  const report=await buildPublic(output);
  report.installers = await buildReleaseInstallers(report.directory);
  const windows = report.installers.find(item => item.target === 'win32-x64');
  await run(process.execPath, ['--test', '--test-concurrency=1', 'tests/windows-release-download.test.mjs'], { visible: true, env: { CHAT2LOCAL_RELEASE_PACKAGE_TEST_ARCHIVE: windows.archive }, timeout: 150000 });
  if (await inputFingerprint() !== input) throw Error('Source changed during installer build; no release was prepared.');
  report.testsPassed=true;report.inputFingerprint=input;report.preparedAt=new Date().toISOString();
  const file=path.join(output,'publication-report.json');await fs.writeFile(file,JSON.stringify(report,null,2));
  await verifyReport(file); console.log('Prepared report: '+file);return {file,report};
}
export async function verifyPublishedTree(tree, directory) {
  const source = JSON.parse(await fs.readFile(path.join(directory, 'SOURCE-SHA256.json'), 'utf8'));
  const names = [...Object.keys(source.files), 'SOURCE-SHA256.json'].sort();
  const entries = tree.tree.filter(item => item.type === 'blob');
  const parents = new Set(names.flatMap(name => { const parts = name.split('/'); return parts.slice(0, -1).map((_part, i) => parts.slice(0, i + 1).join('/')); }));
  if (tree.tree.some(item => !['blob', 'tree'].includes(item.type) || item.type === 'tree' && (item.mode !== '040000' || !parents.has(item.path)))) throw Error('Remote source contains an unsupported entry or unexpected directory.');
  if (tree.truncated || entries.map(item => item.path).sort().join('\n') !== names.join('\n')) throw Error('Remote source commit inventory differs from the reviewed snapshot.');
  for (const item of entries) {
    if (!['100644', '100755'].includes(item.mode)) throw Error('Remote source contains an unsafe file mode.');
    const bytes = await fs.readFile(path.join(directory, item.path));
    const digest = createHash('sha1').update(Buffer.from('blob ' + bytes.length + '\0')).update(bytes).digest('hex');
    if (digest !== item.sha) throw Error('Remote source commit differs from the tested snapshot: ' + item.path);
  }
}
export async function publishRelease(file, options) {
  // Publishing never stages files, pushes main, merges a PR, or rewrites history.
  const report = await verifyReport(file);
  if (options.create) throw Error('Create the repository separately; this publisher only accepts reviewed commits in an existing repository.');
  if (!/^[a-f0-9]{40}$/.test(options.commit || '')) throw Error('Publish requires --commit with the exact reviewed and pushed source commit.');
  const user = JSON.parse(await run('gh', ['api', 'user', '--jq', '{login:.login,id:.id}']));
  const repo = options.repo || user.login + '/chat2local', tag = 'v' + VERSION;
  const metadata = JSON.parse(await run('gh', ['api', 'repos/' + repo]));
  validateRepository(repo, user, metadata, false);
  if (await run('gh', ['api', `repos/${repo}/releases/tags/${tag}`], { missing404: true })) throw Error('Release already exists; no existing assets were overwritten.');
  if (await run('gh', ['api', `repos/${repo}/git/ref/tags/${tag}`], { missing404: true })) throw Error('Tag already exists; its ownership needs review before publication.');
  const tree = JSON.parse(await run('gh', ['api', `repos/${repo}/git/trees/${options.commit}?recursive=1`]));
  await verifyPublishedTree(tree, report.directory);
  const notes = [
    'Windows x64 installs the Rust Agent. Bundled Node supports installation and provisioning. The macOS packages use the Node Agent. The gateway uses JavaScript.',
    'Public source export rejects private files, backups and rotated records. Windows ZIP extraction bounds declared sizes and actual streamed bytes before promoting a verified package. The native panel reports permanent faults and blocked browser storage. Background publication pins the reviewed commit and requires remote-state inspection after a failure.',
    'Quit the old Agent normally before installing the update or selecting a retained verified native package for rollback. The installer preserves the current identity, permissions and data. If login startup is enabled, turn it off in the old panel before switching. Enable it again in the new panel if desired.',
    'The Windows binary and helper are bound to the reviewed source and use the Cargo release profile with OpenSSL 3.5.8. General enrollment, pairing codes, disconnect and unattended upgrade remain incomplete. macOS archives are verified on the build host. Physical Mac execution is outside this release validation.',
  ].join('\n\n');
  const assetFiles = releaseAssetFiles(report);
  console.log('Uploading a draft prerelease at the exact reviewed source commit.');
  await run('gh', ['release', 'create', tag, ...assetFiles, '--repo', repo, '--target', options.commit, '--draft', '--prerelease', '--title', 'chat2local ' + VERSION, '--notes', notes]);
  const verify = path.join(path.dirname(file), 'remote-assets'); await fs.mkdir(verify);
  await run('gh', ['release', 'download', tag, '--repo', repo, '--dir', verify]);
  for (const asset of assetFiles) if (sha(await fs.readFile(path.join(verify, path.basename(asset)))) !== sha(await fs.readFile(asset))) throw Error('Uploaded asset differs; Release remains draft: ' + path.basename(asset));
  await run('gh', ['release', 'edit', tag, '--repo', repo, '--draft=false', '--prerelease']);
  const release = JSON.parse(await run('gh', ['api', `repos/${repo}/releases/tags/${tag}`]));
  if (release.draft || !release.prerelease || release.assets.length !== assetFiles.length) throw Error('Release publication state unconfirmed.');
  const result = { repository: repo, commit: options.commit, tag, url: release.html_url, assets: release.assets.map(a => ({ name: a.name, size: a.size })), published: true, prerelease: true };
  await fs.writeFile(path.join(path.dirname(file), 'published.json'), JSON.stringify(result, null, 2)); console.log(JSON.stringify(result, null, 2)); return result;
}
export async function release(args=process.argv.slice(2)) {
  const options=releaseOptions(args);
  if(options.help){console.log('npm run release prepares a tested, sanitized source snapshot. Publish existing reviewed source with --publish --commit EXACT_SHA --repo OWNER/REPO. Repository creation and PR merge are separate operations. --from VERIFIED_REPORT resumes publication only when source/tests/hashes still match. No force-push, existing tag overwrite, cloud deployment, credentials in output, or local permission changes.');return;}
  const file=options.from?path.resolve(options.from):(await prepareRelease()).file;
  if(options.publish)return publishRelease(file,options);
  const report=await verifyReport(file);console.log(JSON.stringify({report:file,version:report.version,sha256:report.sha256,published:false},null,2));
}
if(import.meta.main)release().catch(error=>{console.error(error.message);process.exitCode=1;});

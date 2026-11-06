import { execFileSync } from 'node:child_process';
import { accessSync, constants, lstatSync, readFileSync, readdirSync, realpathSync, statfsSync, statSync } from 'node:fs';
import { posix, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { release } from 'node:os';

const cgroupRoot = '/sys/fs/cgroup';
const defaultNetworks = ['bridge', 'host', 'none'];
const maxChildren = 128;

function result(status, category) { return { status, category }; }
const pass = category => result('PASS', category);
const blocked = category => result('BLOCKED', category);
const unknown = category => result('UNKNOWN', category);

function observe(operation, unavailable) {
  try { return operation(); } catch { return unknown(unavailable); }
}

export function summarize(facts) {
  const checks = [
    ['hosted_linux_amd64', facts.host],
    ['docker_engine', facts.docker],
    ['docker_inspect_inventory', facts.inspect],
    ['cgroup_v2_mount', facts.mount],
    ['current_process_cgroup', facts.current],
    ['delegated_leaf_access', facts.leaf],
    ['private_workspace_prerequisites', facts.workspace],
    ['flock_binary', facts.flock],
    ['process_enroll_term_kill', unknown('UNVERIFIED_REQUIRES_INERT_PROCESS')],
    ['durable_journal_fsync_rename', unknown('UNVERIFIED_REQUIRES_WRITE_AND_RECOVERY')],
    ['flock_contention', unknown('UNVERIFIED_REQUIRES_LOCK_FIXTURE')],
    ['resource_ownership_cleanup', unknown('UNVERIFIED_REQUIRES_OWNED_FIXTURE')]
  ];
  const passive = checks.slice(0, 8);
  let route;
  if ([facts.mount, facts.current, facts.leaf].some(x => x.status === 'BLOCKED')) {
    route = blocked('GITHUB_HOSTED_ROUTE_NO_GO');
  } else if (passive.some(([, x]) => x.status === 'BLOCKED')) {
    route = blocked('PASSIVE_PREREQUISITE_BLOCKED');
  } else if (passive.some(([, x]) => x.status === 'UNKNOWN')) {
    route = unknown('PASSIVE_EVIDENCE_INCOMPLETE');
  } else {
    route = pass('FEASIBILITY_CANDIDATE');
  }
  return [...checks, ['route', route]].map(([capability, { status, category }]) => ({ capability, status, category }));
}

function writable(path, mode = constants.W_OK) {
  try { accessSync(path, mode); return true; } catch { return false; }
}

function cgroups() {
  let current = null;
  const mount = observe(() => {
    const rows = readFileSync('/proc/self/mountinfo', 'utf8').split('\n');
    const match = rows.map(row => row.split(' - ')).find(([left, right]) =>
      left.split(' ')[4] === cgroupRoot && right?.startsWith('cgroup2 '));
    if (!match || statfsSync(cgroupRoot).type !== 0x63677270) return blocked('CGROUP_V2_NOT_MOUNTED');
    if (match[0].split(' ')[5].split(',').includes('ro') || match[1].split(' ')[2].split(',').includes('ro'))
      return blocked('CGROUP_MOUNT_READ_ONLY');
    // Require an unambiguous mapping from proc membership to the visible mount.
    if (match[0].split(' ')[3] !== '/') return unknown('CGROUP_MOUNT_ROOT_UNVERIFIED');
    return pass('CGROUP_V2_RW_MOUNT');
  }, 'CGROUP_MOUNT_UNREADABLE');

  const currentFact = observe(() => {
    if (mount.status !== 'PASS') return unknown('CGROUP_MOUNT_PREREQUISITE_MISSING');
    const rows = readFileSync('/proc/self/cgroup', 'utf8').split('\n').filter(x => x.startsWith('0::'));
    if (rows.length !== 1) return unknown('PROCESS_CGROUP_UNVERIFIED');
    const member = rows[0].slice(3);
    if (!member.startsWith('/') || posix.normalize(member) !== member) return unknown('PROCESS_CGROUP_UNVERIFIED');
    const candidate = posix.resolve(cgroupRoot, '.' + member);
    if (realpathSync(candidate) !== candidate || !lstatSync(candidate).isDirectory())
      return unknown('PROCESS_CGROUP_UNVERIFIED');
    current = candidate;
    return pass('PROCESS_CGROUP_RESOLVED');
  }, 'PROCESS_CGROUP_UNREADABLE');

  const leaf = observe(() => {
    if (!current) return unknown('PROCESS_CGROUP_PREREQUISITE_MISSING');
    const entries = readdirSync(current, { withFileTypes: true }).filter(x => x.isDirectory());
    if (entries.length > maxChildren) return unknown('DELEGATION_SEARCH_LIMIT');
    let unreadable = false;
    for (const child of entries) {
      const path = posix.join(current, child.name);
      try {
        if (realpathSync(path) !== path || lstatSync(path).uid !== process.getuid()) continue;
        const contents = readdirSync(path, { withFileTypes: true });
        if (contents.some(x => x.isDirectory())) continue;
        const enroll = posix.join(path, 'cgroup.procs');
        const kill = posix.join(path, 'cgroup.kill');
        if (!contents.some(x => x.name === 'cgroup.kill') || !writable(enroll) || !writable(kill) ||
            !writable(posix.join(current, 'cgroup.procs'))) continue;
        if (readFileSync(enroll, 'utf8').trim() === '' &&
            /^populated 0$/m.test(readFileSync(posix.join(path, 'cgroup.events'), 'utf8')))
          return pass('EMPTY_OWNED_LEAF_ACCESS_INDICATED');
      } catch { unreadable = true; }
    }
    return unreadable ? unknown('DELEGATED_LEAF_INVENTORY_INCOMPLETE')
      : blocked('NO_SUITABLE_DELEGATED_CHILD_LEAF');
  }, 'DELEGATED_LEAF_INVENTORY_UNREADABLE');
  return { mount, current: currentFact, leaf };
}

function dockerFacts() {
  let run;
  const docker = observe(() => {
    if (process.env.DOCKER_HOST || process.env.DOCKER_CONTEXT) return blocked('DOCKER_OVERRIDE_PRESENT');
    const socket = '/var/run/docker.sock';
    let stat;
    try { stat = statSync(socket); }
    catch (error) { if (error.code === 'ENOENT') return blocked('DOCKER_SOCKET_MISSING'); throw error; }
    if (!stat.isSocket() || !writable(socket)) return blocked('DOCKER_SOCKET_ACCESS_DENIED');
    run = (...args) => execFileSync('/usr/bin/docker', ['--host', 'unix://' + socket, ...args],
      { encoding: 'utf8', timeout: 5000, maxBuffer: 65536, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    const engine = JSON.parse(run('info', '--format', '{{json .}}'));
    if (engine.OSType !== 'linux' || !['amd64', 'x86_64'].includes(engine.Architecture))
      return blocked('DOCKER_PLATFORM_MISMATCH');
    if (typeof engine.ID !== 'string' || !/^[a-zA-Z0-9:-]{8,100}$/.test(engine.ID) ||
        typeof engine.ServerVersion !== 'string' || !/^\d+\.\d+/.test(engine.ServerVersion))
      return unknown('DOCKER_SERVER_IDENTITY_UNVERIFIED');
    return pass('LOCAL_LINUX_AMD64_ENGINE');
  }, 'DOCKER_INFO_UNAVAILABLE');

  const inspect = observe(() => {
    if (docker.status !== 'PASS') return unknown('DOCKER_ENGINE_PREREQUISITE_MISSING');
    if (run('container', 'ls', '-aq') || run('volume', 'ls', '-q')) return blocked('ENGINE_NOT_EMPTY');
    const names = run('network', 'ls', '--format', '{{.Name}}').split('\n').sort();
    if (JSON.stringify(names) !== JSON.stringify(defaultNetworks)) return blocked('ENGINE_NETWORK_INVENTORY_UNEXPECTED');
    const id = run('network', 'inspect', 'bridge', '--format', '{{.Id}}');
    if (!/^[0-9a-f]{64}$/.test(id)) return unknown('DOCKER_INSPECT_IDENTITY_UNVERIFIED');
    return pass('BASELINE_INVENTORY_AND_INSPECT_OK');
  }, 'DOCKER_INVENTORY_OR_INSPECT_UNAVAILABLE');
  return { docker, inspect };
}

function hostFacts() {
  const host = process.platform === 'linux' && process.arch === 'x64' &&
    process.env.GITHUB_ACTIONS === 'true' && process.env.RUNNER_ENVIRONMENT === 'github-hosted' &&
    process.env.RUNNER_OS === 'Linux' && process.env.RUNNER_ARCH === 'X64' && /^\d+\.\d+/.test(release())
    ? pass('HOSTED_LINUX_AMD64_KERNEL_PRESENT') : blocked('HOSTED_LINUX_AMD64_UNVERIFIED');
  if (host.status !== 'PASS') {
    const skipped = unknown('HOST_PREREQUISITE_MISSING');
    return { host, docker: skipped, inspect: skipped, mount: skipped, current: skipped,
      leaf: skipped, workspace: skipped, flock: skipped };
  }
  const workspace = observe(() => {
    for (const input of [process.env.GITHUB_WORKSPACE, process.env.RUNNER_TEMP]) {
      if (!input || !posix.isAbsolute(input) || realpathSync(input) !== input)
        return blocked('WORKSPACE_PATH_UNVERIFIED');
      const stat = lstatSync(input);
      if (!stat.isDirectory() || stat.uid !== process.getuid() || !writable(input, constants.W_OK | constants.X_OK))
        return blocked('WORKSPACE_OWNERSHIP_OR_ACCESS_MISMATCH');
    }
    const type = statfsSync(process.env.RUNNER_TEMP).type;
    if (![0xef53, 0x58465342, 0x9123683e].includes(type >>> 0))
      return unknown('JOURNAL_FILESYSTEM_TYPE_UNVERIFIED');
    return pass('WORKSPACE_AND_TEMP_ACCESS_INDICATED');
  }, 'WORKSPACE_METADATA_UNREADABLE');
  const flock = observe(() => {
    execFileSync('/usr/bin/flock', ['--version'], { timeout: 5000, stdio: 'ignore' });
    return pass('FLOCK_BINARY_AVAILABLE');
  }, 'FLOCK_BINARY_UNAVAILABLE');
  return { host, ...dockerFacts(), ...cgroups(), workspace, flock };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const rows = summarize(hostFacts());
  for (const row of rows) console.log(JSON.stringify(row));
  process.exitCode = rows.at(-1).status === 'PASS' ? 0 : 1;
}

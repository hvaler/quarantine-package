// Task object lifecycle: reaper, prefix-scoped cleanup, leftover check and
// the detached watchdog that cleans up when the CLI is killed (C6, DEC-15).
'use strict';

const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { docker } = require('./docker');

// Every object the product creates is ar-<prefix>-<role>-<taskId> with one of these roles.
const ROLE_WORDS = ['download', 'sinkhole', 'sandbox', 'tracer', 'probe', 'ctlin', 'ctlout', 'net', 'ctlnet', 'vol'];

function alive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; }
}

async function listObjects(prefix, extraFilter = []) {
  const f = ['--filter', `label=qp.run-prefix=${prefix}`, ...extraFilter];
  const fmt = '{{.Names}}\t{{.Label "qp.task-id"}}\t{{.Label "qp.owner-pid"}}';
  const [c, n, v] = await Promise.all([
    docker(['ps', '-a', ...f, '--format', fmt]),
    docker(['network', 'ls', ...f, '--format', '{{.Name}}\t{{.Label "qp.task-id"}}\t{{.Label "qp.owner-pid"}}']),
    docker(['volume', 'ls', ...f, '--format', '{{.Name}}\t{{.Label "qp.task-id"}}\t{{.Label "qp.owner-pid"}}']),
  ]);
  const rows = (r, type) => r.stdout.split(/\r?\n/).filter(Boolean).map((l) => {
    const [name, task, owner] = l.split('\t');
    return { type, name, task, owner: Number(owner) };
  });
  // Name-based sweep too, in case a label was lost: ar-<prefix>-*
  const byName = await Promise.all([
    docker(['ps', '-a', '--filter', `name=^ar-${prefix}-`, '--format', '{{.Names}}']),
    docker(['network', 'ls', '--filter', `name=^ar-${prefix}-`, '--format', '{{.Name}}']),
    docker(['volume', 'ls', '--filter', `name=^ar-${prefix}-`, '--format', '{{.Name}}']),
  ]);
  const all = [...rows(c, 'container'), ...rows(n, 'network'), ...rows(v, 'volume')];
  const seen = new Set(all.map((o) => `${o.type}:${o.name}`));
  const own = new RegExp(`^ar-${prefix}-(${ROLE_WORDS.join('|')})-[a-f0-9]{10}$`);
  ['container', 'network', 'volume'].forEach((type, i) => {
    for (const name of byName[i].stdout.split(/\r?\n/).filter(Boolean)) {
      if (!own.test(name)) continue;
      if (!seen.has(`${type}:${name}`)) { all.push({ type, name, task: null, owner: NaN }); seen.add(`${type}:${name}`); }
    }
  });
  return all;
}

async function removeObjects(objs) {
  const containers = objs.filter((o) => o.type === 'container').map((o) => o.name);
  const networks = objs.filter((o) => o.type === 'network').map((o) => o.name);
  const volumes = objs.filter((o) => o.type === 'volume').map((o) => o.name);
  if (containers.length) await docker(['rm', '-f', '-v', ...containers], { timeoutMs: 60000 });
  if (networks.length) await docker(['network', 'rm', ...networks], { timeoutMs: 60000 });
  if (volumes.length) await docker(['volume', 'rm', '-f', ...volumes], { timeoutMs: 60000 });
  return { containers, networks, volumes };
}

async function removeTask(prefix, taskId) {
  let removed = { containers: [], networks: [], volumes: [] };
  for (let i = 0; i < 3; i++) {
    const objs = await listObjects(prefix, ['--filter', `label=qp.task-id=${taskId}`]);
    const named = (await listObjects(prefix)).filter((o) => o.name.endsWith(`-${taskId}`));
    const all = [...objs, ...named.filter((o) => !objs.some((x) => x.type === o.type && x.name === o.name))];
    if (!all.length) break;
    const r = await removeObjects(all);
    removed = {
      containers: [...new Set([...removed.containers, ...r.containers])],
      networks: [...new Set([...removed.networks, ...r.networks])],
      volumes: [...new Set([...removed.volumes, ...r.volumes])],
    };
  }
  return removed;
}

// Reap objects of this prefix whose owning CLI process is gone.
async function reapOrphans(prefix) {
  const objs = await listObjects(prefix);
  const orphans = objs.filter((o) => !alive(o.owner));
  if (!orphans.length) return { containers: [], networks: [], volumes: [] };
  return removeObjects(orphans);
}

async function cleanupAll(prefix) {
  const objs = await listObjects(prefix);
  return removeObjects(objs);
}

async function leftovers(prefix) {
  return listObjects(prefix);
}

function startWatchdog(ownerPid, prefix, taskId) {
  const r = spawnSync(process.execPath, [path.join(__dirname, 'watchdog-launch.js'), String(ownerPid), prefix, taskId], {
    encoding: 'utf8', windowsHide: true, timeout: 15000,
  });
  const pid = Number(String(r.stdout || '').trim());
  return { pid: Number.isInteger(pid) && pid > 0 ? pid : null };
}

module.exports = { listObjects, removeObjects, removeTask, reapOrphans, cleanupAll, leftovers, startWatchdog, alive };

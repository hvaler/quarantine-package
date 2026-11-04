// Task object lifecycle: per-task teardown, startup reaper, prefix-scoped
// cleanup, leftover check, and the detached watchdog that cleans up when the
// CLI is killed (C6, DEC-14, DEC-15, ruling on S1-D2).
//
// Scope rules:
// - teardown and the watchdog act only on objects of their own task
//   (label qp.task-id=<taskId>, or the exact name ar-<prefix>-<role>-<taskId>);
// - the startup reaper acts only on labelled objects of its prefix whose owner
//   CLI is gone, or that are older than the longest possible task (stale);
//   it never touches a live task of another CLI under the same prefix;
// - `cleanup` (explicit command) removes every object of the prefix.
'use strict';

const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { docker } = require('./docker');

// Every object the product creates is ar-<prefix>-<role>-<taskId> with one of these roles.
const ROLE_WORDS = ['download', 'sinkhole', 'sandbox', 'tracer', 'probe', 'ctlin', 'ctlout', 'net', 'ctlnet', 'vol', 'meta', 'stage'];
const ownName = (prefix, taskId = '[a-f0-9]{10}') => new RegExp(`^ar-${prefix}-(${ROLE_WORDS.join('|')})-${taskId}$`);

function alive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; }
}

// opts.taskId: only that task's objects. opts.nameSweep: also list unlabelled
// objects found by exact role-name pattern (restricted to opts.taskId when given).
async function listObjects(prefix, opts = {}) {
  const f = ['--filter', `label=qp.run-prefix=${prefix}`];
  if (opts.taskId) f.push('--filter', `label=qp.task-id=${opts.taskId}`);
  const fmt = '\t{{.Label "qp.task-id"}}\t{{.Label "qp.owner-pid"}}\t{{.Label "qp.created"}}';
  const [c, n, v] = await Promise.all([
    docker(['ps', '-a', ...f, '--format', `{{.Names}}${fmt}`]),
    docker(['network', 'ls', ...f, '--format', `{{.Name}}${fmt}`]),
    docker(['volume', 'ls', ...f, '--format', `{{.Name}}${fmt}`]),
  ]);
  const rows = (r, type) => r.stdout.split(/\r?\n/).filter(Boolean).map((l) => {
    const [name, task, owner, created] = l.split('\t');
    return { type, name, task, owner: Number(owner), created: Number(created), labelled: true };
  });
  const all = [...rows(c, 'container'), ...rows(n, 'network'), ...rows(v, 'volume')];
  if (!opts.nameSweep) return all;
  const seen = new Set(all.map((o) => `${o.type}:${o.name}`));
  const pattern = ownName(prefix, opts.taskId || undefined);
  // The query itself is scoped: with a taskId, Docker is asked only for that task's names.
  const nameQuery = opts.taskId ? `name=^ar-${prefix}-[a-z]+-${opts.taskId}$` : `name=^ar-${prefix}-`;
  const byName = await Promise.all([
    docker(['ps', '-a', '--filter', nameQuery, '--format', '{{.Names}}']),
    docker(['network', 'ls', '--filter', nameQuery, '--format', '{{.Name}}']),
    docker(['volume', 'ls', '--filter', nameQuery, '--format', '{{.Name}}']),
  ]);
  ['container', 'network', 'volume'].forEach((type, i) => {
    for (const name of byName[i].stdout.split(/\r?\n/).filter(Boolean)) {
      if (!pattern.test(name) || seen.has(`${type}:${name}`)) continue;
      all.push({ type, name, task: name.slice(-10), owner: NaN, created: NaN, labelled: false });
      seen.add(`${type}:${name}`);
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

// Removes only this task's objects.
async function removeTask(prefix, taskId) {
  if (!/^[a-f0-9]{10}$/.test(String(taskId))) throw new Error('invalid task id');
  let removed = { containers: [], networks: [], volumes: [] };
  for (let i = 0; i < 3; i++) {
    const objs = await listObjects(prefix, { taskId, nameSweep: true });
    if (!objs.length) break;
    const r = await removeObjects(objs);
    removed = {
      containers: [...new Set([...removed.containers, ...r.containers])],
      networks: [...new Set([...removed.networks, ...r.networks])],
      volumes: [...new Set([...removed.volumes, ...r.volumes])],
    };
  }
  return removed;
}

// Pure selection used by the reaper (exported for tests).
function selectOrphans(objs, { now, staleMs, isAlive = alive }) {
  return objs.filter((o) => o.labelled && (!isAlive(o.owner) || (Number.isFinite(o.created) && now - o.created > staleMs)));
}

// Startup reaper: labelled objects of this prefix whose owner CLI is gone,
// or older than the longest possible task. Live tasks of other CLIs are kept.
async function reapOrphans(prefix, { staleMs, now = Date.now() } = {}) {
  const objs = await listObjects(prefix);
  const orphans = selectOrphans(objs, { now, staleMs: staleMs || 30 * 60 * 1000 });
  if (!orphans.length) return { containers: [], networks: [], volumes: [] };
  return removeObjects(orphans);
}

async function cleanupAll(prefix) {
  return removeObjects(await listObjects(prefix, { nameSweep: true }));
}

async function leftovers(prefix) {
  return listObjects(prefix, { nameSweep: true });
}

function startWatchdog(ownerPid, prefix, taskId) {
  const r = spawnSync(process.execPath, [path.join(__dirname, 'watchdog-launch.js'), String(ownerPid), prefix, taskId], {
    encoding: 'utf8', windowsHide: true, timeout: 15000,
  });
  const pid = Number(String(r.stdout || '').trim());
  return { pid: Number.isInteger(pid) && pid > 0 ? pid : null };
}

module.exports = { listObjects, removeObjects, removeTask, reapOrphans, selectOrphans, cleanupAll, leftovers, startWatchdog, alive, ownName, ROLE_WORDS };

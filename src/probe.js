// Host-side probe (C2, DEC-5r1).
// Capture point: a helper container on the Docker engine's host network
// namespace (--network host). On Docker Desktop/WSL2 that is the Linux VM
// running dockerd; on plain Linux it is the host itself. In both, every
// packet leaving a container's network namespace crosses its veth into a
// bridge in this namespace, so `tcpdump -i any` here sees it pre-NAT, with
// the container's own source address, before any routing to an egress
// interface.
'use strict';

const { docker, attach } = require('./docker');
const { objName } = require('./config');

const IP_RE = /\bIP (\d+\.\d+\.\d+\.\d+)(?:\.(\d+))? > (\d+\.\d+\.\d+\.\d+)(?:\.(\d+))?:/;

function ipToInt(ip) { return ip.split('.').reduce((a, b) => (a << 8) + Number(b), 0) >>> 0; }
function inNet(ip, cidr) {
  if (!ip || !cidr) return false;
  const [base, bits] = cidr.split('/');
  const mask = bits === '0' ? 0 : (~0 << (32 - Number(bits))) >>> 0;
  return (ipToInt(ip) & mask) === (ipToInt(base) & mask);
}

async function start(cfg, { taskId, labels, subnet, sinkholeIp, nonceName }) {
  const ctlNet = objName(cfg, 'ctlnet', taskId);
  await docker(['network', 'create', ...labels, ctlNet], { allowFail: false });
  const ctlInfo = JSON.parse((await docker(['network', 'inspect', ctlNet], { allowFail: false })).stdout)[0];
  const ctlSubnet = ctlInfo.IPAM.Config[0].Subnet;
  const name = objName(cfg, 'probe', taskId);
  const filter = `net ${subnet} or net ${ctlSubnet} or port 53`;
  await docker(['create', '--rm', '--name', name, ...labels, '--network', 'host',
    '--read-only', '--tmpfs', '/tmp:size=8m', '--cap-drop', 'ALL', '--cap-add', 'NET_RAW', '--cap-add', 'NET_ADMIN',
    '--security-opt', 'no-new-privileges', '--pids-limit', '16', '--memory', '128m',
    '--entrypoint', 'timeout', cfg.images.sinkhole, '-s', 'KILL', String(cfg.limits.sandboxSeconds + 120),
    'tcpdump', '-i', 'any', '-nn', '-l', '-p', filter], { allowFail: false });
  const h = attach(['start', '-a', name]);
  const listening = await waitFor(() => /listening on/.test(h.stderr), 15000);
  return { name, handle: h, listening, subnet, ctlNet, ctlSubnet, sinkholeIp, nonceName, filter };
}

function waitFor(pred, ms) {
  return new Promise((resolve) => {
    const end = Date.now() + ms;
    const t = setInterval(() => {
      if (pred()) { clearInterval(t); resolve(true); } else if (Date.now() > end) { clearInterval(t); resolve(false); }
    }, 100);
  });
}

async function finish(cfg, p, { taskId, labels, net, sinkholeIp }) {
  // Positive control 1: in-subnet traffic (a peer on the internal network talks to the sinkhole).
  await docker(['run', '--rm', '--name', objName(cfg, 'ctlin', taskId), ...labels, '--network', net,
    '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', '65534:65534', '--pids-limit', '16', '--memory', '64m',
    '--entrypoint', 'sh', cfg.images.sinkhole, '-c', `wget -q -T 2 -O /dev/null http://${sinkholeIp}:15001/qp-control-in || true`], { timeoutMs: 30000 });
  // Positive control 2: a container on a non-internal ar- network sends a packet out.
  await docker(['run', '--rm', '--name', objName(cfg, 'ctlout', taskId), ...labels, '--network', p.ctlNet,
    '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', '65534:65534', '--pids-limit', '16', '--memory', '64m',
    '--entrypoint', 'sh', cfg.images.sinkhole, '-c', 'wget -q -T 3 -O /dev/null http://1.1.1.1/ || true'], { timeoutMs: 30000 });
  await new Promise((r) => setTimeout(r, 1500));
  await docker(['kill', p.name]);
  await Promise.race([p.handle.done, new Promise((r) => setTimeout(r, 5000))]);
  return summarize(p, p.handle.stdout);
}

// Pure classification of tcpdump lines (exported for tests).
function summarize(p, text) {
  const lines = String(text).split(/\r?\n/).filter(Boolean);
  const counts = { sandboxLeaving: 0, inSubnet: 0, controlLeaving: 0, dnsNonceLeaving: 0, dnsNonceSeen: 0, linesParsed: 0 };
  const samples = { sandboxLeaving: [], inSubnet: [], controlLeaving: [], dnsNonceLeaving: [] };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const m = IP_RE.exec(line);
    if (!m) {
      // with -vv, the DNS question can be on a continuation line
      if (p.nonceName && line.includes(p.nonceName)) counts.dnsNonceSeen += 1;
      continue;
    }
    counts.linesParsed += 1;
    const [src, , dst, dport] = [m[1], m[2], m[3], m[4]];
    const push = (k) => { counts[k] += 1; if (samples[k].length < 3) samples[k].push(line.slice(0, 200)); };
    if (inNet(src, p.subnet) && !inNet(dst, p.subnet)) push('sandboxLeaving');
    else if (inNet(src, p.subnet) || inNet(dst, p.subnet)) push('inSubnet');
    if (inNet(src, p.ctlSubnet) && !inNet(dst, p.ctlSubnet)) push('controlLeaving');
    const next = lines[i + 1] || '';
    if (dport === '53' && p.nonceName && (line.includes(p.nonceName) || next.includes(p.nonceName))) {
      counts.dnsNonceSeen += 1;
      if (dst !== p.sinkholeIp) push('dnsNonceLeaving');
    }
  }
  const pass = counts.sandboxLeaving === 0 && counts.dnsNonceLeaving === 0 && counts.inSubnet > 0 && counts.controlLeaving > 0;
  return {
    capturePoint: 'helper container on the Docker engine host network namespace (Docker Desktop: the WSL2 VM running dockerd; plain Linux: the host), tcpdump -i any, pre-NAT on the bridge side',
    whyComplete: 'the sandbox shares the sinkhole\'s network namespace, whose only interface is a veth on the task\'s internal bridge; any packet leaving that namespace crosses the bridge in this namespace with its original source address before routing or NAT',
    filter: p.filter, listening: p.listening, sandboxSubnet: p.subnet, controlSubnet: p.ctlSubnet, sinkholeIp: p.sinkholeIp,
    nonceName: p.nonceName, counts, samples,
    expectation: 'sandboxLeaving = 0 and dnsNonceLeaving = 0; positive controls inSubnet > 0 and controlLeaving > 0',
    pass,
  };
}

module.exports = { start, finish, summarize, inNet };

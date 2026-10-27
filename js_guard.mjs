// Trusted analysis code. Candidate JavaScript is parsed, never imported/evaluated.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const acorn = require('./vendor/acorn.cjs');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const findings = [];
const runtimePaths = new Set(input.files.filter(file => file.role === 'runtime').map(file => file.path));
const blockedNetwork = new Set(['fetch', 'XMLHttpRequest', 'WebSocket', 'EventSource', 'sendBeacon']);
const blockedGm = new Set(['GM_cookie', 'GM_download', 'GM_openInTab']);
const blockedModules = new Set(['fs', 'child_process', 'net', 'tls', 'http', 'https', 'os', 'worker_threads', 'vm', 'module']);

function stringValue(node) {
  if (node?.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node?.type === 'TemplateLiteral' && node.expressions.length === 0)
    return node.quasis[0].value.cooked;
  if (node?.type === 'BinaryExpression' && node.operator === '+') {
    const left = stringValue(node.left), right = stringValue(node.right);
    if (left !== null && right !== null) return left + right;
  }
  return null;
}
function memberName(node) {
  if (node?.type !== 'MemberExpression') return null;
  return node.computed ? stringValue(node.property) : node.property.name;
}
for (const file of input.files) {
  const seen = new Set();
  function issue(rule, node, message) {
    const line = node?.loc?.start?.line || 1, key = rule + ':' + line;
    if (!seen.has(key) && findings.length < 200) {
      seen.add(key);
      findings.push({ severity: 'error', rule, path: file.path, line, message });
    }
  }
  function importSource(node, source) {
    const name = stringValue(source);
    if (name === null) {
      issue('runtime-dynamic-import', node, 'Computed module targets are outside the runtime profile');
      return;
    }
    if (name.startsWith('node:') || blockedModules.has(name.split('/')[0]) || !name.startsWith('.')) {
      issue('runtime-node-dependency', node, 'Only relative imports within the runtime area are allowed');
      return;
    }
    const sourceDirectory = file.role === 'userscript'
      ? input.policy.helper_root + 'src/' : path.posix.dirname(file.path);
    const resolved = path.posix.normalize(path.posix.join(sourceDirectory, name));
    if (!resolved.startsWith(input.policy.helper_root + 'src/'))
      issue('runtime-layer-import', node, 'Runtime imports must stay inside the runtime source area');
    else if (![resolved, resolved + '.js', resolved + '/index.js'].some(name => runtimePaths.has(name)))
      issue('runtime-missing-module', node, 'Runtime imports must resolve to a committed runtime module');
  }
  let ast;
  try {
    ast = acorn.parse(file.source, { ecmaVersion: 'latest', sourceType: 'module', locations: true });
  } catch {
    issue('runtime-syntax', null, 'JavaScript cannot be parsed by the pinned analyzer');
    continue;
  }
  const stack = [{ node: ast, parent: null, key: null }];
  while (stack.length) {
    const { node, parent, key } = stack.pop();
    if (!node || typeof node !== 'object') continue;
    const dataKey = node.type === 'Identifier' && (
      (parent?.type === 'Property' && key === 'key' && !parent.computed && !parent.shorthand) ||
      (parent?.type === 'MemberExpression' && key === 'property' && !parent.computed) ||
      (parent?.type === 'MethodDefinition' && key === 'key' && !parent.computed)
    );
    const referenced = node.type === 'Identifier' && !dataKey ? node.name : memberName(node);
    if (referenced === 'eval' || referenced === 'Function')
      issue('runtime-dynamic-execution', node, 'Dynamic execution capability is outside the runtime profile');
    if (referenced === 'process')
      issue('runtime-node-global', node, 'The Node process object is outside the browser-runtime profile');
    if (blockedNetwork.has(referenced))
      issue('runtime-network-surface', node, 'New network primitives require a reviewed capability change');
    if (blockedGm.has(referenced))
      issue('runtime-extra-gm-api', node, 'This userscript capability is outside the approved profile');
    if (referenced === 'GM_xmlhttpRequest' && file.role !== 'userscript' &&
        !input.policy.network_wiring_files.includes(file.path))
      issue('network-boundary', node, 'Network wiring is outside the approved adapter/runtime files');
    if (node.type === 'MemberExpression' && memberName(node) === 'cookie')
      issue('runtime-cookie-access', node, 'Cookie access is outside this runtime profile');
    if (node.type === 'MemberExpression' && ['read', 'readText'].includes(memberName(node)) &&
        memberName(node.object) === 'clipboard')
      issue('runtime-clipboard-read', node, 'Clipboard reading is outside this runtime profile');
    if (node.type === 'MemberExpression' && memberName(node) === 'constructor' &&
        memberName(node.object) === 'constructor')
      issue('runtime-dynamic-execution', node, 'Constructor chaining is outside this runtime profile');
    if (['ImportDeclaration', 'ExportNamedDeclaration', 'ExportAllDeclaration'].includes(node.type) && node.source)
      importSource(node, node.source);
    if (node.type === 'ImportExpression') importSource(node, node.source);
    if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'require')
      importSource(node, node.arguments[0]);
    if (node.type === 'Identifier' && node.name === 'require' && !dataKey &&
        !(parent?.type === 'CallExpression' && key === 'callee') &&
        !(parent?.type === 'UnaryExpression' && parent.operator === 'typeof'))
      issue('runtime-dynamic-import', node, 'Aliasing the module loader is outside the runtime profile');
    if (node.type === 'CallExpression' && memberName(node.callee) === 'createElement' &&
        ['script', 'iframe', 'object', 'embed'].includes(stringValue(node.arguments[0])))
      issue('runtime-active-element', node, 'Creating an active element requires capability review');
    if (node.type === 'CallExpression' && memberName(node.callee) === 'setAttribute' &&
        stringValue(node.arguments[0])?.toLowerCase().startsWith('on'))
      issue('runtime-dynamic-execution', node, 'String event handlers are outside the runtime profile');
    for (const [childKey, value] of Object.entries(node)) {
      if (childKey === 'loc') continue;
      if (Array.isArray(value)) {
        for (const child of value) if (child && typeof child === 'object')
          stack.push({ node: child, parent: node, key: childKey });
      } else if (value && typeof value === 'object')
        stack.push({ node: value, parent: node, key: childKey });
    }
  }
}
process.stdout.write(JSON.stringify(findings));

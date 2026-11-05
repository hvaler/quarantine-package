// Minimal JSON Schema draft-04 validator, test-only (S7 F1b). It implements exactly
// the keywords the OASIS SARIF 2.1.0 schema uses (checked by a test that lists them):
// type, $ref (local "#/..."), properties, required, additionalProperties, items,
// minItems, uniqueItems, minimum, maximum, pattern, enum, anyOf, oneOf, allOf, not,
// format (uri, uri-reference, date-time). Unknown keywords make it throw, so a schema
// using a keyword this file does not implement can never pass silently.
// Written here because installing a validator package was not available in this
// environment; the auditor validates independently with Python jsonschema (Draft4).
'use strict';

const ANNOTATIONS = new Set(['$schema', 'id', 'title', 'description', 'default', 'definitions']);
const IMPLEMENTED = new Set(['type', '$ref', 'properties', 'required', 'additionalProperties', 'items', 'minItems', 'uniqueItems', 'minimum', 'maximum', 'pattern', 'enum', 'anyOf', 'oneOf', 'allOf', 'not', 'format']);

const typeOf = (v) => (v === null ? 'null' : Array.isArray(v) ? 'array' : Number.isInteger(v) ? 'integer' : typeof v);
const isType = (v, t) => (t === 'number' ? typeof v === 'number' && Number.isFinite(v) : t === 'integer' ? Number.isInteger(v) : typeOf(v) === t);
function canon(v) {
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(',')}}`;
  return JSON.stringify(v);
}
const FORMATS = {
  uri: (s) => /^[A-Za-z][A-Za-z0-9+.-]*:[^\s]*$/.test(s),
  'uri-reference': (s) => !/\s/.test(s),
  'date-time': (s) => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(s),
};

function validate(root, data) {
  const errors = [];
  const resolve = (ref) => {
    if (!ref.startsWith('#')) throw new Error(`non-local $ref ${ref}`);
    return ref.slice(1).split('/').filter(Boolean).reduce((o, k) => o[k.replace(/~1/g, '/').replace(/~0/g, '~')], root);
  };
  function v(schema, x, at) {
    for (const k of Object.keys(schema)) if (!ANNOTATIONS.has(k) && !IMPLEMENTED.has(k)) throw new Error(`keyword not implemented: ${k}`);
    if (schema.$ref) return v(resolve(schema.$ref), x, at);
    const before = errors.length;
    const err = (m) => errors.push(`${at || '/'}: ${m}`);
    if (schema.type) {
      const ts = Array.isArray(schema.type) ? schema.type : [schema.type];
      if (!ts.some((t) => isType(x, t))) { err(`type ${typeOf(x)} not in ${ts.join('|')}`); return false; }
    }
    if (schema.enum && !schema.enum.some((e) => canon(e) === canon(x))) err(`not in enum ${JSON.stringify(schema.enum)}`);
    if (typeof x === 'string') {
      if (schema.pattern && !new RegExp(schema.pattern, 'u').test(x)) err(`does not match ${schema.pattern}`);
      if (schema.format && FORMATS[schema.format] && !FORMATS[schema.format](x)) err(`not a ${schema.format}`);
    }
    if (typeof x === 'number') {
      if (schema.minimum !== undefined && x < schema.minimum) err(`< ${schema.minimum}`);
      if (schema.maximum !== undefined && x > schema.maximum) err(`> ${schema.maximum}`);
    }
    if (Array.isArray(x)) {
      if (schema.minItems !== undefined && x.length < schema.minItems) err(`fewer than ${schema.minItems} items`);
      if (schema.uniqueItems && new Set(x.map(canon)).size !== x.length) err('items not unique');
      if (schema.items && !Array.isArray(schema.items)) x.forEach((it, i) => v(schema.items, it, `${at}/${i}`));
    }
    if (x && typeof x === 'object' && !Array.isArray(x)) {
      for (const r of schema.required || []) if (!Object.hasOwn(x, r)) err(`missing ${r}`);
      const props = schema.properties || {};
      for (const [k, val] of Object.entries(x)) {
        if (Object.hasOwn(props, k)) v(props[k], val, `${at}/${k}`);
        else if (schema.additionalProperties === false) err(`additional property ${k}`);
        else if (schema.additionalProperties && typeof schema.additionalProperties === 'object') v(schema.additionalProperties, val, `${at}/${k}`);
      }
    }
    const sub = (s) => { const save = errors.length; v(s, x, at); const ok = errors.length === save; errors.length = save; return ok; };
    if (schema.anyOf && !schema.anyOf.some(sub)) err('no anyOf branch matches');
    if (schema.oneOf && schema.oneOf.filter(sub).length !== 1) err('not exactly one oneOf branch matches');
    if (schema.allOf) for (const s of schema.allOf) v(s, x, at);
    if (schema.not && sub(schema.not)) err('matches not');
    return errors.length === before;
  }
  v(root, data, '');
  return { valid: errors.length === 0, errors };
}

module.exports = { validate, IMPLEMENTED };

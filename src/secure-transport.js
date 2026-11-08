const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1']);

function normalizedHost(hostname = '') {
  return String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
}

export function validateServiceUrl(value = '', label = 'service URL') {
  let url;
  try {
    url = new URL(String(value || '').trim());
  } catch {
    throw new Error(`${label} must be a valid URL`);
  }
  if (url.username || url.password) throw new Error(`${label} must not include URL credentials`);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error(`${label} must use http or https`);
  if (url.protocol === 'http:' && !LOOPBACK_HOSTS.has(normalizedHost(url.hostname))) {
    throw new Error(`${label} must use HTTPS outside exact loopback HTTP`);
  }
  return url;
}

/**
 * Fetch a bearer-authenticated service without following redirects. A redirect
 * could forward the Authorization header to another origin, so it is rejected.
 */
export async function fetchService(url = '', init = {}, { fetchImpl = globalThis.fetch, label = 'service' } = {}) {
  const safeUrl = validateServiceUrl(url, label);
  if (typeof fetchImpl !== 'function') throw new Error(`${label} fetch unavailable`);
  const response = await fetchImpl(safeUrl.toString(), { ...init, redirect: 'manual' });
  const status = Number(response?.status || 0);
  if (status >= 300 && status < 400) throw new Error(`${label} redirects are not allowed`);
  return response;
}

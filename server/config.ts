const defaultEnv = {
  // PUBLIC_URL: 'http://localhost:8000',
  PUBLIC_URL: 'https://smart-health-links-server.cirg.washington.edu',
  FILE_SIZE_MAX: 1024 * 1024 * 100, // 100 MB
  EMBEDDED_LENGTH_MAX: 10_000, // 10 KB
  JWKS_URL: "",
};

async function envOrDefault(variable: string, defaultValue: string | number) {
  const havePermission = (await Deno.permissions.query({ name: 'env', variable })).state === 'granted';
  let ret;
  try  {
    // in Deno 1.25.1 sometimes 'granted' still leads to a prompt
    // remove this `try` when https://github.com/denoland/deno/issues/15894 is resolved
    ret = (havePermission && Deno.env.get(variable)) || '' + defaultValue;
  }  catch {
    ret = '' + defaultValue
  }
  return typeof defaultValue === 'number' ? parseFloat(ret) : ret;
}

const env = Object.fromEntries(
  await Promise.all(Object.entries(defaultEnv).map(async ([k, v]) => [k, await envOrDefault(k, v)])),
) as typeof defaultEnv;

export default env;

interface Config {
  PUBLIC_URL: string;
  EMBEDDED_LENGTH_MAX: number;
  FILE_SIZE_MAX: number;
  APP_VERSION_STRING?: string;
  PORT?: number;
  JWKS_URL?: string;
  DIR?: string;
};

const port = Number(Deno.env.get("PORT") || 8888);
const test_port = Number(Deno.env.get("TEST_PORT") || 9999);

const defaultEnv: Config = {
  PUBLIC_URL: `http://localhost:${port}`,
  FILE_SIZE_MAX: 1024 * 1024 * 100, // 100 MB
  EMBEDDED_LENGTH_MAX: 10_000, // 10 KB
  APP_VERSION_STRING: "",
  PORT: port,
  JWKS_URL: "",
  DIR: ".",
};

const testEnv: Config = {
  ...defaultEnv,
  PUBLIC_URL: `http://localhost:${test_port}`,
  PORT: test_port,
  DIR: "tests",
}

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
const fallback = Deno.env.get("TEST") ? testEnv : defaultEnv;
const env = Object.fromEntries(
  await Promise.all(Object.entries(fallback).map(async ([k, v]) => [k, await envOrDefault(k, v)])),
) as typeof defaultEnv;

export default env;

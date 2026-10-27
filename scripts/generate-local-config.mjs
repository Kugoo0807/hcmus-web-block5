import { existsSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes, randomUUID } from "node:crypto";
import { exportJWK, generateKeyPair } from "jose";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const force = process.argv.includes("--force");
const asEnv = resolve(root, "apps/wallet-as/.env.local");
const apiEnv = resolve(root, "apps/wallet-api/.env.local");
const taxiEnv = resolve(root, "apps/taxi/.env.local");

if (!force && [asEnv, apiEnv, taxiEnv].some(existsSync)) {
  console.error("Local configuration already exists. Use --force only when you also reset local databases.");
  process.exit(1);
}

function b64Json(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function writeEnv(path, values) {
  const text = Object.entries(values).map(function ([key, value]) {
    return key + "=" + value;
  }).join("\n") + "\n";
  writeFileSync(path, text, { encoding: "utf8", mode: 0o600 });
}

const pair = await generateKeyPair("ES256", { extractable: true });
const privateJwk = await exportJWK(pair.privateKey);
const publicJwk = await exportJWK(pair.publicKey);
const taxiWebSecret = randomBytes(32).toString("base64url");
const taxiM2mSecret = randomBytes(32).toString("base64url");

writeEnv(asEnv, {
  WALLET_AS_BASE_URL: "http://127.0.0.1:3001",
  WALLET_API_BASE_URL: "http://127.0.0.1:3002",
  TAXI_BASE_URL: "http://127.0.0.1:3003",
  WALLET_AS_PORT: "3001",
  WALLET_AS_KID: "lab-" + randomUUID(),
  WALLET_AS_PRIVATE_JWK_B64: b64Json(privateJwk),
  WALLET_AS_PUBLIC_JWK_B64: b64Json(publicJwk),
  WALLET_AS_SESSION_SECRET: randomBytes(32).toString("base64url"),
  TAXI_WEB_CLIENT_SECRET: taxiWebSecret,
  TAXI_M2M_CLIENT_SECRET: taxiM2mSecret
});

writeEnv(apiEnv, {
  WALLET_API_BASE_URL: "http://127.0.0.1:3002",
  WALLET_API_PORT: "3002",
  WALLET_AS_BASE_URL: "http://127.0.0.1:3001"
});

writeEnv(taxiEnv, {
  TAXI_BASE_URL: "http://127.0.0.1:3003",
  TAXI_PORT: "3003",
  WALLET_AS_BASE_URL: "http://127.0.0.1:3001",
  WALLET_API_BASE_URL: "http://127.0.0.1:3002",
  TAXI_WEB_CLIENT_ID: "taxi-web",
  TAXI_WEB_CLIENT_SECRET: taxiWebSecret,
  TAXI_SESSION_SECRET: randomBytes(32).toString("base64url"),
  TAXI_JOB_KEY: randomBytes(32).toString("base64url"),
  TAXI_TOKEN_ENCRYPTION_KEY_B64: randomBytes(32).toString("base64url")
});

console.log("Created ignored local configuration and a fresh ES256 key pair.");
console.log("No generated secret or private key was printed.");

import dotenv from "dotenv";
import { randomBytes } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
dotenv.config({ path: resolve(root, "apps/taxi/.env.local") });
const taxiBaseUrl = process.env.TAXI_BASE_URL || "http://127.0.0.1:3003";
const asBaseUrl = process.env.WALLET_AS_BASE_URL || "http://127.0.0.1:3001";

class BrowserCookies {
  constructor() { this.byOrigin = new Map(); }
  add(url, response) {
    const cookie = response.headers.get("set-cookie");
    if (cookie) this.byOrigin.set(new URL(url).origin, cookie.split(";")[0]);
  }
  async fetch(url, options) {
    const target = new URL(url);
    const headers = new Headers((options && options.headers) || {});
    const cookie = this.byOrigin.get(target.origin);
    if (cookie) headers.set("cookie", cookie);
    const response = await fetch(target, { ...(options || {}), headers, redirect: "manual" });
    this.add(target, response);
    return response;
  }
}
function absolute(base, location) { return new URL(location, base).toString(); }
function expect(condition, message) { if (!condition) throw new Error(message); }

const browser = new BrowserCookies();
let response = await browser.fetch(taxiBaseUrl + "/link-wallet");
expect(response.status === 302, "Taxi did not start authorization");
let location = response.headers.get("location");
expect(location && location.startsWith(asBaseUrl + "/authorize"), "Taxi redirect URI is unexpected");

response = await browser.fetch(location);
expect(response.status === 302 && response.headers.get("location") === "/login", "AS did not request Wallet login");
response = await browser.fetch(asBaseUrl + "/login");
expect(response.status === 200, "Wallet login page unavailable");
response = await browser.fetch(asBaseUrl + "/login", {
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({ username: "alice", password: "alice-password" }).toString()
});
expect(response.status === 302 && response.headers.get("location") === "/consent", "Wallet login failed");
response = await browser.fetch(asBaseUrl + "/consent");
expect(response.status === 200, "Wallet consent page unavailable");
response = await browser.fetch(asBaseUrl + "/consent", {
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: "decision=approve"
});
expect(response.status === 302, "Wallet consent did not redirect to Taxi");
location = response.headers.get("location");
expect(location && location.startsWith(taxiBaseUrl + "/oauth/callback"), "Consent callback is not Taxi");

response = await browser.fetch(location);
expect(response.status === 302 && response.headers.get("location") === "/", "Taxi callback failed");
response = await browser.fetch(taxiBaseUrl + "/wallet/balance");
expect(response.status === 200, "Taxi could not read Wallet balance after linking");
const balanceHtml = await response.text();
expect(balanceHtml.includes("Wallet balance"), "Balance page content is unexpected");

response = await browser.fetch(taxiBaseUrl + "/demo/run-job", { method: "POST", headers: { "x-test-run": randomBytes(4).toString("hex") } });
expect(response.status === 200, "Taxi payment job failed");
const jobHtml = await response.text();
expect(jobHtml.includes("Payment job completed"), "Payment job page content is unexpected");

console.log("PASS Taxi Authorization Code + PKCE flow, server-side refresh, balance read, and idempotent payment job.");
console.log("No authorization code, cookie, access token, or refresh token was printed.");

import { type Buyer, type Json, VendorError, input, json, object, origin, readBytes, text } from "./http.js";
import { type Jwks, verifyRequest } from "./signature.js";

export interface VendorHandlers {
  trial(buyer: Buyer, input: { [key: string]: Json }): Promise<{ output: Json; note: string }>;
  account(buyer: Buyer, email: string): Promise<{ account_id: string; created: boolean }>;
  /** Required for Handover account reuse. Return null only when no owned account exists. */
  lookup?(buyer: Buyer): Promise<{ account_id: string } | null>;
  /** Check environment AND buyer against the stored owner. Called before all account operations. */
  authorizeAccount(buyer: Buyer, accountId: string): Promise<boolean>;
  checkout(buyer: Buyer, accountId: string, offerId: string, paymentToken?: string): Promise<Json>;
  access(buyer: Buyer, accountId: string): Promise<{ api_key: string; offer: string; usage: number }>;
  use(buyer: Buyer, accountId: string, input: { [key: string]: Json }): Promise<{ output: Json; usage: number }>;
}

export interface VendorConfig {
  origin: string;
  /** Local development and tests only: trust these keys instead of Rose's published ones. */
  keys?: Jwks;
  handlers: VendorHandlers;
  /** Mount this handler at the base URL agreed with Rose. Default: /r4a. */
  basePath?: string;
  maxBodyBytes?: number;
}

/** Fetch-compatible router for Rose's five signed-in vendor operations. */
export function createVendorHandler(config: VendorConfig): (request: Request) => Promise<Response> {
  const expectedOrigin = origin(config.origin);
  const base = config.basePath ?? "/r4a";
  if (!/^\/[a-zA-Z0-9/_-]*[a-zA-Z0-9_-]$/.test(base)) throw new Error("Invalid basePath");
  const maxBody = config.maxBodyBytes ?? 65536;
  if (!Number.isSafeInteger(maxBody) || maxBody < 1 || maxBody > 1048576) throw new Error("Invalid maxBodyBytes");
  const handlers = config.handlers;
  return async request => {
    try {
      const url = new URL(request.url);
      if (url.origin !== expectedOrigin || url.search || url.hash) throw new VendorError(404, "Not found");
      const relative = url.pathname.startsWith(`${base}/`) ? url.pathname.slice(base.length) : "";
      const scoped = /^\/accounts\/([a-zA-Z0-9_-]{1,128})\/(checkout|access|use)$/.exec(relative);
      const action = relative === "/trial" ? "trial" : relative === "/accounts" ? "account" : relative === "/account" ? "lookup" : scoped?.[2];
      if (!action || request.method !== (["access", "lookup"].includes(action) ? "GET" : "POST")) throw new VendorError(404, "Not found");
      const bytes = await readBytes(request, maxBody);
      const buyer = await verifyRequest(request, bytes, config.keys);
      const data = ["access", "lookup"].includes(action) ? {} : object(bytes);
      if (action === "lookup") {
        if (!handlers.lookup) throw new VendorError(503, "Account lookup is not configured");
        const result = await handlers.lookup(buyer);
        if (!result) throw new VendorError(404, "No account for this buyer");
        if ((await handlers.authorizeAccount(buyer, result.account_id)) !== true) throw new VendorError(403, "Account access denied");
        return json({ account_id: result.account_id });
      }
      if (action === "trial") return json(await handlers.trial(buyer, input(data.input)));
      if (action === "account") {
        const email = text(data.email, "email");
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new VendorError(422, "Invalid email");
        const result = await handlers.account(buyer, email);
        return json({ account_id: result.account_id }, result.created ? 201 : 200);
      }
      const accountId = scoped?.[1];
      if (!accountId || (await handlers.authorizeAccount(buyer, accountId)) !== true) throw new VendorError(403, "Account access denied");
      if (action === "access") return json(await handlers.access(buyer, accountId));
      if (action === "use") return json(await handlers.use(buyer, accountId, input(data.input)));
      const offer = text(data.offer_id, "offer_id");
      const payment = data.payment_token == null ? undefined : text(data.payment_token, "payment_token");
      return json(await handlers.checkout(buyer, accountId, offer, payment));
    } catch (error) {
      if (error instanceof VendorError) return json({ detail: error.detail }, error.status);
      return json({ detail: "Vendor service error" }, 500);
    }
  };
}

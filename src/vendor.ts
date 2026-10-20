import { type Buyer, EMAIL, type Json, VendorError, input, json, object, origin, readBytes, text } from "./http.js";
import { type Jwks, verifyRequest } from "./signature.js";

export interface VendorHandlers {
  trial(buyer: Buyer, input: { [key: string]: Json }): Promise<{ output: Json; note: string }>;
  account(buyer: Buyer, email: string, input?: { [key: string]: Json }): Promise<{ account_id: string; created: boolean; next?: string }>;
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

type Route =
  | { action: "trial" | "account" | "lookup" }
  | { action: "checkout" | "access" | "use"; accountId: string };

/** The contract's routes, relative to the base path. Anything else is a 404. */
function route(method: string, path: string): Route | null {
  if (method === "POST" && path === "/trial") return { action: "trial" };
  if (method === "POST" && path === "/accounts") return { action: "account" };
  if (method === "GET" && path === "/account") return { action: "lookup" };
  const scoped = /^\/accounts\/([a-zA-Z0-9_-]{1,128})\/(checkout|access|use)$/.exec(path);
  const [, accountId, action] = scoped ?? [];
  if (!accountId || (action !== "checkout" && action !== "access" && action !== "use")) return null;
  return method === (action === "access" ? "GET" : "POST") ? { action, accountId } : null;
}

/** Fetch-compatible router for Rose's six signed vendor operations. */
export function createVendorHandler(config: VendorConfig): (request: Request) => Promise<Response> {
  const expectedOrigin = origin(config.origin);
  const base = config.basePath ?? "/r4a";
  if (!/^\/[a-zA-Z0-9/_-]*[a-zA-Z0-9_-]$/.test(base)) throw new Error("Invalid basePath");
  const maxBody = config.maxBodyBytes ?? 65536;
  if (!Number.isSafeInteger(maxBody) || maxBody < 1 || maxBody > 1048576) throw new Error("Invalid maxBodyBytes");
  const handlers = config.handlers;

  async function handle(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.origin !== expectedOrigin || url.search || url.hash) throw new VendorError(404, "Not found");
    const path = url.pathname.startsWith(`${base}/`) ? url.pathname.slice(base.length) : "";
    const target = route(request.method, path);
    if (!target) throw new VendorError(404, "Not found");

    // Verify Rose's signature over the exact bytes before parsing or calling any handler.
    const bytes = await readBytes(request, maxBody);
    const buyer = await verifyRequest(request, bytes, config.keys);
    const data = request.method === "GET" ? {} : object(bytes);

    switch (target.action) {
      case "trial":
        return json(await handlers.trial(buyer, input(data.input)));
      case "account": {
        const email = text(data.email, "email");
        if (!EMAIL.test(email)) throw new VendorError(422, "Invalid email");
        const setup = data.input === undefined ? undefined : input(data.input);
        const result = await handlers.account(buyer, email, setup);
        return json({ account_id: result.account_id, ...(result.next === undefined ? {} : { next: result.next }) },
          result.created ? 201 : 200);
      }
      case "lookup": {
        if (!handlers.lookup) throw new VendorError(503, "Account lookup is not configured");
        const result = await handlers.lookup(buyer);
        if (!result) throw new VendorError(404, "No account for this buyer");
        await authorize(buyer, result.account_id);
        return json({ account_id: result.account_id });
      }
    }
    const { accountId } = target;
    await authorize(buyer, accountId);
    switch (target.action) {
      case "access":
        return json(await handlers.access(buyer, accountId));
      case "use":
        return json(await handlers.use(buyer, accountId, input(data.input)));
      case "checkout": {
        const offer = text(data.offer_id, "offer_id");
        const payment = data.payment_token == null ? undefined : text(data.payment_token, "payment_token");
        return json(await handlers.checkout(buyer, accountId, offer, payment));
      }
    }
  }

  async function authorize(buyer: Buyer, accountId: string): Promise<void> {
    // Strictly true: a truthy object or string from a careless handler does not grant access.
    if ((await handlers.authorizeAccount(buyer, accountId)) !== true) throw new VendorError(403, "Account access denied");
  }

  return async request => {
    try {
      return await handle(request);
    } catch (error) {
      if (error instanceof VendorError) return json({ detail: error.detail }, error.status);
      // Logged for you, never returned to Rose: the message may hold internal details.
      console.error("Rose vendor request failed", error);
      return json({ detail: "Vendor service error" }, 500);
    }
  };
}

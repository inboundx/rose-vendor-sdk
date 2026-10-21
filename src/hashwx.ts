/** HashWX format-2 wire protocol, interoperable with capjs-core 0.1.5.
 * Wasm source: tevador/hashwx @ 74b567a31276a4c5d7cb232a5b7639467f49f961.
 * Packaged upstream artifact SHA-256: b1a0dbb3ef444d3c7069e0a5e0a0273ffa4cf8fef62cbbe43761c02f7cd6aff5.
 * Only the upstream Wasm export is imported; browser instrumentation is never loaded.
 */
import module from "#hashwx-module";

export interface HashwxPuzzle { protocol: "hashwx"; payload: { c: string; d: number; n: number } }
interface HashwxExports extends WebAssembly.Exports {
  memory: WebAssembly.Memory;
  _initialize(): void;
  hashwx_alloc(mode: number): number;
  hashwx_free(ctx: number): void;
  hashwx_seed(ctx: number): number;
  hashwx_make(ctx: number, seed: number): void;
  hashwx_exec(ctx: number, nonce: bigint): bigint;
}

// The static module/instance holds no request promise. Each redemption allocates its own
// context in this shared 16 MiB memory, avoiding one 16 MiB Wasm heap per concurrent request.
const wasm = new WebAssembly.Instance(module, {}).exports as HashwxExports;
wasm._initialize();

export function challenges(difficulty: number): HashwxPuzzle[] {
  return Array.from({ length: 4 }, () => ({ protocol: "hashwx", payload: {
    c: [...crypto.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, "0")).join(""),
    d: difficulty / 4, n: 65_536,
  } }));
}

export async function verifySolutions(puzzles: HashwxPuzzle[], solutions: unknown[]): Promise<boolean> {
  if (puzzles.length !== 4 || solutions.length !== 4) return false;
  // Each redemption owns its context, including across asynchronous SHA-256 operations.
  const ctx = wasm.hashwx_alloc(0);
  if (ctx <= 0) throw new Error("HashWX unavailable");
  const seedPtr = wasm.hashwx_seed(ctx);
  try {
    for (let i = 0; i < puzzles.length; i++) {
      const solution = solutions[i];
      if (!solution || typeof solution !== "object" || !("nonce" in solution)) return false;
      const value = solution.nonce;
      if (typeof value !== "string" || !/^[0-9]{1,20}$/.test(value)) return false;
      const nonce = BigInt(value), max = (1n << 64n) - 1n;
      if (nonce > max) return false;
      const { c, d, n } = puzzles[i]!.payload;
      const seedInput = new Uint8Array(40);
      seedInput.set(Uint8Array.from(c.match(/../g)!, (h) => Number.parseInt(h, 16)));
      new DataView(seedInput.buffer).setBigUint64(32, nonce / BigInt(n), true);
      const seed = await crypto.subtle.digest("SHA-256", seedInput);
      new Uint8Array(wasm.memory.buffer, seedPtr, 32).set(new Uint8Array(seed));
      wasm.hashwx_make(ctx, seedPtr);
      if (BigInt.asUintN(64, wasm.hashwx_exec(ctx, nonce)) > max / BigInt(d)) return false;
    }
    return true;
  } finally {
    wasm.hashwx_free(ctx);
  }
}

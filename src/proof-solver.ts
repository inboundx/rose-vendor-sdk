/** Autonomous Node solver served by the vendor. Uses Cap's pinned upstream HashWX Wasm.
 * Compilation follows tevador/hashwx js/hashwx.js (public domain), commit
 * 74b567a31276a4c5d7cb232a5b7639467f49f961. No browser or human interaction.
 */
export const proofSolver = String.raw`// Node >=22. Install capjs-core@0.1.5, then: node solve-proof.mjs challenge.json
import { readFileSync } from 'node:fs';
import { hashwxSeed, hashwxTarget } from 'capjs-core';

const input = JSON.parse(readFileSync(process.argv[2] ?? 0, 'utf8'));
const challenge = input.proof_of_work ?? input;
if (challenge.format !== 2 || typeof challenge.token !== 'string' ||
    !Array.isArray(challenge.challenges) || challenge.challenges.length !== 4 ||
    !Number.isFinite(challenge.expires) || challenge.expires <= Date.now()) throw new Error('Invalid or expired challenge');
const wasm = new WebAssembly.Instance(new WebAssembly.Module(readFileSync(new URL(import.meta.resolve('capjs-core/hashwx.wasm')))), {}).exports;
wasm._initialize();
const ctx = wasm.hashwx_alloc(1);
if (ctx <= 0) throw new Error('HashWX compiler unavailable');
const seedPtr = wasm.hashwx_seed(ctx), registers = wasm.hashwx_registers(ctx), memory = wasm.hashwx_memory(ctx);
try {
  const solutions = challenge.challenges.map(({protocol, payload: p}) => {
    if (protocol !== 'hashwx' || !p || !/^[a-f0-9]{64}$/i.test(p.c) ||
        !Number.isSafeInteger(p.d) || p.d < 1 || p.d > 750000 || p.n !== 65536) throw new Error('Unsupported work budget');
    const bytes = Uint8Array.from(p.c.match(/../g), h => Number.parseInt(h, 16));
    const target = hashwxTarget(p.d);
    let program;
    for (let nonce = 0n; ; nonce++) {
      if (nonce % BigInt(p.n) === 0n) {
        if (Date.now() >= challenge.expires) throw new Error('Challenge expired; request a new one');
        new Uint8Array(wasm.memory.buffer, seedPtr, 32).set(hashwxSeed(bytes, nonce / BigInt(p.n)));
        wasm.hashwx_make(ctx, seedPtr);
        const code = new Uint8Array(wasm.memory.buffer, wasm.hashwx_module(ctx), wasm.hashwx_module_size(ctx));
        program = new WebAssembly.Instance(new WebAssembly.Module(code), {env: {memory: wasm.memory}}).exports;
      }
      wasm.hashwx_exec_begin(ctx, nonce);
      program.exec(registers, memory);
      if (BigInt.asUintN(64, wasm.hashwx_exec_final(ctx)) <= target) return {nonce: String(nonce)};
    }
  });
  process.stdout.write(JSON.stringify({type: 'anonymous', proof_of_work: {token: challenge.token, solutions}}) + '\n');
} finally {
  wasm.hashwx_free(ctx);
}
`;

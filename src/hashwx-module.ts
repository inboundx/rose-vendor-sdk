// Node loads synchronously at module initialization: never a request's pending promise.
import { readFileSync } from "node:fs";
export default new WebAssembly.Module(readFileSync(new URL(import.meta.resolve("capjs-core/hashwx.wasm"))));

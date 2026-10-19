import { createVendorHandler, type VendorHandlers } from "@userose/vendor-sdk";

/** Supply your database and product operations; the SDK handles the signed HTTP boundary. */
export function connectProduct(origin: string, handlers: VendorHandlers) {
  return createVendorHandler({ origin, handlers });
}

import type { About } from "../types/api";
import { readJson, send } from "./http";

/** Public: called before anyone signs in, so it does not use the access token. */
export async function getAbout(): Promise<About> {
  return readJson<About>(await send("/about"));
}

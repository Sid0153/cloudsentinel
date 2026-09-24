import type { Rule } from "../types/api";
import { apiGet } from "./api";

export function listRules(): Promise<Rule[]> {
  return apiGet<Rule[]>("/rules");
}

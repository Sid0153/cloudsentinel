import type { AwsAccount, AwsAccountVerification } from "../types/api";
import { apiGet, apiRequest } from "./api";

export interface NewAwsAccount {
  account_id: string;
  name: string;
  regions: string[];
  role_arn: string | null;
}

export function listAwsAccounts(): Promise<AwsAccount[]> {
  return apiGet<AwsAccount[]>("/aws-accounts");
}

export function createAwsAccount(input: NewAwsAccount): Promise<AwsAccount> {
  return apiRequest<AwsAccount>("/aws-accounts", { method: "POST", body: input });
}

export function verifyAwsAccount(id: string): Promise<AwsAccountVerification> {
  return apiRequest<AwsAccountVerification>(`/aws-accounts/${encodeURIComponent(id)}/verify`, {
    method: "POST",
  });
}

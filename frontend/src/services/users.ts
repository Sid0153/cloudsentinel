import type { Role, User } from "../types/auth";
import { apiGet, apiRequest } from "./api";

export interface NewUser {
  email: string;
  password: string;
  role: Role;
}

export function listUsers(): Promise<User[]> {
  return apiGet<User[]>("/users");
}

export function createUser(input: NewUser): Promise<User> {
  return apiRequest<User>("/users", { method: "POST", body: input });
}

/** Change a user's role and/or active flag. Admins cannot change their own (the API refuses). */
export function updateUser(id: string, changes: { role?: Role; is_active?: boolean }): Promise<User> {
  return apiRequest<User>(`/users/${encodeURIComponent(id)}`, { method: "PATCH", body: changes });
}

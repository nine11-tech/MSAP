import { ApiError, apiGet, apiPost, initializeCsrf } from "./client";
import type { AuthUser } from "./types";

export async function login(username: string, password: string) {
  await initializeCsrf();
  const response = await apiPost<
    { user: AuthUser },
    { username: string; password: string }
  >("auth/login/", { username: username.trim(), password });
  if (!response?.user || typeof response.user.username !== "string") {
    throw new ApiError(
      "Login response did not contain a valid user.",
      200,
      undefined,
      "auth/login/",
    );
  }
  return response.user;
}

export const getCurrentUser = () => apiGet<AuthUser>("auth/me/");

export async function logout() {
  await apiPost<null>("auth/logout/");
}

export async function changePassword(
  currentPassword: string,
  newPassword: string,
) {
  await apiPost<
    null,
    { current_password: string; new_password: string }
  >("auth/change-password/", {
    current_password: currentPassword,
    new_password: newPassword,
  });
  await initializeCsrf();
}

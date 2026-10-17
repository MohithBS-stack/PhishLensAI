/**
 * Core Authentication Client Logic and Types for PhishLens AI.
 *
 * Manages in-memory token state, deduplicated token refresh, and HTTP API integration
 * via the same-origin Next.js proxy (/api/v1/auth/...).
 *
 * Security Invariants:
 * - Refresh tokens are managed exclusively by the browser via HttpOnly cookies.
 * - Access tokens are held strictly in memory and never written to localStorage or sessionStorage.
 * - Concurrent refresh calls are deduplicated to avoid race conditions or false reuse triggers.
 */

import { API_BASE_URL } from "./api.ts";

export interface UserResponse {
  id: string;
  email: string;
  full_name: string | null;
  is_active: boolean;
  is_verified: boolean;
  created_at: string;
  updated_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: UserResponse;
}

export interface UserRegisterPayload {
  email: string;
  password: string;
  full_name?: string;
}

export interface UserLoginPayload {
  email: string;
  password: string;
}

export interface AuthContextType {
  user: UserResponse | null;
  accessToken: string | null;
  isLoading: boolean;
  error: string | null;
  login: (payload: UserLoginPayload) => Promise<void>;
  register: (payload: UserRegisterPayload) => Promise<void>;
  logout: () => Promise<void>;
  refreshAuth: () => Promise<string | null>;
  getValidAccessToken: () => Promise<string | null>;
  clearError: () => void;
}

// Concurrency lock: ensures multiple simultaneous refresh requests share a single in-flight Promise
let inflightRefreshPromise: Promise<TokenResponse | null> | null = null;

/**
 * Deduplicated token refresh call.
 * Uses the same-origin proxy (/api/v1/auth/refresh) allowing the browser to manage the HttpOnly cookie.
 */
export async function executeTokenRefresh(): Promise<TokenResponse | null> {
  if (inflightRefreshPromise) {
    return inflightRefreshPromise;
  }

  inflightRefreshPromise = (async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/auth/refresh`, {
        method: "POST",
        headers: {
          Accept: "application/json",
        },
        credentials: "same-origin",
      });

      if (!res.ok) {
        return null;
      }

      const data: TokenResponse = await res.json();
      return data;
    } catch (err) {
      console.warn("[PhishLens Auth] Refresh call failed:", err);
      return null;
    } finally {
      inflightRefreshPromise = null;
    }
  })();

  return inflightRefreshPromise;
}

/**
 * Fetches the authenticated user profile from /api/v1/auth/me using an in-memory access token.
 */
export async function fetchCurrentUser(
  token: string
): Promise<UserResponse | null> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/v1/auth/me`, {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${token}`,
      },
      credentials: "same-origin",
    });

    if (!res.ok) {
      return null;
    }

    const userData: UserResponse = await res.json();
    return userData;
  } catch (err) {
    console.warn("[PhishLens Auth] Fetch current user (/me) failed:", err);
    return null;
  }
}

/**
 * Calls backend login endpoint.
 */
export async function loginApi(payload: UserLoginPayload): Promise<TokenResponse> {
  const res = await fetch(`${API_BASE_URL}/api/v1/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(payload),
    credentials: "same-origin",
  });

  if (!res.ok) {
    const errData = await res.json().catch(() => null);
    const msg =
      errData?.error?.message ||
      (res.status === 401
        ? "Invalid email or password."
        : res.status === 429
        ? "Too many login attempts. Please try again later."
        : `Authentication failed (HTTP ${res.status}).`);
    throw new Error(msg);
  }

  return (await res.json()) as TokenResponse;
}

/**
 * Calls backend register endpoint.
 */
export async function registerApi(payload: UserRegisterPayload): Promise<TokenResponse> {
  const res = await fetch(`${API_BASE_URL}/api/v1/auth/register`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(payload),
    credentials: "same-origin",
  });

  if (!res.ok) {
    const errData = await res.json().catch(() => null);
    const msg =
      errData?.error?.message ||
      (res.status === 409
        ? "An account with this email address already exists."
        : res.status === 429
        ? "Too many registration attempts. Please retry later."
        : `Registration failed (HTTP ${res.status}).`);
    throw new Error(msg);
  }

  return (await res.json()) as TokenResponse;
}

/**
 * Calls backend logout endpoint.
 */
export async function logoutApi(): Promise<void> {
  try {
    await fetch(`${API_BASE_URL}/api/v1/auth/logout`, {
      method: "POST",
      headers: {
        Accept: "application/json",
      },
      credentials: "same-origin",
    });
  } catch (err) {
    console.warn("[PhishLens Auth] Logout endpoint call encountered an error:", err);
  }
}

/**
 * Client-side email and password validation helper.
 */
export function validateAuthCredentials(data: {
  email: string;
  password: string;
  confirmPassword?: string;
  isRegister?: boolean;
}): { valid: boolean; errors: Record<string, string> } {
  const errors: Record<string, string> = {};
  const email = data.email?.trim() || "";
  const password = data.password || "";

  if (!email) {
    errors.email = "Email address is required.";
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    errors.email = "Please enter a valid email address.";
  }

  if (!password) {
    errors.password = "Password is required.";
  } else if (password.length < 8) {
    errors.password = "Password must be at least 8 characters.";
  } else if (password.length > 128) {
    errors.password = "Password cannot exceed 128 characters.";
  }

  if (data.isRegister) {
    if (!data.confirmPassword) {
      errors.confirmPassword = "Confirming your password is required.";
    } else if (password !== data.confirmPassword) {
      errors.confirmPassword = "Passwords do not match.";
    }
  }

  return { valid: Object.keys(errors).length === 0, errors };
}

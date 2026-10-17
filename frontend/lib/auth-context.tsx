"use client";

import React, {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
  useRef,
} from "react";
import {
  UserResponse,
  TokenResponse,
  UserRegisterPayload,
  UserLoginPayload,
  AuthContextType,
  executeTokenRefresh,
  fetchCurrentUser,
  loginApi,
  registerApi,
  logoutApi,
} from "./auth";

export * from "./auth";

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [user, setUser] = useState<UserResponse | null>(null);
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // In-memory token expiration tracking
  const tokenExpiresAtRef = useRef<number | null>(null);

  const clearError = useCallback(() => setError(null), []);

  /**
   * Refreshes the in-memory access token using the browser's HttpOnly cookie,
   * then retrieves and validates the authenticated user via /api/v1/auth/me.
   * Never reports a user as authenticated unless /me succeeds.
   */
  const refreshAuth = useCallback(async (): Promise<string | null> => {
    const tokenData = await executeTokenRefresh();
    if (tokenData && tokenData.access_token) {
      // Step 2: Retrieve the authenticated user using the newly minted access token
      const me = await fetchCurrentUser(tokenData.access_token);
      if (!me) {
        // Failed /me validation: invalidate local session state
        setAccessToken(null);
        setUser(null);
        tokenExpiresAtRef.current = null;
        return null;
      }

      setAccessToken(tokenData.access_token);
      setUser(me);
      tokenExpiresAtRef.current = Date.now() + tokenData.expires_in * 1000;
      return tokenData.access_token;
    } else {
      setAccessToken(null);
      setUser(null);
      tokenExpiresAtRef.current = null;
      return null;
    }
  }, []);

  /**
   * Initial session restoration on mount.
   * Calls the refresh endpoint, then retrieves the authenticated user.
   */
  useEffect(() => {
    let isMounted = true;

    async function restoreSession() {
      setIsLoading(true);
      try {
        const token = await refreshAuth();
        if (!token && isMounted) {
          setAccessToken(null);
          setUser(null);
        }
      } catch (err) {
        if (isMounted) {
          setAccessToken(null);
          setUser(null);
        }
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }
    }

    restoreSession();

    return () => {
      isMounted = false;
    };
  }, [refreshAuth]);

  /**
   * Log in user with email and password, requiring successful /me verification.
   */
  const login = useCallback(
    async (payload: UserLoginPayload): Promise<void> => {
      setIsLoading(true);
      setError(null);

      try {
        const data = await loginApi(payload);
        const me = await fetchCurrentUser(data.access_token);
        if (!me) {
          throw new Error("Failed to verify authenticated operator profile.");
        }
        setAccessToken(data.access_token);
        setUser(me);
        tokenExpiresAtRef.current = Date.now() + data.expires_in * 1000;
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : "Authentication error";
        setError(message);
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    []
  );

  /**
   * Register a new user account, requiring successful /me verification.
   */
  const register = useCallback(
    async (payload: UserRegisterPayload): Promise<void> => {
      setIsLoading(true);
      setError(null);

      try {
        const data = await registerApi(payload);
        const me = await fetchCurrentUser(data.access_token);
        if (!me) {
          throw new Error("Failed to verify newly provisioned operator profile.");
        }
        setAccessToken(data.access_token);
        setUser(me);
        tokenExpiresAtRef.current = Date.now() + data.expires_in * 1000;
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : "Registration error";
        setError(message);
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    []
  );

  /**
   * Log out user: revokes server-side session, clears HttpOnly cookie, resets in-memory state.
   */
  const logout = useCallback(async (): Promise<void> => {
    setIsLoading(true);
    try {
      await logoutApi();
    } finally {
      setAccessToken(null);
      setUser(null);
      tokenExpiresAtRef.current = null;
      setError(null);
      setIsLoading(false);
    }
  }, []);

  /**
   * Returns current access token if still valid, or refreshes transparently.
   */
  const getValidAccessToken = useCallback(async (): Promise<string | null> => {
    if (
      accessToken &&
      tokenExpiresAtRef.current &&
      Date.now() < tokenExpiresAtRef.current - 10000
    ) {
      return accessToken;
    }
    return await refreshAuth();
  }, [accessToken, refreshAuth]);

  return (
    <AuthContext.Provider
      value={{
        user,
        accessToken,
        isLoading,
        error,
        login,
        register,
        logout,
        refreshAuth,
        getValidAccessToken,
        clearError,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}

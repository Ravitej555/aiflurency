/**
 * ThreatLens AI — Axios API Client
 *
 * Configured with:
 * - Base URL from environment variable
 * - Automatic JWT Bearer token injection from cookies
 * - Response interceptor for 401 token refresh
 * - Typed helper methods for all API endpoints
 */

import axios, { AxiosError, AxiosInstance, AxiosResponse } from "axios";
import Cookies from "js-cookie";
import type {
  LoginCredentials,
  PaginationParams,
  ThreatCreate,
  ThreatEvent,
  ThreatListResponse,
  ThreatStats,
  ThreatUpdate,
  TokenResponse,
  User,
} from "@/types";

// ── Axios Instance ────────────────────────────────────────────────────────────
const apiClient: AxiosInstance = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000",
  timeout: 15_000,
  headers: {
    "Content-Type": "application/json",
    Accept: "application/json",
  },
});

// ── Request Interceptor — Inject Bearer Token ─────────────────────────────────
apiClient.interceptors.request.use((config) => {
  const token = Cookies.get("access_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// ── Response Interceptor — Auto Refresh on 401 ───────────────────────────────
let isRefreshing = false;
let failedQueue: Array<{
  resolve: (value: unknown) => void;
  reject: (reason?: unknown) => void;
}> = [];

const processQueue = (error: AxiosError | null, token: string | null) => {
  failedQueue.forEach(({ resolve, reject }) => {
    if (error) reject(error);
    else resolve(token);
  });
  failedQueue = [];
};

apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as typeof error.config & { _retry?: boolean };

    if (error.response?.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then((token) => {
          if (originalRequest.headers) {
            originalRequest.headers.Authorization = `Bearer ${token}`;
          }
          return apiClient(originalRequest);
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      const refreshToken = Cookies.get("refresh_token");
      if (!refreshToken) {
        auth.clearTokens();
        window.location.href = "/login";
        return Promise.reject(error);
      }

      try {
        const { data } = await axios.post<TokenResponse>(
          `${process.env.NEXT_PUBLIC_API_URL}/api/v1/auth/refresh`,
          { refresh_token: refreshToken }
        );
        auth.storeTokens(data);
        processQueue(null, data.access_token);
        if (originalRequest.headers) {
          originalRequest.headers.Authorization = `Bearer ${data.access_token}`;
        }
        return apiClient(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError as AxiosError, null);
        auth.clearTokens();
        window.location.href = "/login";
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

// ── Auth API ──────────────────────────────────────────────────────────────────
export const auth = {
  storeTokens: (tokens: TokenResponse) => {
    Cookies.set("access_token", tokens.access_token, {
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      expires: tokens.expires_in / 86400,
    });
    Cookies.set("refresh_token", tokens.refresh_token, {
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      expires: 7,
    });
  },

  clearTokens: () => {
    Cookies.remove("access_token");
    Cookies.remove("refresh_token");
  },

  login: async (credentials: LoginCredentials): Promise<TokenResponse> => {
    const params = new URLSearchParams();
    params.append("username", credentials.username);
    params.append("password", credentials.password);

    const { data } = await apiClient.post<TokenResponse>("/api/v1/auth/login", params, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
    auth.storeTokens(data);
    return data;
  },

  me: async (): Promise<User> => {
    const { data } = await apiClient.get<User>("/api/v1/auth/me");
    return data;
  },

  logout: async () => {
    await apiClient.post("/api/v1/auth/logout").catch(() => {});
    auth.clearTokens();
  },
};

// ── Threats API ───────────────────────────────────────────────────────────────
export const threats = {
  list: async (params?: PaginationParams): Promise<ThreatListResponse> => {
    const { data } = await apiClient.get<ThreatListResponse>("/api/v1/threats", { params });
    return data;
  },

  stats: async (): Promise<ThreatStats> => {
    const { data } = await apiClient.get<ThreatStats>("/api/v1/threats/stats");
    return data;
  },

  get: async (id: number): Promise<ThreatEvent> => {
    const { data } = await apiClient.get<ThreatEvent>(`/api/v1/threats/${id}`);
    return data;
  },

  create: async (payload: ThreatCreate): Promise<ThreatEvent> => {
    const { data } = await apiClient.post<ThreatEvent>("/api/v1/threats", payload);
    return data;
  },

  update: async (id: number, payload: ThreatUpdate): Promise<ThreatEvent> => {
    const { data } = await apiClient.patch<ThreatEvent>(`/api/v1/threats/${id}`, payload);
    return data;
  },

  /**
   * Scan a file (real bytes uploaded as multipart) or a URL string.
   * - File mode  → POST /api/v1/threats/scan/upload  (multipart/form-data)
   * - URL mode   → POST /api/v1/threats/scan          (application/json)
   */
  scan: async (
    scan_type: string,
    target_input: string,
    file?: File,
  ): Promise<import("@/types").ScanResultResponse> => {
    if (scan_type === "file" && file) {
      // Real file upload — send actual bytes
      const form = new FormData();
      form.append("file", file);
      const token = Cookies.get("access_token");
      const { data } = await apiClient.post<import("@/types").ScanResultResponse>(
        "/api/v1/threats/scan/upload",
        form,
        {
          headers: {
            "Content-Type": "multipart/form-data",
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
          },
        },
      );
      return data;
    }
    // URL / name-only scan
    const { data } = await apiClient.post<import("@/types").ScanResultResponse>(
      "/api/v1/threats/scan",
      { scan_type, target_input },
    );
    return data;
  },

  delete: async (id: number): Promise<void> => {
    await apiClient.delete(`/api/v1/threats/${id}`);
  },
};

export default apiClient;

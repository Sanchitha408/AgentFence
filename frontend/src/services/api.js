/**
 * Thin fetch wrapper around the local AgentFence API.
 *
 * When the dashboard is served by FastAPI at /ui, requests stay same-origin.
 * When it is served separately (for example `python -m http.server 5173`),
 * requests go to the local backend on port 8000. Nothing leaves the machine.
 */

const params = new URLSearchParams(window.location.search);
const override = params.get("api");

const sameOrigin =
  window.location.pathname.startsWith("/ui") ||
  window.location.port === "8000";

export const API_BASE = override ?? (sameOrigin ? "" : "http://127.0.0.1:8000");

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function request(path, options = {}) {
  const headers = { Accept: "application/json", ...(options.headers || {}) };
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, { ...options, headers });
  } catch (error) {
    throw new ApiError(
      "Could not reach the dashboard API. Is the backend running?",
      0,
    );
  }

  let payload = null;
  const text = await response.text();
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch (error) {
      payload = { detail: text };
    }
  }

  if (!response.ok) {
    const detail =
      payload && typeof payload.detail === "string"
        ? payload.detail
        : `Request failed with status ${response.status}.`;
    throw new ApiError(detail, response.status);
  }

  return payload;
}

export function api(path, options) {
  return request(path, options);
}

/** Fetch something optional, turning any failure into a fallback value. */
export async function optional(path, fallback = null) {
  try {
    return await request(path);
  } catch (error) {
    return fallback;
  }
}

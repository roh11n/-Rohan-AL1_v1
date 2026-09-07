import axios from "axios";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
export const API = `${BACKEND_URL}/api`;

const api = axios.create({ baseURL: API });

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("socpilot_token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err?.response?.status === 401) {
      const path = window.location.pathname;
      if (path !== "/login") {
        localStorage.removeItem("socpilot_token");
        localStorage.removeItem("socpilot_user");
        window.location.href = "/login";
      }
    }
    // Normalize FastAPI 422 validation errors: detail may be an array of
    // objects {type, loc, msg, input, ctx}. Toast/React can't render those.
    const d = err?.response?.data?.detail;
    if (Array.isArray(d)) {
      err.response.data.detail = d.map((x) =>
        x && typeof x === "object" ? (x.msg || JSON.stringify(x)) : String(x)
      ).join("; ");
    } else if (d && typeof d === "object") {
      err.response.data.detail = d.msg || JSON.stringify(d);
    }
    return Promise.reject(err);
  }
);

export default api;

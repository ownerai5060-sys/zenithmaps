/**
 * Thin browser/Node fetch helper for Zenith Maps Platform API (N2).
 *
 * Usage (browser):
 *   const z = new ZenithMaps({ baseUrl: "http://127.0.0.1:8000", apiKey: "..." });
 *   const layers = await z.listLayers();
 *
 * No bundler required. Does not invent tile CDNs — only calls `/api/v1`.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.ZenithMaps = factory().ZenithMaps;
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  class ZenithMaps {
    /**
     * @param {{ baseUrl?: string, apiKey?: string, bearerToken?: string, fetchImpl?: typeof fetch }} opts
     */
    constructor(opts) {
      opts = opts || {};
      this.baseUrl = (opts.baseUrl || "http://127.0.0.1:8000").replace(/\/$/, "");
      this.apiKey = opts.apiKey || null;
      this.bearerToken = opts.bearerToken || null;
      this.fetchImpl = opts.fetchImpl || fetch.bind(globalThis);
    }

    _headers(extra) {
      const headers = Object.assign({ Accept: "application/json" }, extra || {});
      if (this.apiKey) headers["X-API-Key"] = this.apiKey;
      if (this.bearerToken) headers["Authorization"] = "Bearer " + this.bearerToken;
      return headers;
    }

    async _get(path, query) {
      const url = new URL(this.baseUrl + path);
      if (query) {
        Object.keys(query).forEach(function (k) {
          if (query[k] !== undefined && query[k] !== null) {
            url.searchParams.set(k, String(query[k]));
          }
        });
      }
      const res = await this.fetchImpl(url.toString(), { headers: this._headers() });
      if (!res.ok) {
        const body = await res.text();
        const err = new Error("Zenith API " + res.status + ": " + body);
        err.status = res.status;
        throw err;
      }
      const ct = res.headers.get("content-type") || "";
      if (ct.indexOf("application/json") !== -1) return res.json();
      return res.arrayBuffer();
    }

    healthz(checkUpstreams) {
      return this._get("/healthz", { check_upstreams: !!checkUpstreams });
    }

    listLayers() {
      return this._get("/api/v1/layers");
    }

    getLayer(layerId) {
      return this._get("/api/v1/layers/" + encodeURIComponent(layerId));
    }

    getLegend(layerId) {
      return this._get("/api/v1/layers/" + encodeURIComponent(layerId) + "/legend");
    }

    getFeatures(layerId, opts) {
      opts = opts || {};
      return this._get(
        "/api/v1/layers/" + encodeURIComponent(layerId) + "/features",
        { bbox: opts.bbox, limit: opts.limit }
      );
    }

    listTiles() {
      return this._get("/api/v1/tiles");
    }

    getTiles(layerId) {
      return this._get("/api/v1/tiles/" + encodeURIComponent(layerId));
    }
  }

  return { ZenithMaps: ZenithMaps };
});

#!/usr/bin/env node

/**
 * NIST NVD MCP Server v1.1.0
 *
 * This MCP server provides access to the NIST National Vulnerability Database (NVD) API which contains:
 * - Common Vulnerabilities and Exposures (CVE) data with comprehensive filtering
 * - CVE change history tracking for transparency and monitoring
 * - CVSS scoring (v2, v3, v4) and severity-based filtering
 * - CPE-based product vulnerability searches
 * - CPE Dictionary and CPE Match Criteria lookups
 * - CISA Known Exploited Vulnerabilities (KEV) integration
 * - CERT alerts and vulnerability notes
 *
 * The NIST NVD API is free to use but has rate limits:
 *   - 5 requests / 30 seconds without an API key
 *   - 50 requests / 30 seconds with a free API key
 * Set the NVD_API_KEY environment variable to use a key (optional, strongly recommended).
 * Request one at: https://nvd.nist.gov/developers/request-an-api-key
 *
 * API documentation: https://nvd.nist.gov/developers/vulnerabilities
 *                     https://nvd.nist.gov/developers/products
 */

import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import {
  Server,
  ProtocolError,
  ProtocolErrorCode,
} from "@modelcontextprotocol/server";
import axios, { AxiosInstance } from "axios";

interface NVDSearchParams {
  cveId?: string;
  cpeName?: string;
  cweId?: string;
  keywordSearch?: string;
  keywordExactMatch?: boolean;
  cvssV2Metrics?: string;
  cvssV2Severity?: string;
  cvssV3Metrics?: string;
  cvssV3Severity?: string;
  cvssV4Metrics?: string;
  cvssV4Severity?: string;
  hasKev?: boolean;
  hasCertAlerts?: boolean;
  hasCertNotes?: boolean;
  hasOval?: boolean;
  isVulnerable?: boolean;
  noRejected?: boolean;
  cveTag?: string;
  pubStartDate?: string;
  pubEndDate?: string;
  lastModStartDate?: string;
  lastModEndDate?: string;
  sourceIdentifier?: string;
  versionStart?: string;
  versionStartType?: string;
  versionEnd?: string;
  versionEndType?: string;
  virtualMatchString?: string;
  resultsPerPage?: number;
  startIndex?: number;
}

interface NVDChangeHistoryParams {
  cveId?: string;
  changeStartDate?: string;
  changeEndDate?: string;
  eventName?: string;
  resultsPerPage?: number;
  startIndex?: number;
}

// Params for the CPE Dictionary API (/rest/json/cpes/2.0)
interface NVDCPESearchParams {
  cpeNameId?: string;
  cpeMatchString?: string;
  keywordSearch?: string;
  keywordExactMatch?: boolean;
  matchCriteriaId?: string;
  lastModStartDate?: string;
  lastModEndDate?: string;
  resultsPerPage?: number;
  startIndex?: number;
}

// Params for the CPE Match Criteria API (/rest/json/cpematch/2.0)
interface NVDCPEMatchParams {
  matchCriteriaId?: string;
  cveId?: string;
  lastModStartDate?: string;
  lastModEndDate?: string;
  resultsPerPage?: number;
  startIndex?: number;
}

interface CacheEntry {
  data: any;
  timestamp: number;
  ttl: number;
}

interface NVDResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  format: string;
  version: string;
  timestamp: string;
  vulnerabilities?: any[];
  cveChanges?: any[];
  products?: any[];
  matchStrings?: any[];
}

// JSON Schema for a single summarized CVE entry, as produced by formatCVEResponse().
const CVE_SUMMARY_ITEM_SCHEMA = {
  type: "object",
  properties: {
    cve_id: { type: "string" },
    status: { type: "string" },
    published: { type: "string" },
    last_modified: { type: "string" },
    description: { type: "string" },
    cvss: {
      type: "object",
      properties: {
        v3_score: { type: ["number", "null"] },
        v3_severity: { type: ["string", "null"] },
        v2_score: { type: ["number", "null"] },
      },
    },
    weaknesses: {
      type: "array",
      items: { type: "string" },
      description: "First 5 CWE IDs associated with the CVE",
    },
    reference_count: { type: "number" },
    cisa_kev: {
      type: ["object", "null"],
      properties: {
        exploitAdd: { type: "string" },
        actionDue: { type: "string" },
        requiredAction: { type: "string" },
        vulnerabilityName: { type: "string" },
      },
    },
    configurations_count: { type: "number" },
  },
  required: [
    "cve_id",
    "status",
    "published",
    "last_modified",
    "description",
    "cvss",
    "weaknesses",
    "reference_count",
    "configurations_count",
  ],
};

// JSON Schema shared by every tool that returns a paginated list of CVEs
// (search_cves, search_cves_by_cpe, search_cves_by_cvss, search_recent_cves,
// search_modified_cves, search_high_priority_cves), matching formatCVEResponse().
const CVE_LIST_OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    summary: {
      type: "object",
      properties: {
        search_context: { type: "string" },
        total_results: { type: "number" },
        showing_results: { type: "number" },
        results_per_page: { type: "number" },
        start_index: { type: "number" },
        timestamp: { type: "string" },
      },
      required: [
        "search_context",
        "total_results",
        "showing_results",
        "results_per_page",
        "start_index",
        "timestamp",
      ],
    },
    vulnerabilities: {
      type: "array",
      items: CVE_SUMMARY_ITEM_SCHEMA,
    },
    raw_response_metadata: {
      type: "object",
      properties: {
        format: { type: "string" },
        version: { type: "string" },
        has_more_results: { type: "boolean" },
      },
      required: ["format", "version", "has_more_results"],
    },
  },
  required: ["summary", "vulnerabilities", "raw_response_metadata"],
};

// JSON Schema for get_cve, matching the detailed formattedResponse built in getCVE().
const CVE_DETAIL_OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    cve_id: { type: "string" },
    status: { type: "string" },
    published: { type: "string" },
    last_modified: { type: "string" },
    source_identifier: { type: "string" },
    descriptions: {
      type: "array",
      items: { type: "object" },
      description: "Raw NVD description objects ({lang, value})",
    },
    metrics: {
      type: "object",
      description:
        "Raw NVD metrics object (cvssMetricV2/V30/V31 arrays, as provided by the API)",
    },
    weaknesses: {
      type: "array",
      items: { type: "object" },
      description: "Raw NVD weaknesses (CWE) entries",
    },
    configurations: {
      type: "array",
      items: { type: "object" },
      description: "Raw NVD configuration/CPE match entries",
    },
    references: {
      type: "array",
      items: { type: "object" },
      description: "Raw NVD reference entries",
    },
    vendor_comments: {
      type: "array",
      items: { type: "object" },
    },
    cisa_kev_info: {
      type: ["object", "null"],
      properties: {
        exploit_add_date: { type: "string" },
        action_due_date: { type: "string" },
        required_action: { type: "string" },
        vulnerability_name: { type: "string" },
      },
    },
    raw_data: {
      type: "object",
      description: "Full raw NVD API vulnerability record for this CVE",
    },
  },
  required: [
    "cve_id",
    "status",
    "published",
    "last_modified",
    "descriptions",
    "metrics",
    "weaknesses",
    "configurations",
    "references",
    "raw_data",
  ],
};

// JSON Schema for get_cve_change_history, matching formatChangeHistoryResponse().
const CVE_CHANGE_HISTORY_OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    summary: {
      type: "object",
      properties: {
        search_context: { type: "string" },
        total_changes: { type: "number" },
        showing_changes: { type: "number" },
        results_per_page: { type: "number" },
        start_index: { type: "number" },
        timestamp: { type: "string" },
      },
      required: [
        "search_context",
        "total_changes",
        "showing_changes",
        "results_per_page",
        "start_index",
        "timestamp",
      ],
    },
    changes: {
      type: "array",
      items: {
        type: "object",
        properties: {
          cve_id: { type: "string" },
          event_name: { type: "string" },
          change_id: { type: "string" },
          source: { type: "string" },
          created: { type: "string" },
          details_count: { type: "number" },
          sample_details: {
            type: "array",
            items: { type: "object" },
            description: "First 3 raw change detail entries",
          },
        },
        required: [
          "cve_id",
          "event_name",
          "change_id",
          "source",
          "created",
          "details_count",
          "sample_details",
        ],
      },
    },
    raw_response_metadata: {
      type: "object",
      properties: {
        format: { type: "string" },
        version: { type: "string" },
        has_more_results: { type: "boolean" },
      },
      required: ["format", "version", "has_more_results"],
    },
  },
  required: ["summary", "changes", "raw_response_metadata"],
};

// JSON Schema for search_cpe_dictionary, matching formatCPEResponse().
const CPE_LIST_OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    summary: {
      type: "object",
      properties: {
        search_context: { type: "string" },
        total_results: { type: "number" },
        showing_results: { type: "number" },
        results_per_page: { type: "number" },
        start_index: { type: "number" },
        timestamp: { type: "string" },
      },
      required: [
        "search_context",
        "total_results",
        "showing_results",
        "results_per_page",
        "start_index",
        "timestamp",
      ],
    },
    products: {
      type: "array",
      items: {
        type: "object",
        properties: {
          cpe_name: { type: "string" },
          cpe_name_id: { type: "string" },
          deprecated: { type: "boolean" },
          last_modified: { type: "string" },
          created: { type: "string" },
          titles: {
            type: "array",
            items: { type: "object" },
            description: "Raw NVD title entries ({title, lang})",
          },
          refs: {
            type: "array",
            items: { type: "object" },
            description: "Raw NVD reference entries ({ref, type})",
          },
          deprecated_by: {
            type: "array",
            items: { type: "object" },
            description: "CPE names that deprecate this one, if any",
          },
        },
        required: [
          "cpe_name",
          "cpe_name_id",
          "deprecated",
          "last_modified",
          "created",
        ],
      },
    },
    raw_response_metadata: {
      type: "object",
      properties: {
        format: { type: "string" },
        version: { type: "string" },
        has_more_results: { type: "boolean" },
      },
      required: ["format", "version", "has_more_results"],
    },
  },
  required: ["summary", "products", "raw_response_metadata"],
};

// JSON Schema for search_cpe_match_criteria, matching formatCPEMatchResponse().
const CPE_MATCH_LIST_OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    summary: {
      type: "object",
      properties: {
        search_context: { type: "string" },
        total_results: { type: "number" },
        showing_results: { type: "number" },
        results_per_page: { type: "number" },
        start_index: { type: "number" },
        timestamp: { type: "string" },
      },
      required: [
        "search_context",
        "total_results",
        "showing_results",
        "results_per_page",
        "start_index",
        "timestamp",
      ],
    },
    match_criteria: {
      type: "array",
      items: {
        type: "object",
        properties: {
          match_criteria_id: { type: "string" },
          criteria: { type: "string" },
          status: { type: "string" },
          created: { type: "string" },
          last_modified: { type: "string" },
          cpe_last_modified: { type: "string" },
          matches_count: { type: "number" },
          sample_matches: {
            type: "array",
            items: { type: "object" },
            description: "First 5 raw CPE name matches ({cpeName, cpeNameId})",
          },
        },
        required: [
          "match_criteria_id",
          "criteria",
          "status",
          "created",
          "last_modified",
          "matches_count",
          "sample_matches",
        ],
      },
    },
    raw_response_metadata: {
      type: "object",
      properties: {
        format: { type: "string" },
        version: { type: "string" },
        has_more_results: { type: "boolean" },
      },
      required: ["format", "version", "has_more_results"],
    },
  },
  required: ["summary", "match_criteria", "raw_response_metadata"],
};

class NISTNVDServer {
  private server: Server;
  private axiosInstance: AxiosInstance;
  private cache: Map<string, CacheEntry> = new Map();
  private readonly CACHE_TTL = 5 * 60 * 1000; // 5 minutes
  private readonly MAX_RETRIES = 3;
  private readonly RETRY_DELAY = 1000; // 1 second
  private readonly MAX_DATE_RANGE_DAYS = 120;

  constructor() {
    this.server = new Server(
      {
        name: "nist-nvd-mcp-server",
        version: "1.1.0",
      },
      {
        capabilities: {
          tools: {},
        },
      },
    );

    // NIST NVD API configuration.
    // An API key is optional but strongly recommended: it raises the rate limit
    // from 5 requests/30s to 50 requests/30s. Get a free key at
    // https://nvd.nist.gov/developers/request-an-api-key
    const apiKey = process.env.NVD_API_KEY;
    const headers: Record<string, string> = {
      "User-Agent": "NIST-NVD-MCP-Server/1.1.0",
      Accept: "application/json",
    };
    if (apiKey) {
      headers["apiKey"] = apiKey;
    } else {
      console.error(
        "[nist-nvd-mcp-server] No NVD_API_KEY set. Running unauthenticated " +
          "(5 requests/30s limit). Set NVD_API_KEY for a higher limit " +
          "(50 requests/30s) — see https://nvd.nist.gov/developers/request-an-api-key",
      );
    }

    this.axiosInstance = axios.create({
      baseURL: "https://services.nvd.nist.gov/rest/json",
      timeout: 30000,
      headers,
      // NVD's API requires boolean "flag" params (hasKev, hasCertAlerts, hasOval,
      // isVulnerable, keywordExactMatch, noRejected, ...) to be sent as bare flags
      // with NO value at all (e.g. "?hasKev"), never as "?hasKev=true". Sending a
      // value causes NVD to 404. Axios's default serializer would emit
      // "hasKev=true", so every request goes through this custom serializer instead.
      paramsSerializer: {
        serialize: (params: Record<string, any>) =>
          this.serializeNVDParams(params),
      },
    });

    this.setupToolHandlers();

    // Error handling
    this.server.onerror = (error) => console.error("[MCP Error]", error);
    process.on("SIGINT", async () => {
      await this.server.close();
      process.exit(0);
    });

    // Clean up cache periodically
    setInterval(() => this.cleanupCache(), 60000); // Every minute
  }

  // Serializes query params for NVD's API. Boolean `true` values are emitted as
  // bare flags with no "=value" (NVD requires this — see constructor comment).
  // `false`/`null`/`undefined` values are omitted entirely.
  private serializeNVDParams(params: Record<string, any>): string {
    const parts: string[] = [];
    for (const [key, value] of Object.entries(params)) {
      if (value === undefined || value === null || value === false) continue;
      if (value === true) {
        parts.push(encodeURIComponent(key));
      } else {
        parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`);
      }
    }
    return parts.join("&");
  }

  private cleanupCache() {
    const now = Date.now();
    for (const [key, entry] of this.cache.entries()) {
      if (now - entry.timestamp > entry.ttl) {
        this.cache.delete(key);
      }
    }
  }

  private getCachedResponse(key: string): any | null {
    const entry = this.cache.get(key);
    if (!entry) return null;

    const now = Date.now();
    if (now - entry.timestamp > entry.ttl) {
      this.cache.delete(key);
      return null;
    }

    return entry.data;
  }

  private setCachedResponse(key: string, data: any, ttl?: number) {
    this.cache.set(key, {
      data,
      timestamp: Date.now(),
      ttl: ttl || this.CACHE_TTL,
    });
  }

  private validateDateRange(startDate?: string, endDate?: string): void {
    if (startDate && endDate) {
      const start = new Date(startDate);
      const end = new Date(endDate);
      const diffDays = Math.abs(
        (end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24),
      );

      if (diffDays > this.MAX_DATE_RANGE_DAYS) {
        throw new ProtocolError(
          ProtocolErrorCode.InvalidParams,
          `Date range cannot exceed ${this.MAX_DATE_RANGE_DAYS} days. Current range: ${Math.ceil(diffDays)} days`,
        );
      }
    }
  }

  private validateISO8601Date(dateString: string): boolean {
    const iso8601Regex =
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?(Z|[+-]\d{2}:\d{2})?$/;
    return iso8601Regex.test(dateString) && !isNaN(Date.parse(dateString));
  }

  private setupToolHandlers() {
    this.server.setRequestHandler("tools/list", async (): Promise<any> => ({
      tools: [
        {
          name: "search_cves",
          description:
            "Search CVEs with comprehensive filtering options including keywords, CVSS scores, dates, and more",
          inputSchema: {
            type: "object",
            properties: {
              keywordSearch: {
                type: "string",
                description:
                  'Search for keywords in CVE descriptions (e.g., "Microsoft", "remote code execution")',
              },
              keywordExactMatch: {
                type: "boolean",
                description:
                  "If true, search for exact phrase match (requires keywordSearch)",
              },
              cvssV3Severity: {
                type: "string",
                enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                description: "Filter by CVSSv3 severity rating",
              },
              cvssV2Severity: {
                type: "string",
                enum: ["LOW", "MEDIUM", "HIGH"],
                description: "Filter by CVSSv2 severity rating",
              },
              cweId: {
                type: "string",
                description:
                  'Filter by Common Weakness Enumeration ID (e.g., "CWE-79", "CWE-89")',
                pattern: "^CWE-\\d+$",
              },
              hasKev: {
                type: "boolean",
                description:
                  "If true, only return CVEs in CISA's Known Exploited Vulnerabilities catalog",
              },
              hasCertAlerts: {
                type: "boolean",
                description:
                  "If true, only return CVEs with US-CERT Technical Alerts",
              },
              hasCertNotes: {
                type: "boolean",
                description:
                  "If true, only return CVEs with CERT/CC Vulnerability Notes",
              },
              hasOval: {
                type: "boolean",
                description:
                  "If true, only return CVEs with an associated OVAL (Open Vulnerability and Assessment Language) query",
              },
              noRejected: {
                type: "boolean",
                description: "If true, exclude rejected CVEs from results",
              },
              sourceIdentifier: {
                type: "string",
                description:
                  'Filter by the organization that reported/manages the CVE (e.g., "cve@mitre.org", "security-advisories@github.com")',
              },
              cveTag: {
                type: "string",
                enum: [
                  "disputed",
                  "unsupported-when-assigned",
                  "exclusively-hosted-service",
                ],
                description: "Filter by CVE tag applied by the assigning CNA",
              },
              pubStartDate: {
                type: "string",
                description:
                  "Start date for publication range (ISO-8601 format, max 120 day range)",
              },
              pubEndDate: {
                type: "string",
                description:
                  "End date for publication range (ISO-8601 format, required if pubStartDate used)",
              },
              lastModStartDate: {
                type: "string",
                description:
                  "Start date for last modification range (ISO-8601 format, max 120 day range)",
              },
              lastModEndDate: {
                type: "string",
                description:
                  "End date for last modification range (ISO-8601 format, required if lastModStartDate used)",
              },
              resultsPerPage: {
                type: "number",
                description: "Number of results per page (1-2000, default: 20)",
                minimum: 1,
                maximum: 2000,
              },
              startIndex: {
                type: "number",
                description: "Starting index for pagination (0-based)",
                minimum: 0,
              },
            },
          },
          annotations: { readOnlyHint: true, openWorldHint: true },
          outputSchema: CVE_LIST_OUTPUT_SCHEMA,
        },
        {
          name: "get_cve",
          description:
            "Get detailed information about a specific CVE by its ID",
          inputSchema: {
            type: "object",
            properties: {
              cveId: {
                type: "string",
                description: 'CVE identifier (e.g., "CVE-2021-44228")',
                pattern: "^CVE-\\d{4}-\\d{4,}$",
              },
            },
            required: ["cveId"],
          },
          annotations: { readOnlyHint: true, openWorldHint: true },
          outputSchema: CVE_DETAIL_OUTPUT_SCHEMA,
        },
        {
          name: "search_cves_by_cpe",
          description:
            "Find CVEs affecting specific products using Common Platform Enumeration (CPE)",
          inputSchema: {
            type: "object",
            properties: {
              cpeName: {
                type: "string",
                description:
                  'CPE name (e.g., "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")',
              },
              virtualMatchString: {
                type: "string",
                description:
                  'CPE match string for broader searches (e.g., "cpe:2.3:a:apache:*")',
              },
              isVulnerable: {
                type: "boolean",
                description:
                  "If true with cpeName, only return CVEs where the CPE is vulnerable",
              },
              versionStart: {
                type: "string",
                description:
                  "Starting version for range search (requires virtualMatchString)",
              },
              versionStartType: {
                type: "string",
                enum: ["including", "excluding"],
                description: "Whether versionStart is inclusive or exclusive",
              },
              versionEnd: {
                type: "string",
                description:
                  "Ending version for range search (requires virtualMatchString)",
              },
              versionEndType: {
                type: "string",
                enum: ["including", "excluding"],
                description: "Whether versionEnd is inclusive or exclusive",
              },
              resultsPerPage: {
                type: "number",
                description: "Number of results per page (1-2000, default: 20)",
                minimum: 1,
                maximum: 2000,
              },
            },
          },
          annotations: { readOnlyHint: true, openWorldHint: true },
          outputSchema: CVE_LIST_OUTPUT_SCHEMA,
        },
        {
          name: "search_cves_by_cvss",
          description:
            "Search CVEs by CVSS vector strings and severity ratings",
          inputSchema: {
            type: "object",
            properties: {
              cvssV3Metrics: {
                type: "string",
                description:
                  'CVSSv3 vector string (e.g., "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")',
              },
              cvssV3Severity: {
                type: "string",
                enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                description: "CVSSv3 severity rating",
              },
              cvssV2Metrics: {
                type: "string",
                description:
                  'CVSSv2 vector string (e.g., "AV:N/AC:L/Au:N/C:C/I:C/A:C")',
              },
              cvssV2Severity: {
                type: "string",
                enum: ["LOW", "MEDIUM", "HIGH"],
                description: "CVSSv2 severity rating",
              },
              cvssV4Metrics: {
                type: "string",
                description: "CVSSv4 vector string (experimental)",
              },
              cvssV4Severity: {
                type: "string",
                enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                description: "CVSSv4 severity rating",
              },
              resultsPerPage: {
                type: "number",
                description: "Number of results per page (1-2000, default: 20)",
                minimum: 1,
                maximum: 2000,
              },
            },
          },
          annotations: { readOnlyHint: true, openWorldHint: true },
          outputSchema: CVE_LIST_OUTPUT_SCHEMA,
        },
        {
          name: "search_recent_cves",
          description:
            "Get recently published CVEs within a specified date range",
          inputSchema: {
            type: "object",
            properties: {
              pubStartDate: {
                type: "string",
                description:
                  "Start date for publication range (ISO-8601 format)",
              },
              pubEndDate: {
                type: "string",
                description: "End date for publication range (ISO-8601 format)",
              },
              days: {
                type: "number",
                description:
                  "Number of days back from today (alternative to date range, max 120)",
                minimum: 1,
                maximum: 120,
              },
              resultsPerPage: {
                type: "number",
                description: "Number of results per page (1-2000, default: 50)",
                minimum: 1,
                maximum: 2000,
              },
            },
          },
          annotations: { readOnlyHint: true, openWorldHint: true },
          outputSchema: CVE_LIST_OUTPUT_SCHEMA,
        },
        {
          name: "search_modified_cves",
          description:
            "Get CVEs that were recently modified within a specified date range",
          inputSchema: {
            type: "object",
            properties: {
              lastModStartDate: {
                type: "string",
                description:
                  "Start date for modification range (ISO-8601 format)",
              },
              lastModEndDate: {
                type: "string",
                description:
                  "End date for modification range (ISO-8601 format)",
              },
              days: {
                type: "number",
                description:
                  "Number of days back from today (alternative to date range, max 120)",
                minimum: 1,
                maximum: 120,
              },
              resultsPerPage: {
                type: "number",
                description: "Number of results per page (1-2000, default: 50)",
                minimum: 1,
                maximum: 2000,
              },
            },
          },
          annotations: { readOnlyHint: true, openWorldHint: true },
          outputSchema: CVE_LIST_OUTPUT_SCHEMA,
        },
        {
          name: "get_cve_change_history",
          description:
            "Get change history for a specific CVE or all changes within a date range",
          inputSchema: {
            type: "object",
            properties: {
              cveId: {
                type: "string",
                description: "CVE identifier to get change history for",
                pattern: "^CVE-\\d{4}-\\d{4,}$",
              },
              changeStartDate: {
                type: "string",
                description:
                  "Start date for change range (ISO-8601 format, max 120 day range)",
              },
              changeEndDate: {
                type: "string",
                description:
                  "End date for change range (ISO-8601 format, required if changeStartDate used)",
              },
              eventName: {
                type: "string",
                enum: [
                  "CVE Received",
                  "Initial Analysis",
                  "Reanalysis",
                  "CVE Modified",
                  "Modified Analysis",
                  "CVE Translated",
                  "Vendor Comment",
                  "CVE Source Update",
                  "CPE Deprecation Remap",
                  "CWE Remap",
                  "Reference Tag Update",
                  "CVE Rejected",
                  "CVE Unrejected",
                  "CVE CISA KEV Update",
                ],
                description: "Filter by specific type of change event",
              },
              resultsPerPage: {
                type: "number",
                description:
                  "Number of results per page (1-5000, default: 100)",
                minimum: 1,
                maximum: 5000,
              },
            },
          },
          annotations: { readOnlyHint: true, openWorldHint: true },
          outputSchema: CVE_CHANGE_HISTORY_OUTPUT_SCHEMA,
        },
        {
          name: "search_high_priority_cves",
          description:
            "Search for high-priority CVEs using multiple risk indicators",
          inputSchema: {
            type: "object",
            properties: {
              includeKev: {
                type: "boolean",
                description:
                  "Include CISA Known Exploited Vulnerabilities (default: true)",
              },
              includeCertAlerts: {
                type: "boolean",
                description:
                  "Include CVEs with US-CERT Technical Alerts (default: true)",
              },
              includeCriticalCvss: {
                type: "boolean",
                description:
                  "Include CVEs with CRITICAL CVSSv3 severity (default: true)",
              },
              minCvssScore: {
                type: "number",
                description:
                  "Minimum CVSS score threshold (0-10, default: 7.0)",
                minimum: 0,
                maximum: 10,
              },
              keywordSearch: {
                type: "string",
                description:
                  "Additional keyword filter for high-priority search",
              },
              days: {
                type: "number",
                description:
                  "Look for high-priority CVEs from the last N days (max 120)",
                minimum: 1,
                maximum: 120,
              },
              resultsPerPage: {
                type: "number",
                description: "Number of results per page (1-2000, default: 50)",
                minimum: 1,
                maximum: 2000,
              },
            },
          },
          annotations: { readOnlyHint: true, openWorldHint: true },
          outputSchema: CVE_LIST_OUTPUT_SCHEMA,
        },
        {
          name: "search_cpe_dictionary",
          description:
            "Browse or search the official CPE (Common Platform Enumeration) Dictionary to find canonical product/version identifiers",
          inputSchema: {
            type: "object",
            properties: {
              cpeNameId: {
                type: "string",
                description:
                  "Return a specific CPE record by its UUID (e.g., \"82F877C8-FC1D-4790-A6AC-FC89556011C5\")",
              },
              cpeMatchString: {
                type: "string",
                description:
                  'CPE match string in CPEv2.3 format to search the dictionary (e.g., "cpe:2.3:a:apache:log4j")',
              },
              keywordSearch: {
                type: "string",
                description:
                  'Search for keywords in CPE titles/references (e.g., "log4j", "Microsoft Windows 10")',
              },
              keywordExactMatch: {
                type: "boolean",
                description:
                  "If true, search for exact phrase match (requires keywordSearch)",
              },
              matchCriteriaId: {
                type: "string",
                description:
                  "Return CPEs associated with a specific CPE Match Criteria UUID",
              },
              lastModStartDate: {
                type: "string",
                description:
                  "Start date for last modification range (ISO-8601 format, max 120 day range)",
              },
              lastModEndDate: {
                type: "string",
                description:
                  "End date for last modification range (ISO-8601 format, required if lastModStartDate used)",
              },
              resultsPerPage: {
                type: "number",
                description:
                  "Number of results per page (1-10000, default: 20)",
                minimum: 1,
                maximum: 10000,
              },
              startIndex: {
                type: "number",
                description: "Starting index for pagination (0-based)",
                minimum: 0,
              },
            },
          },
          annotations: { readOnlyHint: true, openWorldHint: true },
          outputSchema: CPE_LIST_OUTPUT_SCHEMA,
        },
        {
          name: "search_cpe_match_criteria",
          description:
            "Search the CPE Match Criteria API to see the version-range matching rules NVD uses to link CVEs to CPEs",
          inputSchema: {
            type: "object",
            properties: {
              matchCriteriaId: {
                type: "string",
                description: "Return a specific Match Criteria record by its UUID",
              },
              cveId: {
                type: "string",
                description:
                  'Return match criteria referenced by a specific CVE (e.g., "CVE-2021-44228")',
                pattern: "^CVE-\\d{4}-\\d{4,}$",
              },
              lastModStartDate: {
                type: "string",
                description:
                  "Start date for last modification range (ISO-8601 format, max 120 day range)",
              },
              lastModEndDate: {
                type: "string",
                description:
                  "End date for last modification range (ISO-8601 format, required if lastModStartDate used)",
              },
              resultsPerPage: {
                type: "number",
                description:
                  "Number of results per page (1-5000, default: 20)",
                minimum: 1,
                maximum: 5000,
              },
              startIndex: {
                type: "number",
                description: "Starting index for pagination (0-based)",
                minimum: 0,
              },
            },
          },
          annotations: { readOnlyHint: true, openWorldHint: true },
          outputSchema: CPE_MATCH_LIST_OUTPUT_SCHEMA,
        },
      ],
    }));

    this.server.setRequestHandler(
      "tools/call",
      async (request): Promise<any> => {
        try {
          switch (request.params.name) {
            case "search_cves":
              return await this.searchCVEs(request.params.arguments);
            case "get_cve":
              return await this.getCVE(request.params.arguments);
            case "search_cves_by_cpe":
              return await this.searchCVEsByCPE(request.params.arguments);
            case "search_cves_by_cvss":
              return await this.searchCVEsByCVSS(request.params.arguments);
            case "search_recent_cves":
              return await this.searchRecentCVEs(request.params.arguments);
            case "search_modified_cves":
              return await this.searchModifiedCVEs(request.params.arguments);
            case "get_cve_change_history":
              return await this.getCVEChangeHistory(request.params.arguments);
            case "search_high_priority_cves":
              return await this.searchHighPriorityCVEs(
                request.params.arguments,
              );
            case "search_cpe_dictionary":
              return await this.searchCPEDictionary(request.params.arguments);
            case "search_cpe_match_criteria":
              return await this.searchCPEMatchCriteria(
                request.params.arguments,
              );
            default:
              throw new ProtocolError(
                ProtocolErrorCode.MethodNotFound,
                `Unknown tool: ${request.params.name}`,
              );
          }
        } catch (error: unknown) {
          if (axios.isAxiosError(error)) {
            const statusCode = error.response?.status;
            const errorMessage = error.response?.data?.message || error.message;

            if (statusCode === 404) {
              return {
                content: [
                  {
                    type: "text",
                    text: `Resource not found. Please verify the parameters and try again.`,
                  },
                ],
                isError: true,
              };
            }

            if (statusCode === 429) {
              return {
                content: [
                  {
                    type: "text",
                    text: `Rate limit exceeded. The NVD API is experiencing high load. Please wait and try again.`,
                  },
                ],
                isError: true,
              };
            }

            if (statusCode === 400) {
              return {
                content: [
                  {
                    type: "text",
                    text: `Invalid request parameters: ${errorMessage}`,
                  },
                ],
                isError: true,
              };
            }

            if (error.code === "ECONNABORTED") {
              return {
                content: [
                  {
                    type: "text",
                    text: `Request timed out. The NVD API may be experiencing high load.`,
                  },
                ],
                isError: true,
              };
            }

            return {
              content: [
                {
                  type: "text",
                  text: `NIST NVD API error (${statusCode}): ${errorMessage}`,
                },
              ],
              isError: true,
            };
          }

          throw error;
        }
      },
    );
  }

  private async makeNVDRequestWithRetry(
    endpoint: string,
    params: any = {},
    useCache = true,
  ): Promise<NVDResponse> {
    const cacheKey = `${endpoint}_${JSON.stringify(params)}`;

    // Check cache first
    if (useCache) {
      const cached = this.getCachedResponse(cacheKey);
      if (cached) {
        return cached;
      }
    }

    let lastError: any;
    for (let attempt = 1; attempt <= this.MAX_RETRIES; attempt++) {
      try {
        const response = await this.axiosInstance.get(endpoint, { params });
        const data = response.data;

        // Cache the response
        if (useCache) {
          this.setCachedResponse(cacheKey, data);
        }

        return data;
      } catch (error) {
        lastError = error;
        if (
          attempt < this.MAX_RETRIES &&
          axios.isAxiosError(error) &&
          error.response?.status !== 404
        ) {
          await new Promise((resolve) =>
            setTimeout(resolve, this.RETRY_DELAY * attempt),
          );
          continue;
        }
        throw error;
      }
    }
    throw lastError;
  }

  private formatCVEResponse(data: NVDResponse, context: string = "") {
    if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
      return {
        content: [
          {
            type: "text",
            text: `No CVEs found${context ? ` ${context}` : ""}.`,
          },
        ],
      };
    }

    const summary = {
      search_context: context,
      total_results: data.totalResults,
      showing_results: data.vulnerabilities.length,
      results_per_page: data.resultsPerPage,
      start_index: data.startIndex,
      timestamp: data.timestamp,
    };

    // Extract key metrics from results
    const cves = data.vulnerabilities.map((vuln) => {
      const cve = vuln.cve;
      const cveId = cve.id;
      const published = cve.published;
      const lastModified = cve.lastModified;
      const vulnStatus = cve.vulnStatus;

      // Extract descriptions
      const descriptions = cve.descriptions || [];
      const primaryDesc =
        descriptions.find((d: any) => d.lang === "en")?.value ||
        "No description available";

      // Extract CVSS scores
      const metrics = cve.metrics || {};
      let cvssV3Score = null;
      let cvssV3Severity = null;
      let cvssV2Score = null;

      if (metrics.cvssMetricV31 && metrics.cvssMetricV31.length > 0) {
        const cvss = metrics.cvssMetricV31[0].cvssData;
        cvssV3Score = cvss.baseScore;
        cvssV3Severity = cvss.baseSeverity;
      } else if (metrics.cvssMetricV30 && metrics.cvssMetricV30.length > 0) {
        const cvss = metrics.cvssMetricV30[0].cvssData;
        cvssV3Score = cvss.baseScore;
        cvssV3Severity = cvss.baseSeverity;
      }

      if (metrics.cvssMetricV2 && metrics.cvssMetricV2.length > 0) {
        cvssV2Score = metrics.cvssMetricV2[0].cvssData.baseScore;
      }

      // Extract weaknesses (CWE)
      const weaknesses = cve.weaknesses || [];
      const cweIds = weaknesses.flatMap((w: any) =>
        w.description
          .map((d: any) => d.value)
          .filter((v: any) => v.startsWith("CWE-")),
      );

      // Extract references
      const references = cve.references || [];
      const referenceCount = references.length;

      // Check for special flags
      const cisaKev = cve.cisaExploitAdd
        ? {
            exploitAdd: cve.cisaExploitAdd,
            actionDue: cve.cisaActionDue,
            requiredAction: cve.cisaRequiredAction,
            vulnerabilityName: cve.cisaVulnerabilityName,
          }
        : null;

      return {
        cve_id: cveId,
        status: vulnStatus,
        published: published,
        last_modified: lastModified,
        description:
          primaryDesc.length > 200
            ? primaryDesc.substring(0, 200) + "..."
            : primaryDesc,
        cvss: {
          v3_score: cvssV3Score,
          v3_severity: cvssV3Severity,
          v2_score: cvssV2Score,
        },
        weaknesses: cweIds.slice(0, 5), // Show first 5 CWEs
        reference_count: referenceCount,
        cisa_kev: cisaKev,
        configurations_count: cve.configurations?.length || 0,
      };
    });

    const formattedResponse = {
      summary,
      vulnerabilities: cves,
      raw_response_metadata: {
        format: data.format,
        version: data.version,
        has_more_results:
          data.totalResults > data.startIndex + data.resultsPerPage,
      },
    };

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(formattedResponse, null, 2),
        },
      ],
      structuredContent: formattedResponse,
    };
  }

  private formatChangeHistoryResponse(data: NVDResponse, context: string = "") {
    if (!data.cveChanges || data.cveChanges.length === 0) {
      return {
        content: [
          {
            type: "text",
            text: `No change history found${context ? ` ${context}` : ""}.`,
          },
        ],
      };
    }

    const summary = {
      search_context: context,
      total_changes: data.totalResults,
      showing_changes: data.cveChanges.length,
      results_per_page: data.resultsPerPage,
      start_index: data.startIndex,
      timestamp: data.timestamp,
    };

    const changes = data.cveChanges.map((changeWrapper) => {
      const change = changeWrapper.change;
      return {
        cve_id: change.cveId,
        event_name: change.eventName,
        change_id: change.cveChangeId,
        source: change.sourceIdentifier,
        created: change.created,
        details_count: change.details.length,
        sample_details: change.details.slice(0, 3), // Show first 3 details
      };
    });

    const formattedResponse = {
      summary,
      changes,
      raw_response_metadata: {
        format: data.format,
        version: data.version,
        has_more_results:
          data.totalResults > data.startIndex + data.resultsPerPage,
      },
    };

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(formattedResponse, null, 2),
        },
      ],
      structuredContent: formattedResponse,
    };
  }

  private formatCPEResponse(data: NVDResponse, context: string = "") {
    if (!data.products || data.products.length === 0) {
      return {
        content: [
          {
            type: "text",
            text: `No CPE records found${context ? ` ${context}` : ""}.`,
          },
        ],
      };
    }

    const summary = {
      search_context: context,
      total_results: data.totalResults,
      showing_results: data.products.length,
      results_per_page: data.resultsPerPage,
      start_index: data.startIndex,
      timestamp: data.timestamp,
    };

    const products = data.products.map((productWrapper) => {
      const cpe = productWrapper.cpe;
      return {
        cpe_name: cpe.cpeName,
        cpe_name_id: cpe.cpeNameId,
        deprecated: !!cpe.deprecated,
        last_modified: cpe.lastModified,
        created: cpe.created,
        titles: cpe.titles || [],
        refs: cpe.refs || [],
        deprecated_by: cpe.deprecatedBy || [],
      };
    });

    const formattedResponse = {
      summary,
      products,
      raw_response_metadata: {
        format: data.format,
        version: data.version,
        has_more_results:
          data.totalResults > data.startIndex + data.resultsPerPage,
      },
    };

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(formattedResponse, null, 2),
        },
      ],
      structuredContent: formattedResponse,
    };
  }

  private formatCPEMatchResponse(data: NVDResponse, context: string = "") {
    if (!data.matchStrings || data.matchStrings.length === 0) {
      return {
        content: [
          {
            type: "text",
            text: `No CPE match criteria found${context ? ` ${context}` : ""}.`,
          },
        ],
      };
    }

    const summary = {
      search_context: context,
      total_results: data.totalResults,
      showing_results: data.matchStrings.length,
      results_per_page: data.resultsPerPage,
      start_index: data.startIndex,
      timestamp: data.timestamp,
    };

    const matchCriteria = data.matchStrings.map((wrapper) => {
      const match = wrapper.matchString;
      const matches = match.matches || [];
      return {
        match_criteria_id: match.matchCriteriaId,
        criteria: match.criteria,
        status: match.status,
        created: match.created,
        last_modified: match.lastModified,
        cpe_last_modified: match.cpeLastModified,
        matches_count: matches.length,
        sample_matches: matches.slice(0, 5),
      };
    });

    const formattedResponse = {
      summary,
      match_criteria: matchCriteria,
      raw_response_metadata: {
        format: data.format,
        version: data.version,
        has_more_results:
          data.totalResults > data.startIndex + data.resultsPerPage,
      },
    };

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(formattedResponse, null, 2),
        },
      ],
      structuredContent: formattedResponse,
    };
  }

  private async searchCVEs(args: any) {
    const params: NVDSearchParams = {};

    if (args.keywordSearch) {
      params.keywordSearch = String(args.keywordSearch);
      if (args.keywordExactMatch) {
        params.keywordExactMatch = true;
      }
    }

    if (args.cvssV3Severity)
      params.cvssV3Severity = String(args.cvssV3Severity);
    if (args.cvssV2Severity)
      params.cvssV2Severity = String(args.cvssV2Severity);
    if (args.cweId) params.cweId = String(args.cweId);
    if (args.hasKev) params.hasKev = true;
    if (args.hasCertAlerts) params.hasCertAlerts = true;
    if (args.hasCertNotes) params.hasCertNotes = true;
    if (args.hasOval) params.hasOval = true;
    if (args.noRejected) params.noRejected = true;
    if (args.sourceIdentifier)
      params.sourceIdentifier = String(args.sourceIdentifier);
    if (args.cveTag) params.cveTag = String(args.cveTag);

    // Handle date ranges
    if (args.pubStartDate && args.pubEndDate) {
      this.validateDateRange(args.pubStartDate, args.pubEndDate);
      params.pubStartDate = String(args.pubStartDate);
      params.pubEndDate = String(args.pubEndDate);
    }

    if (args.lastModStartDate && args.lastModEndDate) {
      this.validateDateRange(args.lastModStartDate, args.lastModEndDate);
      params.lastModStartDate = String(args.lastModStartDate);
      params.lastModEndDate = String(args.lastModEndDate);
    }

    params.resultsPerPage = Math.min(Number(args.resultsPerPage || 20), 2000);
    if (args.startIndex) params.startIndex = Number(args.startIndex);

    const data = await this.makeNVDRequestWithRetry("/cves/2.0", params);
    return this.formatCVEResponse(data, "for search criteria");
  }

  private async getCVE(args: any) {
    const cveId = String(args?.cveId || "").toUpperCase();

    if (!cveId.match(/^CVE-\d{4}-\d{4,}$/)) {
      throw new ProtocolError(
        ProtocolErrorCode.InvalidParams,
        "Invalid CVE ID format. Expected format: CVE-YYYY-NNNN (e.g., CVE-2021-44228)",
      );
    }

    const params: NVDSearchParams = { cveId };
    const data = await this.makeNVDRequestWithRetry("/cves/2.0", params);

    if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
      return {
        content: [
          {
            type: "text",
            text: `CVE ${cveId} not found in the NVD database.`,
          },
        ],
      };
    }

    // Return detailed information for single CVE
    const vuln = data.vulnerabilities[0];
    const cve = vuln.cve;

    const formattedResponse = {
      cve_id: cve.id,
      status: cve.vulnStatus,
      published: cve.published,
      last_modified: cve.lastModified,
      source_identifier: cve.sourceIdentifier,

      descriptions: cve.descriptions || [],

      metrics: cve.metrics || {},

      weaknesses: cve.weaknesses || [],

      configurations: cve.configurations || [],

      references: cve.references || [],

      vendor_comments: cve.vendorComments || [],

      cisa_kev_info: cve.cisaExploitAdd
        ? {
            exploit_add_date: cve.cisaExploitAdd,
            action_due_date: cve.cisaActionDue,
            required_action: cve.cisaRequiredAction,
            vulnerability_name: cve.cisaVulnerabilityName,
          }
        : null,

      raw_data: vuln,
    };

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(formattedResponse, null, 2),
        },
      ],
      structuredContent: formattedResponse,
    };
  }

  private async searchCVEsByCPE(args: any) {
    const params: NVDSearchParams = {};

    if (args.cpeName) {
      params.cpeName = String(args.cpeName);
      if (args.isVulnerable) {
        params.isVulnerable = true;
      }
    }

    if (args.virtualMatchString) {
      params.virtualMatchString = String(args.virtualMatchString);

      if (args.versionStart) {
        params.versionStart = String(args.versionStart);
        params.versionStartType = String(args.versionStartType || "including");
      }

      if (args.versionEnd) {
        params.versionEnd = String(args.versionEnd);
        params.versionEndType = String(args.versionEndType || "excluding");
      }
    }

    if (!params.cpeName && !params.virtualMatchString) {
      throw new ProtocolError(
        ProtocolErrorCode.InvalidParams,
        "Either cpeName or virtualMatchString is required",
      );
    }

    params.resultsPerPage = Math.min(Number(args.resultsPerPage || 20), 2000);

    const data = await this.makeNVDRequestWithRetry("/cves/2.0", params);
    const context = `for CPE: ${params.cpeName || params.virtualMatchString}`;
    return this.formatCVEResponse(data, context);
  }

  private async searchCVEsByCVSS(args: any) {
    const params: NVDSearchParams = {};

    if (args.cvssV3Metrics) params.cvssV3Metrics = String(args.cvssV3Metrics);
    if (args.cvssV3Severity)
      params.cvssV3Severity = String(args.cvssV3Severity);
    if (args.cvssV2Metrics) params.cvssV2Metrics = String(args.cvssV2Metrics);
    if (args.cvssV2Severity)
      params.cvssV2Severity = String(args.cvssV2Severity);
    if (args.cvssV4Metrics) params.cvssV4Metrics = String(args.cvssV4Metrics);
    if (args.cvssV4Severity)
      params.cvssV4Severity = String(args.cvssV4Severity);

    // Check for conflicting CVSS version parameters
    const cvssVersions = [
      args.cvssV2Metrics || args.cvssV2Severity,
      args.cvssV3Metrics || args.cvssV3Severity,
      args.cvssV4Metrics || args.cvssV4Severity,
    ].filter(Boolean);

    if (cvssVersions.length > 1) {
      throw new ProtocolError(
        ProtocolErrorCode.InvalidParams,
        "Cannot specify multiple CVSS version parameters in the same request",
      );
    }

    if (cvssVersions.length === 0) {
      throw new ProtocolError(
        ProtocolErrorCode.InvalidParams,
        "At least one CVSS parameter is required",
      );
    }

    params.resultsPerPage = Math.min(Number(args.resultsPerPage || 20), 2000);

    const data = await this.makeNVDRequestWithRetry("/cves/2.0", params);
    const context = "matching CVSS criteria";
    return this.formatCVEResponse(data, context);
  }

  private async searchRecentCVEs(args: any) {
    const params: NVDSearchParams = {};

    if (args.days) {
      const days = Number(args.days);
      if (days > 120) {
        throw new ProtocolError(
          ProtocolErrorCode.InvalidParams,
          "Days parameter cannot exceed 120",
        );
      }

      const endDate = new Date();
      const startDate = new Date();
      startDate.setDate(endDate.getDate() - days);

      params.pubStartDate = startDate.toISOString();
      params.pubEndDate = endDate.toISOString();
    } else if (args.pubStartDate && args.pubEndDate) {
      this.validateDateRange(args.pubStartDate, args.pubEndDate);
      params.pubStartDate = String(args.pubStartDate);
      params.pubEndDate = String(args.pubEndDate);
    } else {
      // Default to last 7 days
      const endDate = new Date();
      const startDate = new Date();
      startDate.setDate(endDate.getDate() - 7);

      params.pubStartDate = startDate.toISOString();
      params.pubEndDate = endDate.toISOString();
    }

    params.resultsPerPage = Math.min(Number(args.resultsPerPage || 50), 2000);

    const data = await this.makeNVDRequestWithRetry("/cves/2.0", params);
    const context = `published between ${params.pubStartDate} and ${params.pubEndDate}`;
    return this.formatCVEResponse(data, context);
  }

  private async searchModifiedCVEs(args: any) {
    const params: NVDSearchParams = {};

    if (args.days) {
      const days = Number(args.days);
      if (days > 120) {
        throw new ProtocolError(
          ProtocolErrorCode.InvalidParams,
          "Days parameter cannot exceed 120",
        );
      }

      const endDate = new Date();
      const startDate = new Date();
      startDate.setDate(endDate.getDate() - days);

      params.lastModStartDate = startDate.toISOString();
      params.lastModEndDate = endDate.toISOString();
    } else if (args.lastModStartDate && args.lastModEndDate) {
      this.validateDateRange(args.lastModStartDate, args.lastModEndDate);
      params.lastModStartDate = String(args.lastModStartDate);
      params.lastModEndDate = String(args.lastModEndDate);
    } else {
      // Default to last 7 days
      const endDate = new Date();
      const startDate = new Date();
      startDate.setDate(endDate.getDate() - 7);

      params.lastModStartDate = startDate.toISOString();
      params.lastModEndDate = endDate.toISOString();
    }

    params.resultsPerPage = Math.min(Number(args.resultsPerPage || 50), 2000);

    const data = await this.makeNVDRequestWithRetry("/cves/2.0", params);
    const context = `modified between ${params.lastModStartDate} and ${params.lastModEndDate}`;
    return this.formatCVEResponse(data, context);
  }

  private async getCVEChangeHistory(args: any) {
    const params: NVDChangeHistoryParams = {};

    if (args.cveId) {
      const cveId = String(args.cveId).toUpperCase();
      if (!cveId.match(/^CVE-\d{4}-\d{4,}$/)) {
        throw new ProtocolError(
          ProtocolErrorCode.InvalidParams,
          "Invalid CVE ID format. Expected format: CVE-YYYY-NNNN",
        );
      }
      params.cveId = cveId;
    }

    if (args.changeStartDate && args.changeEndDate) {
      this.validateDateRange(args.changeStartDate, args.changeEndDate);
      params.changeStartDate = String(args.changeStartDate);
      params.changeEndDate = String(args.changeEndDate);
    }

    if (args.eventName) {
      params.eventName = String(args.eventName);
    }

    params.resultsPerPage = Math.min(Number(args.resultsPerPage || 100), 5000);

    const data = await this.makeNVDRequestWithRetry("/cvehistory/2.0", params);
    let context = "change history";
    if (params.cveId) context += ` for ${params.cveId}`;
    if (params.eventName) context += ` (${params.eventName} events)`;

    return this.formatChangeHistoryResponse(data, context);
  }

  private async searchHighPriorityCVEs(args: any) {
    const includeKev = args.includeKev !== false; // Default true
    const includeCertAlerts = args.includeCertAlerts !== false; // Default true
    const includeCriticalCvss = args.includeCriticalCvss !== false; // Default true
    const minCvssScore = args.minCvssScore || 7.0;

    // We'll need to make multiple requests for different criteria and combine results
    const allResults: any[] = [];
    let totalResults = 0;
    const resultsPerPage = Math.min(Number(args.resultsPerPage || 50), 2000);

    let dateParams = {};
    if (args.days) {
      const days = Number(args.days);
      if (days > 120) {
        throw new ProtocolError(
          ProtocolErrorCode.InvalidParams,
          "Days parameter cannot exceed 120",
        );
      }

      const endDate = new Date();
      const startDate = new Date();
      startDate.setDate(endDate.getDate() - days);

      dateParams = {
        pubStartDate: startDate.toISOString(),
        pubEndDate: endDate.toISOString(),
      };
    }

    const searchPromises = [];

    // Search for CISA KEV CVEs
    if (includeKev) {
      const kevParams: any = {
        hasKev: true,
        resultsPerPage: Math.floor(resultsPerPage / 3),
        ...dateParams,
      };
      if (args.keywordSearch)
        kevParams.keywordSearch = String(args.keywordSearch);
      searchPromises.push(this.makeNVDRequestWithRetry("/cves/2.0", kevParams));
    }

    // Search for CERT Alert CVEs
    if (includeCertAlerts) {
      const certParams: any = {
        hasCertAlerts: true,
        resultsPerPage: Math.floor(resultsPerPage / 3),
        ...dateParams,
      };
      if (args.keywordSearch)
        certParams.keywordSearch = String(args.keywordSearch);
      searchPromises.push(
        this.makeNVDRequestWithRetry("/cves/2.0", certParams),
      );
    }

    // Search for Critical CVSS CVEs
    if (includeCriticalCvss) {
      const cvssParams: any = {
        cvssV3Severity: "CRITICAL",
        resultsPerPage: Math.floor(resultsPerPage / 3),
        ...dateParams,
      };
      if (args.keywordSearch)
        cvssParams.keywordSearch = String(args.keywordSearch);
      searchPromises.push(
        this.makeNVDRequestWithRetry("/cves/2.0", cvssParams),
      );
    }

    try {
      const results = await Promise.all(searchPromises);

      // Combine and deduplicate results
      const seenCVEs = new Set();
      for (const result of results) {
        if (result.vulnerabilities) {
          for (const vuln of result.vulnerabilities) {
            const cveId = vuln.cve.id;
            if (!seenCVEs.has(cveId)) {
              // Apply additional CVSS score filtering if specified
              let includeVuln = true;
              if (minCvssScore > 0) {
                const metrics = vuln.cve.metrics || {};
                let maxScore = 0;

                if (metrics.cvssMetricV31 && metrics.cvssMetricV31.length > 0) {
                  maxScore = Math.max(
                    maxScore,
                    metrics.cvssMetricV31[0].cvssData.baseScore,
                  );
                }
                if (metrics.cvssMetricV30 && metrics.cvssMetricV30.length > 0) {
                  maxScore = Math.max(
                    maxScore,
                    metrics.cvssMetricV30[0].cvssData.baseScore,
                  );
                }
                if (metrics.cvssMetricV2 && metrics.cvssMetricV2.length > 0) {
                  maxScore = Math.max(
                    maxScore,
                    metrics.cvssMetricV2[0].cvssData.baseScore,
                  );
                }

                includeVuln = maxScore >= minCvssScore;
              }

              if (includeVuln) {
                seenCVEs.add(cveId);
                allResults.push(vuln);
                totalResults++;
              }
            }
          }
        }
      }

      // Sort by CVSS score (highest first) and published date (newest first)
      allResults.sort((a, b) => {
        const aMetrics = a.cve.metrics || {};
        const bMetrics = b.cve.metrics || {};

        let aScore = 0;
        let bScore = 0;

        if (aMetrics.cvssMetricV31 && aMetrics.cvssMetricV31.length > 0) {
          aScore = aMetrics.cvssMetricV31[0].cvssData.baseScore;
        }
        if (bMetrics.cvssMetricV31 && bMetrics.cvssMetricV31.length > 0) {
          bScore = bMetrics.cvssMetricV31[0].cvssData.baseScore;
        }

        if (aScore !== bScore) {
          return bScore - aScore; // Higher score first
        }

        // If scores are equal, sort by published date (newer first)
        return (
          new Date(b.cve.published).getTime() -
          new Date(a.cve.published).getTime()
        );
      });

      // Limit results to requested page size
      const limitedResults = allResults.slice(0, resultsPerPage);

      const mockResponse: NVDResponse = {
        resultsPerPage: resultsPerPage,
        startIndex: 0,
        totalResults: totalResults,
        format: "NVD_CVE",
        version: "2.0",
        timestamp: new Date().toISOString(),
        vulnerabilities: limitedResults,
      };

      let context = "high-priority CVEs";
      const criteria = [];
      if (includeKev) criteria.push("CISA KEV");
      if (includeCertAlerts) criteria.push("CERT Alerts");
      if (includeCriticalCvss) criteria.push("Critical CVSS");
      if (criteria.length > 0) context += ` (${criteria.join(", ")})`;
      if (minCvssScore > 0) context += ` with CVSS ≥ ${minCvssScore}`;

      return this.formatCVEResponse(mockResponse, context);
    } catch (error) {
      throw new ProtocolError(
        ProtocolErrorCode.InternalError,
        `Failed to search high-priority CVEs: ${error}`,
      );
    }
  }

  private async searchCPEDictionary(args: any) {
    const params: NVDCPESearchParams = {};

    if (args.cpeNameId) params.cpeNameId = String(args.cpeNameId);
    if (args.cpeMatchString)
      params.cpeMatchString = String(args.cpeMatchString);

    if (args.keywordSearch) {
      params.keywordSearch = String(args.keywordSearch);
      if (args.keywordExactMatch) {
        params.keywordExactMatch = true;
      }
    }

    if (args.matchCriteriaId)
      params.matchCriteriaId = String(args.matchCriteriaId);

    if (args.lastModStartDate && args.lastModEndDate) {
      this.validateDateRange(args.lastModStartDate, args.lastModEndDate);
      params.lastModStartDate = String(args.lastModStartDate);
      params.lastModEndDate = String(args.lastModEndDate);
    }

    params.resultsPerPage = Math.min(
      Number(args.resultsPerPage || 20),
      10000,
    );
    if (args.startIndex) params.startIndex = Number(args.startIndex);

    const data = await this.makeNVDRequestWithRetry("/cpes/2.0", params);
    const context = params.cpeNameId
      ? `for CPE Name ID: ${params.cpeNameId}`
      : params.cpeMatchString
        ? `for CPE match string: ${params.cpeMatchString}`
        : params.keywordSearch
          ? `for keyword: ${params.keywordSearch}`
          : "in the CPE dictionary";
    return this.formatCPEResponse(data, context);
  }

  private async searchCPEMatchCriteria(args: any) {
    const params: NVDCPEMatchParams = {};

    if (args.matchCriteriaId)
      params.matchCriteriaId = String(args.matchCriteriaId);

    if (args.cveId) {
      const cveId = String(args.cveId).toUpperCase();
      if (!cveId.match(/^CVE-\d{4}-\d{4,}$/)) {
        throw new ProtocolError(
          ProtocolErrorCode.InvalidParams,
          "Invalid CVE ID format. Expected format: CVE-YYYY-NNNN",
        );
      }
      params.cveId = cveId;
    }

    if (args.lastModStartDate && args.lastModEndDate) {
      this.validateDateRange(args.lastModStartDate, args.lastModEndDate);
      params.lastModStartDate = String(args.lastModStartDate);
      params.lastModEndDate = String(args.lastModEndDate);
    }

    params.resultsPerPage = Math.min(Number(args.resultsPerPage || 20), 5000);
    if (args.startIndex) params.startIndex = Number(args.startIndex);

    const data = await this.makeNVDRequestWithRetry("/cpematch/2.0", params);
    const context = params.matchCriteriaId
      ? `for Match Criteria ID: ${params.matchCriteriaId}`
      : params.cveId
        ? `for ${params.cveId}`
        : "in the CPE match criteria list";
    return this.formatCPEMatchResponse(data, context);
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error("NIST NVD MCP server v1.1.0 running on stdio");
  }
}

const server = new NISTNVDServer();
server.run().catch(console.error);

# NIST NVD MCP Server

A comprehensive Model Context Protocol (MCP) server providing access to the NIST National Vulnerability Database (NVD) API. This server enables AI agents to search, retrieve, and analyze vulnerability data from the authoritative U.S. government repository of standards-based vulnerability management data.

## Features

### Core Capabilities
- **CVE Search & Retrieval**: Advanced search with keyword, date, severity, and CWE filtering
- **CPE-Based Searches**: Find vulnerabilities affecting specific products and versions
- **CVSS Analysis**: Filter by CVSS v2/v3/v4 scores and severity ratings
- **Change History Tracking**: Monitor CVE modifications and analysis updates
- **High-Priority Detection**: Automated discovery of CISA KEV, CERT alerts, and critical CVEs
- **Comprehensive Filtering**: Date ranges, rejection status, source identifiers, and more

### Advanced Features
- **Intelligent Caching**: 5-minute TTL with automatic cleanup
- **Rate Limiting**: Built-in retry logic with exponential backoff
- **Error Handling**: Comprehensive HTTP error handling and user-friendly messages
- **Data Validation**: NIST API compliance with proper date range enforcement (120-day max)
- **Rich Formatting**: Enhanced JSON responses with security metrics extraction

## Installation

```bash
npm install @cyreslab/nist-nvd-mcp-server
```

Or clone and build locally:

```bash
git clone https://github.com/cyreslab/nist-nvd-mcp-server.git
cd nist-nvd-mcp-server
npm install
npm run build
```

## Quick Start

### Basic Usage
```bash
# Run the server
npm start

# Or run in development mode
npm run dev
```

### Integration with AI Agents

Add to your MCP client configuration:

```json
{
  "servers": {
    "nist-nvd": {
      "command": "node",
      "args": ["/path/to/nist-nvd-mcp-server/build/index.js"]
    }
  }
}
```

## Available Tools

### 1. search_cves
Search CVEs with comprehensive filtering options.

**Parameters:**
- `keywordSearch` (string): Search terms in CVE descriptions
- `keywordExactMatch` (boolean): Exact phrase matching
- `cvssV3Severity` (enum): LOW, MEDIUM, HIGH, CRITICAL
- `cvssV2Severity` (enum): LOW, MEDIUM, HIGH
- `cweId` (string): Common Weakness Enumeration ID (e.g., "CWE-79")
- `hasKev` (boolean): CISA Known Exploited Vulnerabilities only
- `hasCertAlerts` (boolean): US-CERT Technical Alerts only
- `hasCertNotes` (boolean): CERT/CC Vulnerability Notes only
- `noRejected` (boolean): Exclude rejected CVEs
- `pubStartDate/pubEndDate` (string): Publication date range (ISO-8601)
- `lastModStartDate/lastModEndDate` (string): Modification date range
- `resultsPerPage` (number): 1-2000, default 20
- `startIndex` (number): Pagination offset

**Example:**
```json
{
  "keywordSearch": "remote code execution",
  "cvssV3Severity": "CRITICAL",
  "hasKev": true,
  "resultsPerPage": 10
}
```

### 2. get_cve
Retrieve detailed information about a specific CVE.

**Parameters:**
- `cveId` (string, required): CVE identifier (e.g., "CVE-2021-44228")

**Example:**
```json
{
  "cveId": "CVE-2021-44228"
}
```

### 3. search_cves_by_cpe
Find CVEs affecting specific products using CPE.

**Parameters:**
- `cpeName` (string): Full CPE name
- `virtualMatchString` (string): CPE match string for broader searches
- `isVulnerable` (boolean): Only return vulnerable configurations
- `versionStart/versionEnd` (string): Version range filtering
- `versionStartType/versionEndType` (enum): "including" or "excluding"

**Example:**
```json
{
  "virtualMatchString": "cpe:2.3:a:apache:log4j",
  "versionStart": "2.0",
  "versionStartType": "including",
  "versionEnd": "2.15.0",
  "versionEndType": "excluding"
}
```

### 4. search_cves_by_cvss
Search CVEs by CVSS vector strings and severity.

**Parameters:**
- `cvssV3Metrics` (string): CVSSv3 vector string
- `cvssV3Severity` (enum): LOW, MEDIUM, HIGH, CRITICAL
- `cvssV2Metrics` (string): CVSSv2 vector string
- `cvssV2Severity` (enum): LOW, MEDIUM, HIGH
- `cvssV4Metrics` (string): CVSSv4 vector string (experimental)

**Example:**
```json
{
  "cvssV3Severity": "CRITICAL"
}
```

### 5. search_recent_cves
Get recently published CVEs.

**Parameters:**
- `days` (number): Days back from today (1-120)
- `pubStartDate/pubEndDate` (string): Custom date range
- `resultsPerPage` (number): Default 50

**Example:**
```json
{
  "days": 7,
  "resultsPerPage": 25
}
```

### 6. search_modified_cves
Get recently modified CVEs.

**Parameters:**
- `days` (number): Days back from today (1-120)
- `lastModStartDate/lastModEndDate` (string): Custom date range

**Example:**
```json
{
  "days": 3
}
```

### 7. get_cve_change_history
Track CVE modification history.

**Parameters:**
- `cveId` (string): Specific CVE to track
- `changeStartDate/changeEndDate` (string): Date range for changes
- `eventName` (enum): Filter by event type:
  - "CVE Received", "Initial Analysis", "Reanalysis"
  - "CVE Modified", "Modified Analysis", "CVE Translated"
  - "Vendor Comment", "CVE Source Update"
  - "CPE Deprecation Remap", "CWE Remap"
  - "Reference Tag Update", "CVE Rejected"
  - "CVE Unrejected", "CVE CISA KEV Update"

**Example:**
```json
{
  "cveId": "CVE-2021-44228",
  "eventName": "Initial Analysis"
}
```

### 8. search_high_priority_cves
Find high-priority CVEs using multiple risk indicators.

**Parameters:**
- `includeKev` (boolean): Include CISA KEV (default: true)
- `includeCertAlerts` (boolean): Include CERT alerts (default: true)
- `includeCriticalCvss` (boolean): Include critical CVSS (default: true)
- `minCvssScore` (number): Minimum CVSS threshold (0-10, default: 7.0)
- `keywordSearch` (string): Additional keyword filter
- `days` (number): Limit to recent CVEs (max 120)

**Example:**
```json
{
  "minCvssScore": 9.0,
  "days": 30,
  "keywordSearch": "authentication bypass"
}
```

## Response Format

All tools return structured JSON responses with:

### CVE Responses
```json
{
  "summary": {
    "search_context": "search description",
    "total_results": 1500,
    "showing_results": 20,
    "results_per_page": 20,
    "start_index": 0,
    "timestamp": "2025-06-08T14:26:00.000Z"
  },
  "vulnerabilities": [
    {
      "cve_id": "CVE-2021-44228",
      "status": "Analyzed",
      "published": "2021-12-10T10:15:09.043",
      "last_modified": "2021-12-29T00:15:09.427",
      "description": "Apache Log4j2 <=2.14.1 JNDI features...",
      "cvss": {
        "v3_score": 10.0,
        "v3_severity": "CRITICAL",
        "v2_score": 9.3
      },
      "weaknesses": ["CWE-502", "CWE-400"],
      "reference_count": 15,
      "cisa_kev": {
        "exploitAdd": "2021-12-10",
        "actionDue": "2021-12-24",
        "requiredAction": "Apply updates per vendor instructions.",
        "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability"
      },
      "configurations_count": 200
    }
  ],
  "raw_response_metadata": {
    "format": "NVD_CVE",
    "version": "2.0",
    "has_more_results": true
  }
}
```

### Change History Responses
```json
{
  "summary": {
    "search_context": "change history for CVE-2021-44228",
    "total_changes": 5,
    "showing_changes": 5
  },
  "changes": [
    {
      "cve_id": "CVE-2021-44228",
      "event_name": "Initial Analysis",
      "change_id": "ABC123-DEF456",
      "source": "nvd@nist.gov",
      "created": "2021-12-10T15:30:00.000Z",
      "details_count": 8,
      "sample_details": [
        {
          "action": "Added",
          "type": "CVSS V3.1",
          "newValue": "NIST AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        }
      ]
    }
  ]
}
```

## Use Cases for AI Agents

### 1. Threat Intelligence Analysis
```json
{
  "tool": "search_high_priority_cves",
  "args": {
    "days": 7,
    "minCvssScore": 8.0,
    "includeKev": true
  }
}
```

### 2. Software Asset Vulnerability Assessment
```json
{
  "tool": "search_cves_by_cpe",
  "args": {
    "virtualMatchString": "cpe:2.3:a:microsoft:windows",
    "versionStart": "10",
    "versionStartType": "including"
  }
}
```

### 3. Security Research & Analysis
```json
{
  "tool": "search_cves",
  "args": {
    "keywordSearch": "authentication bypass",
    "cvssV3Severity": "HIGH",
    "noRejected": true
  }
}
```

### 4. Vulnerability Lifecycle Monitoring
```json
{
  "tool": "get_cve_change_history",
  "args": {
    "changeStartDate": "2024-01-01T00:00:00.000Z",
    "changeEndDate": "2024-01-31T23:59:59.999Z",
    "eventName": "CISA KEV Update"
  }
}
```

## API Limits & Best Practices

### NIST NVD API Constraints
- **Date Range Limit**: Maximum 120 consecutive days
- **Rate Limiting**: Built-in retry logic handles API limits
- **No API Key Required**: Free access to public data
- **Data Freshness**: Real-time access to official NIST data

### Optimization Tips
- Use caching effectively (5-minute TTL implemented)
- Implement reasonable page sizes (20-100 results)
- Leverage specific filters to reduce result sets
- Monitor for rate limiting in high-volume scenarios

## Error Handling

The server provides comprehensive error handling:

- **404**: Resource not found
- **400**: Invalid request parameters
- **429**: Rate limit exceeded (automatic retry)
- **Timeout**: Request timeout with retry logic
- **Validation**: Parameter validation with helpful messages

## Technical Details

### Architecture
- **TypeScript**: Full type safety and modern ES2022
- **MCP SDK**: Official Model Context Protocol implementation
- **Axios**: HTTP client with retry logic and timeouts
- **Caching**: In-memory cache with TTL and cleanup
- **Error Recovery**: Exponential backoff and circuit breaker patterns

### Performance Features
- **Smart Caching**: Reduces API calls and improves response times
- **Pagination**: Efficient handling of large result sets
- **Parallel Requests**: High-priority search combines multiple API calls
- **Memory Management**: Automatic cache cleanup and optimization

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Support

- **Issues**: [GitHub Issues](https://github.com/cyreslab/nist-nvd-mcp-server/issues)
- **Documentation**: [API Documentation](https://nvd.nist.gov/developers/vulnerabilities)
- **Community**: [MCP Community](https://github.com/modelcontextprotocol)

## Version History

### v1.0.0
- Initial release with full NIST NVD API 2.0 support
- 8 comprehensive tools for vulnerability research
- Advanced filtering and search capabilities
- Change history tracking
- High-priority CVE detection
- Production-ready caching and error handling

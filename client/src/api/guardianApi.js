/**
 * URL Guardian API Service Layer
 * Interacts with the Node.js + Express.js backend.
 */

const getApiUrl = () => {
  const envUrl = import.meta.env.VITE_API_URL;
  if (envUrl) {
    // Strip trailing slash if present
    return envUrl.replace(/\/$/, '');
  }
  // Dev default: local backend. Production default: same origin (frontend and API behind one domain).
  return import.meta.env.DEV ? 'http://localhost:5000' : '';
};

const API_BASE = getApiUrl();
const ANALYZE_ENDPOINT = `${API_BASE}/api/analyze`;

const HEALTH_TIMEOUT_MS = 3000;
// A full scan may wait on VirusTotal and ScrapingBee (up to ~30s each, run in parallel)
const SCAN_TIMEOUT_MS = 60000;

/**
 * Connectivity check: GET /api/analyze returns { status: "ok" } when the backend is up.
 */
export const checkHealth = async () => {
  try {
    const response = await fetch(ANALYZE_ENDPOINT, {
      method: 'GET',
      signal: AbortSignal.timeout(HEALTH_TIMEOUT_MS),
      headers: { Accept: 'application/json' },
    });
    return response.ok;
  } catch {
    return false;
  }
};

/**
 * Submit a URL to the backend for analysis via POST /api/analyze.
 */
export const scanUrl = async (urlToScan) => {
  const cleanUrl = urlToScan.trim();
  if (!cleanUrl) {
    throw new Error('URL is required');
  }

  let response;
  try {
    response = await fetch(ANALYZE_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({ url: cleanUrl }),
      signal: AbortSignal.timeout(SCAN_TIMEOUT_MS),
    });
  } catch (err) {
    if (err.name === 'TimeoutError') {
      throw new Error('The analysis took too long to respond. Please try again.');
    }
    throw new Error('Failed to connect to analysis server. Please check if backend is running.');
  }

  if (!response.ok) {
    let errMsg = response.status === 429
      ? 'Too many scans. Please wait a few minutes and try again.'
      : `Server returned status ${response.status}`;
    try {
      const errData = await response.json();
      errMsg = errData.message || errData.error || errMsg;
    } catch {
      // Response body was not JSON; keep the status-based message
    }
    throw new Error(errMsg);
  }

  const rawData = await response.json();
  return parseScanResponse(rawData);
};

/**
 * Defensive Response Parser.
 * Ensures all required properties exist, providing defaults for missing or failed service details
 * so the frontend never crashes due to incomplete backend responses.
 */
function parseScanResponse(data) {
  if (!data) {
    throw new Error('Received empty response from scanner');
  }

  // Extract lexical metadata if present (new backend response format)
  const lexicalMetadata = data.findings?.lexical?.urlMetadata;
  
  // Map score, risk, and recommendation from either root or new explanation.verdict object
  const score = typeof data.score === 'number' 
    ? data.score 
    : (typeof data.explanation?.verdict?.score === 'number' ? data.explanation.verdict.score : 0);
    
  const risk = data.risk || data.explanation?.verdict?.riskLevel || 'UNKNOWN';
  
  const recommendation = data.recommendation 
    || data.explanation?.verdict?.recommendedAction 
    || 'No recommendation provided.';

  // Map URL metadata details defensively
  const details = {
    protocol: data.details?.protocol || lexicalMetadata?.protocol || 'N/A',
    hostname: data.details?.hostname || lexicalMetadata?.hostname || 'N/A',
    registeredDomain: data.details?.registeredDomain || lexicalMetadata?.registeredDomain || 'N/A',
    subdomain: data.details?.subdomain || lexicalMetadata?.subdomain || '',
    tld: data.details?.tld || lexicalMetadata?.tld || 'N/A',
    port: data.details?.port || lexicalMetadata?.port || 'N/A',
    urlLength: typeof data.details?.urlLength === 'number' 
      ? data.details.urlLength 
      : (typeof lexicalMetadata?.urlLength === 'number' ? lexicalMetadata.urlLength : (data.url?.length || 0))
  };

  // Map URL findings. Support findings.lexical.fullFindings as findings.url.findings
  let activeFindings = [];
  let suppressedFindings = [];

  if (Array.isArray(data.findings?.lexical?.fullFindings)) {
    data.findings.lexical.fullFindings.forEach(f => {
      const rule = {
        ruleId: f.observationId || 'UNKNOWN_RULE',
        title: f.title || 'Rule Violation',
        description: f.description || 'No description available.',
        recommendation: f.recommendation || 'Exercise caution.',
        severity: f.suggestedSeverity || 'medium'
      };
      if (f.suppressed) {
        suppressedFindings.push(rule);
      } else {
        activeFindings.push(rule);
      }
    });
  } else {
    if (Array.isArray(data.findings?.url?.findings)) {
      activeFindings = data.findings.url.findings.map(f => ({
        ruleId: f.ruleId || 'UNKNOWN_RULE',
        title: f.title || 'Rule Violation',
        description: f.description || 'No description available.',
        recommendation: f.recommendation || 'Exercise caution.',
        severity: f.severity || 'medium'
      }));
    }
    if (Array.isArray(data.findings?.url?.suppressedFindings)) {
      suppressedFindings = data.findings.url.suppressedFindings.map(f => ({
        ruleId: f.ruleId || 'SUPPRESSED_RULE',
        title: f.title || 'Suppressed Flag',
        description: f.description || 'No description available.',
        recommendation: f.recommendation || 'No action needed.',
        severity: f.severity || 'low'
      }));
    }
  }

  // Parse WHOIS dates defensively (handle Date object / String / Number representation)
  const parseWhoisDate = (dateVal) => {
    if (!dateVal) return null;
    if (typeof dateVal === 'string') return dateVal;
    if (typeof dateVal.toISOString === 'function') return dateVal.toISOString();
    return String(dateVal);
  };

  // Map VirusTotal completed status if scanners checked
  const vtTotalScanners = typeof data.findings?.virustotal?.totalScanners === 'number' 
    ? data.findings.virustotal.totalScanners 
    : 0;
  
  const vtStatus = data.findings?.virustotal?.status 
    || (vtTotalScanners > 0 ? 'COMPLETED' : 'N/A');

  // Base structured response mapping the contract
  return {
    url: data.url || '',
    score,
    risk,
    recommendation,
    timestamp: data.timestamp || data.explanation?.generatedAt || new Date().toISOString(),
    explanation: data.explanation || null,
    
    details,
    
    findings: {
      url: {
        success: data.findings?.url?.success ?? (data.findings?.lexical?.success ?? false),
        threatFound: data.findings?.url?.threatFound ?? (activeFindings.length > 0),
        findings: activeFindings,
        suppressedFindings
      },
      
      dns: {
        success: data.findings?.dns?.success ?? (!!data.findings?.dns),
        domain: data.findings?.dns?.domain || details.hostname || 'N/A',
        ipv4: Array.isArray(data.findings?.dns?.ipv4) ? data.findings.dns.ipv4 : null,
        ipv6: Array.isArray(data.findings?.dns?.ipv6) ? data.findings.dns.ipv6 : null,
        nameServers: Array.isArray(data.findings?.dns?.nameServers) ? data.findings.dns.nameServers : null
      },
      
      whois: {
        success: data.findings?.whois?.success ?? (!!data.findings?.whois),
        domain: data.findings?.whois?.domain || details.registeredDomain || 'N/A',
        creationDate: parseWhoisDate(data.findings?.whois?.creationDate),
        expireDate: parseWhoisDate(data.findings?.whois?.expireDate),
        registerName: data.findings?.whois?.registerName || 'N/A',
        nameServers: Array.isArray(data.findings?.whois?.nameServers) ? data.findings.whois.nameServers : null,
        status: data.findings?.whois?.status || 'N/A',
        domainAge: typeof data.findings?.whois?.domainAge === 'number' ? data.findings.whois.domainAge : null,
        daysSinceRegistration: typeof data.findings?.whois?.daysSinceRegistration === 'number' ? data.findings.whois.daysSinceRegistration : null
      },
      
      html: {
        success: data.findings?.html?.success ?? (!!data.findings?.html),
        threatFound: data.findings?.html?.threatFound ?? false,
        riskScore: typeof data.findings?.html?.riskScore === 'number' ? data.findings.html.riskScore : 0,
        findings: Array.isArray(data.findings?.html?.findings) ? data.findings.html.findings : []
      },
      
      virustotal: {
        success: data.findings?.virustotal?.success ?? (!!data.findings?.virustotal),
        threatFound: data.findings?.virustotal?.threatFound ?? false,
        positives: typeof data.findings?.virustotal?.positives === 'number' ? data.findings.virustotal.positives : 0,
        totalScanners: vtTotalScanners,
        reputation: typeof data.findings?.virustotal?.reputation === 'number' ? data.findings.virustotal.reputation : 0,
        status: vtStatus,
        findings: data.findings?.virustotal?.findings || null
      }
    },
    
    correlations: Array.isArray(data.correlations) ? data.correlations.map(c => ({
      id: c.id || 'UNKNOWN_CORRELATION',
      title: c.title || 'Correlated Indicator',
      severity: c.severity?.toLowerCase() || 'medium', // Normalise severity
      confidence: c.confidence || 'medium',
      evidence: Array.isArray(c.evidence) ? c.evidence : []
    })) : []
  };
}

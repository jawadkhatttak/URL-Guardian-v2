/**
 * Risk Engine — Fixed to parse WHOIS age and Lexical Observation IDs correctly
 */

const CORRELATION_WEIGHTS = {
  CORR_ACTIVE_MALICIOUS_CAMPAIGN: 45,
  CORR_HIGH_RISK_PHISHING_CANDIDATE: 40,
  CORR_EVASIVE_PHISHING_INFRASTRUCTURE: 45,
  CORR_TARGETED_SOCIAL_ENGINEERING: 30,
  CORR_BRAND_IMPERSONATION: 35,
  CORR_HOMOGRAPH_BRAND_TARGETING: 35,
  CORR_URL_TRICK_WITH_EXTERNAL_HARVEST: 35,
  CORR_CREDENTIAL_HARVESTING: 25,
  CORR_EVASIVE_MALWARE_CLOAKING: 25,
  CORR_DYNAMIC_DNS_HOSTING: 12,
  CORR_AGGRESSIVE_REDIRECT_LOOP: 15,
  DEFAULT: 15,
};

// Map raw Lexical Observation IDs to their base logical threat weights
const LEXICAL_BASE_WEIGHTS = {
  // Critical / High Targets
  BRAND_IMPERSONATION: 30,
  BRAND_TYPOSQUAT: 30,
  HOMOGRAPH: 30,
  AT_USERINFO_TRICK: 30,
  DANGEROUS_PROTOCOL: 30,
  IP_ADDRESS_HOST: 25,
  PUNYCODE: 20,
  SUBDOMAIN_LABEL_MIMICRY: 20,
  OPEN_REDIRECT_PARAM: 20,

  // Medium / General Deceptions
  SUSPICIOUS_KEYWORDS: 15,
  UNICODE_HOSTNAME: 15,
  URL_SHORTENER: 15,
  NON_STANDARD_PORT: 15,
  RISKY_FILE_EXTENSION: 15,
  INSECURE_PROTOCOL: 10,

  // Low / Supporting Evidence
  SUBDOMAIN_DEPTH: 8,
  LONG_URL: 8,
  HIGH_ENTROPY: 8
};

// Dynamic scaling multipliers based on the runtime severity resolved by describe()
const RUNTIME_SEVERITY_MULTIPLIERS = {
  critical: 1.4, // e.g. Extremely long URL or 1-distance typosquat gets boosted
  high: 1.1,
  medium: 0.8,
  low: 0.5       // e.g. Shorter long URLs or low entropy gets scaled down
};

const SEVERITY_MULTIPLIER = { CRITICAL: 1.3, HIGH: 1.1, MEDIUM: 0.9, LOW: 0.6 };
const CONFIDENCE_MULTIPLIER = { CRITICAL: 1.2, HIGH: 1.0, MEDIUM: 0.8, LOW: 0.5 };

const DEVELOPER_PLATFORMS = [
  'github.io', 'vercel.app', 'netlify.app', 'pages.dev', 'workers.dev',
  'firebaseapp.com', 'web.app', 'blogspot.com', 'githubusercontent.com'
];

/**
 * Mitigates false positives dynamically based on host reputation context.
 */
function applyMitigations(contributions, hostname) {
  const isCloudHost = DEVELOPER_PLATFORMS.some(platform => hostname.endsWith(platform));

  return contributions.map(contrib => {
    let mitigatedValue = contrib.contribution;
    let note = null;

    if (isCloudHost) {
      if (contrib.id === 'CORR_DYNAMIC_DNS_HOSTING') {
        mitigatedValue = Math.round(contrib.contribution * 0.2 * 10) / 10;
        note = "Mitigated: Expected dynamic/shared infrastructure on developer cloud host.";
      }
      if (contrib.id === 'CORR_HIGH_RISK_PHISHING_CANDIDATE' || contrib.id === 'WHOIS_NEW_REGISTRATION') {
        mitigatedValue = Math.round(contrib.contribution * 0.5 * 10) / 10;
        note = "Mitigated: Young registration weight reduced for trusted cloud provider platform.";
      }
    }

    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname.endsWith('.local')) {
      mitigatedValue = 0;
      note = "Mitigated: Development environments ignored by policy.";
    }

    return {
      ...contrib,
      contribution: mitigatedValue,
      mitigated: mitigatedValue !== contrib.contribution,
      mitigationReason: note
    };
  });
}

function scoreCorrelatedFindings(correlatedFindings) {
  return correlatedFindings.map((cf) => {
    const base = CORRELATION_WEIGHTS[cf.id] ?? CORRELATION_WEIGHTS.DEFAULT;
    const sevMult = SEVERITY_MULTIPLIER[cf.severity] ?? 1.0;
    const confMult = CONFIDENCE_MULTIPLIER[cf.confidence] ?? 1.0;
    return {
      source: 'correlation',
      id: cf.id,
      title: cf.title,
      contribution: Math.round(base * sevMult * confMult * 10) / 10,
    };
  });
}

/**
 * Scores Whois registration age and Lexical analysis components
 */
function scoreRawSignals(masterFindings) {
  const contributions = [];
  const { virustotal = {}, urlLexical = {}, lexical = {}, whois = {} } = masterFindings;

  // Check both possible pathways for the lexical findings array
  const lexicalPayload = urlLexical?.fullFindings ? urlLexical : (lexical?.fullFindings ? lexical : null);

  // 1. Process Whois Registration Age
  if (whois && typeof whois.daysSinceRegistration === 'number') {
    const age = whois.daysSinceRegistration;
    if (age <= 30 && age >= 0) {
      contributions.push({
        source: 'whois',
        id: 'WHOIS_NEW_REGISTRATION',
        title: `Newly Registered Domain (Age: ${age} days)`,
        contribution: 25, // Brand new domain gets heavy threat score
      });
    } else if (age <= 90 && age > 30) {
      contributions.push({
        source: 'whois',
        id: 'WHOIS_RECENT_REGISTRATION',
        title: `Recently Registered Domain (Age: ${age} days)`,
        contribution: 12,
      });
    }
  }

  // 2. Process VirusTotal Reputations
  if (virustotal.success && virustotal.totalScanners > 0) {
    const ratio = virustotal.positives / virustotal.totalScanners;
    if (ratio > 0) {
      contributions.push({
        source: 'virustotal',
        id: 'VT_POSITIVE_RATIO',
        title: `${virustotal.positives}/${virustotal.totalScanners} security vendors flagged this domain`,
        contribution: Math.round(Math.min(40, ratio * 100) * 10) / 10,
      });
    }
  }

  // 3. Process Dynamic Lexical Analysis Observations (Handling all 18 rules)
  if (lexicalPayload && Array.isArray(lexicalPayload.fullFindings)) {
    for (const finding of lexicalPayload.fullFindings) {
      if (finding.suppressed) continue;

      const obsId = finding.observationId;
      const baseWeight = LEXICAL_BASE_WEIGHTS[obsId];

      if (baseWeight !== undefined) {
        // Read the runtime severity output by describe() (default to medium if missing)
        const runtimeSeverity = finding.suggestedSeverity || finding.baseSeverity || 'medium';
        const severityMultiplier = RUNTIME_SEVERITY_MULTIPLIERS[runtimeSeverity.toLowerCase()] ?? 1.0;
        const confidence = finding.confidence ?? 1.0;

        // Calculate a dynamically scaled contribution
        const dynamicScore = Math.round(baseWeight * severityMultiplier * confidence * 10) / 10;

        contributions.push({
          source: 'lexical',
          id: obsId,
          title: finding.title || finding.description,
          contribution: dynamicScore,
        });
      }
    }
  }

  return contributions;
}


function levelForScore(score) {
  if (score >= 71) return 'CRITICAL';
  if (score >= 41) return 'HIGH';
  if (score >= 21) return 'MEDIUM';
  if (score >= 1) return 'LOW';
  return 'SAFE';
}

function calculateVerdictConfidence(allContributions) {
  const activeSignals = allContributions.filter(c => c.contribution > 0);
  const uniqueSources = new Set(activeSignals.map(c => c.source));
  const uniqueCount = uniqueSources.size;

  if (uniqueCount >= 3) return 'HIGH';
  if (uniqueCount === 2) return 'MEDIUM';
  if (uniqueCount === 1) return 'LOW';
  return 'NONE';
}

function generateVerdictJustification(score, contributions) {
  if (score === 0) {
    return "No indicators of threat activity or structural deception were detected during scanning.";
  }

  const activeContributions = contributions.filter(c => c.contribution > 0);
  if (activeContributions.length === 0) {
    return "All scan indicators were contextually mitigated to SAFE for this environment.";
  }

  const heaviestContribution = activeContributions[0];
  let text = `Score driven primarily by ${heaviestContribution.title} (+${heaviestContribution.contribution} risk points)`;
  if (activeContributions.length > 1) {
    text += `, supported by ${activeContributions.length - 1} other security observations.`;
  }
  return text;
}

export function computeRisk(masterFindings, correlatedFindings, targetUrl) {
  const urlObj = new URL(targetUrl.toLowerCase());
  const hostname = urlObj.hostname;

  const rawCorrelationContributions = scoreCorrelatedFindings(correlatedFindings);
  const rawSingleContributions = scoreRawSignals(masterFindings);
  const combinedRaw = [...rawCorrelationContributions, ...rawSingleContributions];

  const mitigatedContributions = applyMitigations(combinedRaw, hostname);

  const total = mitigatedContributions.reduce((sum, c) => sum + c.contribution, 0);
  const score = Math.min(100, Math.round(total));
  const sortedContributions = mitigatedContributions.sort((a, b) => b.contribution - a.contribution);

  return {
    score,
    risk: levelForScore(score),
    contributions: sortedContributions,
    transparency: {
      verdictConfidence: calculateVerdictConfidence(sortedContributions),
      justification: generateVerdictJustification(score, sortedContributions),
      totalSignalsProcessed: sortedContributions.length,
      mitigationsApplied: sortedContributions.filter(c => c.mitigated).length
    }
  };
}
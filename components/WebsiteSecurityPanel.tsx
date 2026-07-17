'use client';

import { useState, useEffect } from 'react';

interface WebsiteScan {
  _id: string;
  domain: string;
  securityScore: number;
  riskScore: number;
  threats: string[];
  timestamp: string;
}

interface WebsiteAlert {
  _id: string;
  domain: string;
  riskScore: number;
  threats: string[];
  severity: string;
  timestamp: string;
}

interface WebsiteSecurityPanelProps {
  onThreatClick?: (threat: WebsiteAlert) => void;
}

// ── AI Fix Dropdown ────────────────────────────────────────────
function ScanRowDropdown({ scan }: { scan: WebsiteScan }) {
  const [open,    setOpen]    = useState(false);
  const [loading, setLoading] = useState(false);
  const [fixes,   setFixes]   = useState<string[]>([]);
  const [fetched, setFetched] = useState(false);

  const getAiFixes = async () => {
    if (fetched) return; // don't re-fetch
    setLoading(true);
    try {
      const res = await fetch('/api/groq-analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url:          `https://${scan.domain}`,
          domain:       scan.domain,
          htmlSnippet:  '',
          cookies:      [],
          scripts:      [],
          forms:        [],
          localRisk:    scan.riskScore,
          localThreats: scan.threats,
        }),
      });
      const data = await res.json();
      if (data.recommendations?.length) {
        setFixes(data.recommendations);
      } else {
        setFixes(['No specific fixes returned — check CSP, HTTPS, and cookie flags.']);
      }
      setFetched(true);
    } catch {
      setFixes(['Could not reach AI engine. Make sure the server is running.']);
    } finally {
      setLoading(false);
    }
  };

  const toggle = () => {
    setOpen(o => !o);
    if (!open && !fetched) getAiFixes();
  };

  const scoreColor = (s: number) =>
    s >= 80 ? '#22c55e' : s >= 60 ? '#eab308' : s >= 40 ? '#f97316' : '#ef4444';

  const riskBadge = (r: number) => {
    if (r >= 70) return { label: 'CRITICAL', bg: '#7f1d1d', color: '#fca5a5' };
    if (r >= 50) return { label: 'HIGH',     bg: '#7c2d12', color: '#fdba74' };
    if (r >= 30) return { label: 'MEDIUM',   bg: '#713f12', color: '#fde047' };
    return              { label: 'LOW',      bg: '#14532d', color: '#86efac' };
  };

  const badge = riskBadge(scan.riskScore);

  return (
    <>
      {/* Table row */}
      <tr
        onClick={toggle}
        style={{ borderBottom: '1px solid #1f2937', cursor: 'pointer', background: open ? '#0f172a' : 'transparent', transition: 'background 0.15s' }}
      >
        <td style={{ padding: '10px 16px', fontSize: 12, color: '#6b7280', fontFamily: 'monospace' }}>
          {new Date(scan.timestamp).toLocaleTimeString()}
        </td>
        <td style={{ padding: '10px 16px', fontSize: 12, color: '#e5e7eb', fontFamily: 'monospace' }}>
          {scan.domain}
        </td>
        <td style={{ padding: '10px 16px' }}>
          <span style={{ fontWeight: 700, color: scoreColor(scan.securityScore), fontSize: 13 }}>
            {scan.securityScore}/100
          </span>
        </td>
        <td style={{ padding: '10px 16px' }}>
          <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 4, background: badge.bg, color: badge.color }}>
            {badge.label}
          </span>
        </td>
        <td style={{ padding: '10px 16px', fontSize: 12, color: '#9ca3af' }}>
          {scan.threats?.length || 0} issues
        </td>
        <td style={{ padding: '10px 16px', textAlign: 'right' }}>
          <span style={{ fontSize: 10, color: '#00eaff', border: '1px solid #1e3a5f', padding: '2px 8px', borderRadius: 3, fontFamily: 'monospace' }}>
            {open ? '▲ CLOSE' : '▼ DETAILS'}
          </span>
        </td>
      </tr>

      {/* Dropdown row */}
      {open && (
        <tr style={{ background: '#0a0f1a' }}>
          <td colSpan={6} style={{ padding: '0 16px 16px' }}>
            <div style={{ borderLeft: '2px solid #1e3a5f', paddingLeft: 14, marginTop: 8 }}>

              {/* Issues list */}
              <div style={{ fontSize: 10, color: '#4b5563', letterSpacing: '0.08em', marginBottom: 8 }}>
                // DETECTED_ISSUES [{scan.threats?.length || 0}]
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 14 }}>
                {(scan.threats || []).map((t, i) => {
                  const tl = t.toLowerCase();
                  const color = tl.includes('critical') || tl.includes('password') || tl.includes('insecure') ? '#ff3b3b'
                              : tl.includes('xss') || tl.includes('csrf') || tl.includes('samesite') ? '#facc15'
                              : '#9ca3af';

                  // Inline fix hint based on threat content
                  const hint =
                    tl.includes('https') || tl.includes('plain text')
                      ? 'Fix: Obtain a TLS certificate (free via Let\'s Encrypt). Redirect all HTTP traffic to HTTPS using a 301 redirect. Update all internal links to use https://.'
                    : tl.includes('content-security-policy') || tl.includes('csp')
                      ? 'Fix: Add a Content-Security-Policy header in your server config. Start with Content-Security-Policy: default-src \'self\'. Tighten script-src to block inline scripts and untrusted CDNs.'
                    : tl.includes('x-frame-options') || tl.includes('iframe') || tl.includes('clickjack')
                      ? 'Fix: Add the header X-Frame-Options: DENY or SAMEORIGIN. Alternatively use CSP frame-ancestors \'none\'. This prevents your page from being embedded in malicious iframes.'
                    : tl.includes('x-content-type') || tl.includes('mime')
                      ? 'Fix: Add the header X-Content-Type-Options: nosniff to all responses. This stops browsers from guessing content types and executing unexpected scripts.'
                    : tl.includes('hsts') || tl.includes('strict-transport')
                      ? 'Fix: Add Strict-Transport-Security: max-age=31536000; includeSubDomains to your HTTPS responses. This forces browsers to always use HTTPS for your domain.'
                    : tl.includes('secure flag') || tl.includes('missing secure')
                      ? 'Fix: Set the Secure attribute on all session and auth cookies. In Express: res.cookie("session", val, { secure: true, httpOnly: true }). Never send sensitive cookies over HTTP.'
                    : tl.includes('httponly') || tl.includes('readable by javascript')
                      ? 'Fix: Add the HttpOnly flag to all session cookies so JavaScript cannot read them. This blocks XSS attacks from stealing session tokens.'
                    : tl.includes('samesite') || tl.includes('csrf')
                      ? 'Fix: Set SameSite=Lax or SameSite=Strict on all cookies. This prevents cross-site request forgery by blocking cookies from being sent with cross-origin requests.'
                    : tl.includes('mixed content') || tl.includes('http resource')
                      ? 'Fix: Update all resource URLs (images, scripts, fonts) to use https://. Search your codebase for http:// and replace. Use a CSP upgrade-insecure-requests directive as a safety net.'
                    : tl.includes('innerhtml') || tl.includes('xss')
                      ? 'Fix: Replace innerHTML assignments with textContent or DOM methods like createElement. If HTML is required, sanitize input with DOMPurify before inserting.'
                    : tl.includes('eval') || tl.includes('code injection')
                      ? 'Fix: Remove eval() calls and replace with safer alternatives like JSON.parse() for data or Function constructors only when absolutely necessary. Add a CSP that blocks unsafe-eval.'
                    : tl.includes('document.write')
                      ? 'Fix: Replace document.write() with DOM manipulation methods (appendChild, insertAdjacentHTML). document.write() blocks parsing and is a common XSS vector.'
                    : tl.includes('phishing') || tl.includes('login-verify')
                      ? 'Fix: This domain pattern matches known phishing templates. Do not enter credentials. Verify the real domain via WHOIS and report to Google Safe Browsing.'
                    : tl.includes('form') || tl.includes('post to http')
                      ? 'Fix: Change all form action URLs from http:// to https://. Ensure your server enforces HTTPS on the receiving endpoint. Never submit credentials over unencrypted connections.'
                    : 'Fix: Review your server security headers, cookie configuration, and HTTPS setup. Use securityheaders.com to audit your response headers.';

                  return (
                    <div key={i} style={{ borderLeft: `2px solid ${color}`, paddingLeft: 10 }}>
                      <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start', marginBottom: 4 }}>
                        <span style={{ color, fontSize: 9, marginTop: 2, flexShrink: 0 }}>●</span>
                        <span style={{ fontSize: 11, color: '#e5e7eb', lineHeight: 1.5, fontWeight: 600 }}>{t}</span>
                      </div>
                      <div style={{ fontSize: 10, color: '#6b7280', lineHeight: 1.6, paddingLeft: 16 }}>
                        {hint}
                      </div>
                    </div>
                  );
                })}
              </div>
              {/* AI Fix section */}
              <div style={{ borderTop: '1px solid #1f2937', paddingTop: 12 }}>
                <div style={{ fontSize: 10, color: '#4b5563', letterSpacing: '0.08em', marginBottom: 8 }}>
                  // AI_REMEDIATION_GUIDE
                </div>

                {loading && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#00eaff', fontSize: 11 }}>
                    <span style={{ display: 'inline-block', width: 12, height: 12, border: '2px solid #1f2937', borderTop: '2px solid #00eaff', borderRadius: '50%', animation: 'spin 0.7s linear infinite' }} />
                    Asking Groq AI for fixes...
                  </div>
                )}

                {!loading && fixes.length > 0 && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {fixes.map((fix, i) => (
                      <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'flex-start', padding: '6px 10px', background: '#0d1f0d', borderLeft: '2px solid #00ff88' }}>
                        <span style={{ color: '#00ff88', fontSize: 10, flexShrink: 0, marginTop: 1 }}>AI›</span>
                        <span style={{ fontSize: 11, color: '#86efac', lineHeight: 1.5 }}>{fix}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// Severity color function
const getThreatSeverity = (threat: string) => {
  const threatLower = threat.toLowerCase();
  if (threatLower.includes('critical') || threatLower.includes('password') || threatLower.includes('secure flag') || threatLower.includes('insecure')) 
    return { level: 'CRITICAL', color: '#ef4444', bgColor: 'bg-red-900/50', borderColor: 'border-red-500', icon: '🔴' };
  if (threatLower.includes('tracking') || threatLower.includes('samesite') || threatLower.includes('xss') || threatLower.includes('csrf')) 
    return { level: 'MEDIUM', color: '#eab308', bgColor: 'bg-yellow-900/50', borderColor: 'border-yellow-500', icon: '🟡' };
  if (threatLower.includes('iframe') || threatLower.includes('long-lived') || threatLower.includes('expires'))
    return { level: 'LOW', color: '#22c55e', bgColor: 'bg-green-900/50', borderColor: 'border-green-500', icon: '🟢' };
  return { level: 'INFO', color: '#3b82f6', bgColor: 'bg-blue-900/50', borderColor: 'border-blue-500', icon: 'ℹ️' };
};

export default function WebsiteSecurityPanel({ onThreatClick }: WebsiteSecurityPanelProps) {
  const [scans, setScans] = useState<WebsiteScan[]>([]);
  const [alerts, setAlerts] = useState<WebsiteAlert[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [selectedAlert, setSelectedAlert] = useState<WebsiteAlert | null>(null);

  useEffect(() => {
    fetchSecurityData();
    const interval = setInterval(fetchSecurityData, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchSecurityData = async () => {
    try {
      const response = await fetch('/api/website-security');
      const result = await response.json();
      if (result.success) {
        // Filter out scans with NO real threats
        const realScans = (result.scans || []).filter((scan: WebsiteScan) => {
          // Only show scans that have REAL threats (not just "1 issue" placeholder)
          return scan.threats && scan.threats.length > 0 && scan.threats[0] !== 'No threats detected';
        });
        
        // Filter alerts that have REAL threats
        const realAlerts = (result.alerts || []).filter((alert: WebsiteAlert) => {
          return alert.threats && alert.threats.length > 0 && alert.riskScore > 0;
        });
        
        setScans(realScans);
        setAlerts(realAlerts);
        setStats(result.stats);
      }
    } catch (error) {
      console.error('Error fetching security data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-green-400';
    if (score >= 60) return 'text-yellow-400';
    if (score >= 40) return 'text-orange-400';
    return 'text-red-400';
  };

  const getScoreBgColor = (score: number) => {
    if (score >= 80) return 'bg-green-500';
    if (score >= 60) return 'bg-yellow-500';
    if (score >= 40) return 'bg-orange-500';
    return 'bg-red-500';
  };

  const getSeverityColor = (severity: string) => {
    switch(severity) {
      case 'critical': return 'bg-red-600 text-white';
      case 'high': return 'bg-orange-600 text-white';
      case 'medium': return 'bg-yellow-600 text-black';
      default: return 'bg-blue-600 text-white';
    }
  };

  if (loading) {
    return (
      <div className="bg-gray-800/40 rounded-2xl p-8 text-center">
        <div className="animate-pulse flex flex-col items-center">
          <div className="w-12 h-12 bg-gray-700 rounded-full mb-3"></div>
          <div className="h-4 bg-gray-700 rounded w-32 mb-2"></div>
          <div className="h-3 bg-gray-700 rounded w-48"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Stats Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-gradient-to-br from-gray-800/40 to-gray-900/40 rounded-2xl p-5 border border-gray-700/50">
          <div className="flex items-center gap-3">
            <span className="text-2xl">🌐</span>
            <div>
              <div className="text-2xl font-bold text-blue-400">{scans.length}</div>
              <div className="text-xs text-gray-400">Sites with Issues</div>
            </div>
          </div>
        </div>
        <div className="bg-gradient-to-br from-gray-800/40 to-gray-900/40 rounded-2xl p-5 border border-gray-700/50">
          <div className="flex items-center gap-3">
            <span className="text-2xl">🚨</span>
            <div>
              <div className="text-2xl font-bold text-red-400">{alerts.length}</div>
              <div className="text-xs text-gray-400">Active Threats</div>
            </div>
          </div>
        </div>
        <div className="bg-gradient-to-br from-gray-800/40 to-gray-900/40 rounded-2xl p-5 border border-gray-700/50">
          <div className="flex items-center gap-3">
            <span className="text-2xl">✅</span>
            <div>
              <div className="text-2xl font-bold text-green-400">{scans.filter(s => s.securityScore >= 80).length}</div>
              <div className="text-xs text-gray-400">Secure Sites</div>
            </div>
          </div>
        </div>
        <div className="bg-gradient-to-br from-gray-800/40 to-gray-900/40 rounded-2xl p-5 border border-gray-700/50">
          <div className="flex items-center gap-3">
            <span className="text-2xl">📊</span>
            <div>
              <div className="text-2xl font-bold text-purple-400">{stats?.totalScans || 0}</div>
              <div className="text-xs text-gray-400">Total Scans</div>
            </div>
          </div>
        </div>
      </div>

      {/* Current Security Score Card */}
      {stats && stats.latestRisk > 0 && (
        <div className="bg-gradient-to-br from-gray-800/40 to-gray-900/40 rounded-2xl p-6 border border-gray-700/50">
          <h3 className="text-lg font-bold text-blue-400 mb-4">📊 Current Security Status</h3>
          <div className="flex flex-col md:flex-row items-center gap-6">
            <div className="relative">
              <svg className="w-32 h-32 transform -rotate-90">
                <circle cx="64" cy="64" r="58" stroke="#374151" strokeWidth="8" fill="none" />
                <circle
                  cx="64"
                  cy="64"
                  r="58"
                  stroke={getScoreBgColor(stats.latestScore || 100)}
                  strokeWidth="8"
                  fill="none"
                  strokeDasharray={`${((stats.latestScore || 100) / 100) * 364} 364`}
                  strokeLinecap="round"
                  className="transition-all duration-700"
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className={`text-3xl font-bold ${getScoreColor(stats.latestScore || 100)}`}>
                  {stats.latestScore || 100}
                </span>
                <span className="text-xs text-gray-400">SECURITY</span>
              </div>
            </div>
            <div className="flex-1">
              <div className="mb-3">
                <div className="text-sm text-gray-400 mb-1">Last Scanned Domain</div>
                <div className="font-mono text-sm text-white bg-gray-700/30 p-2 rounded-lg">
                  {stats.latestDomain || 'No scans yet'}
                </div>
              </div>
              <div className="flex gap-4">
                <div>
                  <div className="text-xs text-gray-400">Risk Level</div>
                  <div className={`text-sm font-bold ${stats.latestRisk >= 50 ? 'text-red-400' : 'text-green-400'}`}>
                    {stats.latestRisk >= 50 ? '⚠️ High Risk' : '✅ Low Risk'}
                  </div>
                </div>
                <div>
                  <div className="text-xs text-gray-400">Threats Found</div>
                  <div className="text-sm font-bold text-orange-400">{alerts.length}</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Active Threats - Only show REAL threats */}
      <div className="bg-gradient-to-br from-gray-800/40 to-gray-900/40 rounded-2xl p-6 border border-gray-700/50">
        <h3 className="text-lg font-bold text-red-400 mb-4 flex items-center gap-2">
          <span className="animate-pulse">🚨</span> Active Security Threats
        </h3>
        {alerts.length > 0 ? (
          <div className="space-y-3 max-h-96 overflow-y-auto">
            {alerts.map((alert) => (
              <div
                key={alert._id}
                onClick={() => {
                  setSelectedAlert(alert);
                  onThreatClick?.(alert);
                }}
                className="bg-red-900/20 border border-red-700/30 rounded-xl p-4 hover:bg-red-900/30 cursor-pointer transition-all"
              >
                <div className="flex justify-between items-start mb-2">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded-full text-xs font-bold ${getSeverityColor(alert.severity)}`}>
                      {alert.severity.toUpperCase()}
                    </span>
                    <span className="font-mono text-sm text-white">{alert.domain}</span>
                  </div>
                  <span className="text-xs text-gray-400">
                    {new Date(alert.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                <div className="space-y-1">
                  {alert.threats?.slice(0, 3).map((threat, idx) => {
                    const severity = getThreatSeverity(threat);
                    return (
                      <div key={idx} className={`flex items-center gap-2 p-1 rounded ${severity.bgColor}`}>
                        <span>{severity.icon}</span>
                        <span className="text-xs text-gray-300 flex-1">{threat}</span>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded ${severity.borderColor}`} style={{ color: severity.color }}>
                          {severity.level}
                        </span>
                      </div>
                    );
                  })}
                  {alert.threats && alert.threats.length > 3 && (
                    <div className="text-gray-400 text-xs mt-1">+{alert.threats.length - 3} more issues</div>
                  )}
                </div>
                <div className="mt-2 flex items-center gap-2">
                  <div className="flex-1 h-1 bg-gray-700 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full ${getScoreBgColor(100 - alert.riskScore)}`}
                      style={{ width: `${100 - alert.riskScore}%` }}
                    />
                  </div>
                  <span className="text-xs text-gray-400">Risk: {alert.riskScore}</span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-8">
            <div className="text-5xl mb-3">✅</div>
            <div className="text-gray-400">No active threats detected</div>
            <div className="text-xs text-gray-500 mt-1">All websites are secure</div>
          </div>
        )}
      </div>

      {/* Recent Scans - Only show scans with REAL issues */}
      {scans.length > 0 && (
        <div className="bg-gradient-to-br from-gray-800/40 to-gray-900/40 rounded-2xl p-6 border border-gray-700/50">
          <h3 className="text-lg font-bold text-green-400 mb-4 flex items-center gap-2">
            <span>📋</span> Recent Security Scans
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full" style={{ borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ background: '#111827', borderBottom: '1px solid #1f2937' }}>
                  {['Time', 'Domain', 'Security Score', 'Risk Level', 'Issues', ''].map(h => (
                    <th key={h} style={{ padding: '10px 16px', textAlign: 'left', fontSize: 11, color: '#00eaff', fontWeight: 700, letterSpacing: '0.08em', fontFamily: 'monospace' }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {scans.slice(0, 10).map(scan => (
                  <ScanRowDropdown key={scan._id} scan={scan} />
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Selected Alert Modal */}
      {selectedAlert && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 animate-fadeIn">
          <div className="bg-gradient-to-br from-gray-800 to-gray-900 rounded-2xl max-w-md w-full mx-4 border border-red-500/50 shadow-2xl max-h-[80vh] overflow-y-auto">
            <div className="p-6">
              <div className="flex justify-between items-start mb-4">
                <h3 className="text-xl font-bold text-red-400">Threat Details</h3>
                <button onClick={() => setSelectedAlert(null)} className="text-gray-400 hover:text-white text-xl">✕</button>
              </div>
              <div className="space-y-3">
                <div>
                  <div className="text-xs text-gray-400">Domain</div>
                  <div className="font-mono text-sm text-white bg-black/30 p-2 rounded-lg">{selectedAlert.domain}</div>
                </div>
                <div>
                  <div className="text-xs text-gray-400">Risk Score</div>
                  <div className="text-2xl font-bold text-red-400">{selectedAlert.riskScore}/100</div>
                </div>
                <div>
                  <div className="text-xs text-gray-400 mb-2">Threats Detected ({selectedAlert.threats?.length || 0})</div>
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {selectedAlert.threats?.map((threat, idx) => {
                      const severity = getThreatSeverity(threat);
                      return (
                        <div key={idx} className={`p-2 rounded-lg ${severity.bgColor} border-l-4 ${severity.borderColor}`}>
                          <div className="flex items-center gap-2 mb-1">
                            <span>{severity.icon}</span>
                            <span className="text-xs font-bold" style={{ color: severity.color }}>{severity.level}</span>
                          </div>
                          <div className="text-sm text-red-300">⚠️ {threat}</div>
                        </div>
                      );
                    })}
                  </div>
                </div>
                <div>
                  <div className="text-xs text-gray-400">Time Detected</div>
                  <div className="text-sm text-gray-300">{new Date(selectedAlert.timestamp).toLocaleString()}</div>
                </div>
              </div>
              <div className="flex gap-3 mt-6">
                <button
                  onClick={() => window.open(process.env.NEXT_PUBLIC_BASE_URL || 'https://lokey-secure.vercel.app', '_blank')}
                  className="flex-1 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white font-bold py-2 rounded-lg transition-all"
                >
                  View Dashboard
                </button>
                <button onClick={() => setSelectedAlert(null)} className="flex-1 bg-gray-700 hover:bg-gray-600 text-white font-bold py-2 rounded-lg transition-all">Close</button>
              </div>
            </div>
          </div>
        </div>
      )}

      <style jsx>{`
        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        .animate-fadeIn {
          animation: fadeIn 0.2s ease-out;
        }
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}
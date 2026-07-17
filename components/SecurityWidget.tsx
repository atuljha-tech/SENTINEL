'use client';

import { useState, useEffect } from 'react';

interface SecurityWidgetProps {
  initialScore?: number;
  domain?: string;
  onClose?: () => void;
}

export default function SecurityWidget({ initialScore = 100, domain = 'current site', onClose }: SecurityWidgetProps) {
  const [score, setScore] = useState(initialScore);
  const [isExpanded, setIsExpanded] = useState(false);
  const [threats, setThreats] = useState<string[]>([]);
  const [isMinimized, setIsMinimized] = useState(false);

  useEffect(() => {
    // Fetch real-time security score from API
    const fetchSecurityScore = async () => {
      try {
        const response = await fetch('/api/website-security');
        const result = await response.json();
        if (result.success && result.stats) {
          setScore(result.stats.latestScore || initialScore);
          if (result.alerts && result.alerts.length > 0) {
            const newThreats = result.alerts.slice(0, 3).map((a: any) => a.threats?.[0] || 'Suspicious activity detected');
            setThreats(newThreats);
          }
        }
      } catch (error) {
        console.error('Error fetching security score:', error);
      }
    };

    fetchSecurityScore();
    const interval = setInterval(fetchSecurityScore, 5000);
    return () => clearInterval(interval);
  }, [initialScore]);

  const getScoreColor = () => {
    if (score >= 80) return '#22c55e';
    if (score >= 60) return '#eab308';
    if (score >= 40) return '#f97316';
    return '#ef4444';
  };

  const getScoreLabel = () => {
    if (score >= 80) return 'SAFE';
    if (score >= 60) return 'CAUTION';
    if (score >= 40) return 'RISKY';
    return 'DANGER';
  };

  const getScoreMessage = () => {
    if (score >= 80) return 'This website appears secure';
    if (score >= 60) return 'Some security concerns detected';
    if (score >= 40) return 'High risk - proceed with caution';
    return 'Critical threat detected! Leave immediately';
  };

  if (isMinimized) {
    return (
      <div
        onClick={() => setIsMinimized(false)}
        className="fixed bottom-4 left-4 z-50 cursor-pointer group"
      >
        <div className="w-12 h-12 bg-gradient-to-br from-gray-800 to-gray-900 rounded-full border-2 flex items-center justify-center shadow-lg transition-all duration-300 group-hover:scale-110"
          style={{ borderColor: getScoreColor() }}>
          <span className="text-lg">🛡️</span>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed bottom-4 left-4 z-50 animate-slideIn">
      <div className="bg-gradient-to-br from-gray-900 to-gray-800 rounded-2xl shadow-2xl border border-gray-700 w-80 overflow-hidden">
        {/* Header */}
        <div className="p-4 bg-gradient-to-r from-gray-800 to-gray-900 border-b border-gray-700 flex justify-between items-center">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 bg-gradient-to-r from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
              <span className="text-sm">🛡️</span>
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">AI-NMS Guardian</h3>
              <p className="text-xs text-gray-400">Real-time Security</p>
            </div>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => setIsExpanded(!isExpanded)}
              className="text-gray-400 hover:text-white transition"
            >
              {isExpanded ? '▲' : '▼'}
            </button>
            <button
              onClick={() => setIsMinimized(true)}
              className="text-gray-400 hover:text-white transition"
            >
              ─
            </button>
            {onClose && (
              <button onClick={onClose} className="text-gray-400 hover:text-white transition">
                ✕
              </button>
            )}
          </div>
        </div>

        {/* Score Circle */}
        <div className="p-6 text-center">
          <div className="relative inline-block">
            <svg className="w-32 h-32 transform -rotate-90">
              <circle
                cx="64"
                cy="64"
                r="58"
                stroke="#374151"
                strokeWidth="8"
                fill="none"
              />
              <circle
                cx="64"
                cy="64"
                r="58"
                stroke={getScoreColor()}
                strokeWidth="8"
                fill="none"
                strokeDasharray={`${(score / 100) * 364} 364`}
                strokeLinecap="round"
                className="transition-all duration-700"
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-4xl font-bold" style={{ color: getScoreColor() }}>
                {score}
              </span>
              <span className="text-xs text-gray-400 mt-1">SECURITY</span>
            </div>
          </div>
          <div className="mt-3">
            <span className={`inline-block px-3 py-1 rounded-full text-xs font-bold ${
              score >= 80 ? 'bg-green-900 text-green-300' :
              score >= 60 ? 'bg-yellow-900 text-yellow-300' :
              score >= 40 ? 'bg-orange-900 text-orange-300' :
              'bg-red-900 text-red-300'
            }`}>
              {getScoreLabel()}
            </span>
          </div>
          <p className="text-xs text-gray-400 mt-2">{getScoreMessage()}</p>
        </div>

        {/* Expanded Content */}
        {isExpanded && (
          <div className="p-4 border-t border-gray-700 bg-gray-800/50">
            <div className="mb-3">
              <div className="flex justify-between text-xs text-gray-400 mb-1">
                <span>Security Score</span>
                <span style={{ color: getScoreColor() }}>{score}/100</span>
              </div>
              <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{ width: `${score}%`, backgroundColor: getScoreColor() }}
                />
              </div>
            </div>

            <div className="mb-3">
              <div className="text-xs text-gray-400 mb-2">⚠️ Detected Issues</div>
              {threats.length > 0 ? (
                <div className="space-y-1">
                  {threats.map((threat, idx) => (
                    <div key={idx} className="text-xs text-red-400 flex items-center gap-2">
                      <span>⚠️</span> {threat}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs text-green-400 flex items-center gap-2">
                  <span>✅</span> No threats detected
                </div>
              )}
            </div>

            <button
              onClick={() => window.open(process.env.NEXT_PUBLIC_BASE_URL || 'https://lokey-secure.vercel.app', '_blank')}
              className="w-full mt-2 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white text-sm font-bold py-2 rounded-lg transition-all"
            >
              View Full Dashboard →
            </button>
          </div>
        )}

        {/* Footer */}
        <div className="px-4 py-2 bg-gray-800/50 text-center text-[10px] text-gray-500 border-t border-gray-700">
          Powered by Agentic AI | Real-time Protection
        </div>
      </div>

      <style jsx>{`
        @keyframes slideIn {
          from {
            transform: translateX(-100%);
            opacity: 0;
          }
          to {
            transform: translateX(0);
            opacity: 1;
          }
        }
        .animate-slideIn {
          animation: slideIn 0.3s ease-out;
        }
      `}</style>
    </div>
  );
}
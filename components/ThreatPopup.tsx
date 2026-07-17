'use client';

import { useState, useEffect } from 'react';

interface ThreatPopupProps {
  domain: string;
  riskScore: number;
  threats: string[];
  onClose?: () => void;
  onViewDetails?: () => void;
  autoCloseDelay?: number;
}

export default function ThreatPopup({
  domain,
  riskScore,
  threats,
  onClose,
  onViewDetails,
  autoCloseDelay = 15000
}: ThreatPopupProps) {
  const [isVisible, setIsVisible] = useState(true);
  const [countdown, setCountdown] = useState(autoCloseDelay / 1000);

  useEffect(() => {
    if (autoCloseDelay > 0) {
      const timer = setInterval(() => {
        setCountdown((prev) => {
          if (prev <= 1) {
            clearInterval(timer);
            handleClose();
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
      return () => clearInterval(timer);
    }
  }, [autoCloseDelay]);

  const handleClose = () => {
    setIsVisible(false);
    onClose?.();
  };

  const handleViewDetails = () => {
    onViewDetails?.();
    handleClose();
  };

  if (!isVisible) return null;

  const severity = riskScore >= 70 ? 'critical' : riskScore >= 50 ? 'high' : riskScore >= 30 ? 'medium' : 'low';
  
  const severityConfig = {
    critical: { icon: '🚨', color: 'red', title: 'CRITICAL SECURITY THREAT', bgGradient: 'from-red-900 to-red-800' },
    high: { icon: '⚠️', color: 'orange', title: 'HIGH RISK DETECTED', bgGradient: 'from-orange-900 to-orange-800' },
    medium: { icon: '⚠️', color: 'yellow', title: 'Security Warning', bgGradient: 'from-yellow-900 to-yellow-800' },
    low: { icon: 'ℹ️', color: 'blue', title: 'Security Notice', bgGradient: 'from-blue-900 to-blue-800' }
  };

  const config = severityConfig[severity];

  return (
    <div className="fixed top-4 right-4 z-50 animate-slideInRight">
      <div className={`bg-gradient-to-br ${config.bgGradient} rounded-2xl shadow-2xl border-2 w-96 overflow-hidden`}
        style={{ borderColor: config.color === 'red' ? '#ef4444' : config.color === 'orange' ? '#f97316' : config.color === 'yellow' ? '#eab308' : '#3b82f6' }}>
        
        {/* Header */}
        <div className="p-4 bg-black/30 flex justify-between items-start">
          <div className="flex items-center gap-3">
            <div className="text-3xl animate-pulse">{config.icon}</div>
            <div>
              <h3 className="text-lg font-bold text-white">{config.title}</h3>
              <p className="text-xs text-gray-300">Detected by AI-NMS Guardian</p>
            </div>
          </div>
          <button onClick={handleClose} className="text-gray-400 hover:text-white transition text-xl">
            ✕
          </button>
        </div>

        {/* Content */}
        <div className="p-4">
          <div className="mb-3">
            <div className="text-xs text-gray-300 mb-1">Domain</div>
            <div className="font-mono text-sm text-white bg-black/30 p-2 rounded-lg break-all">
              {domain}
            </div>
          </div>

          <div className="mb-3">
            <div className="flex justify-between text-xs text-gray-300 mb-1">
              <span>Risk Score</span>
              <span className={`font-bold ${
                riskScore >= 70 ? 'text-red-400' :
                riskScore >= 50 ? 'text-orange-400' :
                riskScore >= 30 ? 'text-yellow-400' : 'text-blue-400'
              }`}>{riskScore}/100</span>
            </div>
            <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{ width: `${riskScore}%`, backgroundColor: config.color === 'red' ? '#ef4444' : config.color === 'orange' ? '#f97316' : config.color === 'yellow' ? '#eab308' : '#3b82f6' }}
              />
            </div>
          </div>

          <div className="mb-4">
            <div className="text-xs text-gray-300 mb-2 flex items-center gap-2">
              <span>⚠️ Threats Detected ({threats.length})</span>
            </div>
            <div className="space-y-2 max-h-40 overflow-y-auto">
              {threats.slice(0, 5).map((threat, idx) => (
                <div key={idx} className="text-xs text-red-300 bg-red-900/30 p-2 rounded-lg flex items-start gap-2">
                  <span>⚠️</span>
                  <span>{threat}</span>
                </div>
              ))}
              {threats.length === 0 && (
                <div className="text-xs text-green-300 bg-green-900/30 p-2 rounded-lg flex items-center gap-2">
                  <span>✅</span>
                  <span>No specific threats identified</span>
                </div>
              )}
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex gap-3">
            <button
              onClick={handleViewDetails}
              className="flex-1 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white text-sm font-bold py-2.5 rounded-lg transition-all"
            >
              View Details →
            </button>
            <button
              onClick={handleClose}
              className="px-4 bg-gray-700 hover:bg-gray-600 text-white text-sm font-bold py-2.5 rounded-lg transition-all"
            >
              Dismiss
            </button>
          </div>

          {/* Auto-close countdown */}
          {autoCloseDelay > 0 && (
            <div className="mt-3 text-center">
              <div className="text-[10px] text-gray-500">
                Auto-closing in {countdown}s
                <div className="w-full bg-gray-700 rounded-full h-0.5 mt-1">
                  <div
                    className="bg-gray-500 h-0.5 rounded-full transition-all"
                    style={{ width: `${(countdown / (autoCloseDelay / 1000)) * 100}%` }}
                  />
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      <style jsx>{`
        @keyframes slideInRight {
          from {
            transform: translateX(100%);
            opacity: 0;
          }
          to {
            transform: translateX(0);
            opacity: 1;
          }
        }
        .animate-slideInRight {
          animation: slideInRight 0.3s ease-out;
        }
      `}</style>
    </div>
  );
}
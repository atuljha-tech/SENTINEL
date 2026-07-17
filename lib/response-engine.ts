// Autonomous Response Engine
// This handles automated defensive actions

export interface BlockedIP {
  ip: string;
  blockedAt: Date;
  reason: string;
  attackType: string;
  riskScore: number;
}

// Store blocked IPs (in memory - for demo)
// In production, this would be in a database
let blockedIPs: BlockedIP[] = [];

// Response actions available
export type ResponseAction = 
  | 'BLOCK_IP'
  | 'RATE_LIMIT'
  | 'ALERT_ONLY'
  | 'LOG_ONLY'
  | 'CAPTCHA_CHALLENGE';

export interface ResponseDecision {
  action: ResponseAction;
  reason: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  autoExecute: boolean;
}

// Autonomous Response Engine
export class AutonomousResponseEngine {
  
  // Decide what action to take based on detection
  decideAction(
    attackType: string, 
    riskScore: number, 
    threatStatus: string,
    ip: string
  ): ResponseDecision {
    
    // Check if IP is already blocked
    if (this.isIPBlocked(ip)) {
      return {
        action: 'BLOCK_IP',
        reason: `IP ${ip} is already in blocklist`,
        severity: 'High',
        autoExecute: true
      };
    }
    
    // High risk - Critical attacks
    if (riskScore >= 80) {
      return {
        action: 'BLOCK_IP',
        reason: `Critical threat detected: ${attackType} with risk score ${riskScore}`,
        severity: 'Critical',
        autoExecute: true
      };
    }
    
    // High risk attacks
    if (riskScore >= 60) {
      if (attackType === 'DDoS') {
        return {
          action: 'RATE_LIMIT',
          reason: `DDoS attack detected from ${ip}. Implementing rate limiting.`,
          severity: 'High',
          autoExecute: true
        };
      }
      
      if (attackType === 'Brute Force') {
        return {
          action: 'CAPTCHA_CHALLENGE',
          reason: `Brute force attempt from ${ip}. Adding CAPTCHA challenge.`,
          severity: 'High',
          autoExecute: true
        };
      }
      
      return {
        action: 'BLOCK_IP',
        reason: `High risk ${attackType} attack from ${ip}. Blocking IP.`,
        severity: 'High',
        autoExecute: true
      };
    }
    
    // Medium risk - Suspicious
    if (riskScore >= 35) {
      if (attackType === 'Port Scan') {
        return {
          action: 'RATE_LIMIT',
          reason: `Port scan detected from ${ip}. Rate limiting connections.`,
          severity: 'Medium',
          autoExecute: true
        };
      }
      
      if (attackType === 'Bot Traffic') {
        return {
          action: 'CAPTCHA_CHALLENGE',
          reason: `Bot traffic detected from ${ip}. Adding CAPTCHA verification.`,
          severity: 'Medium',
          autoExecute: true
        };
      }
      
      return {
        action: 'ALERT_ONLY',
        reason: `Suspicious activity from ${ip}. Monitoring only.`,
        severity: 'Medium',
        autoExecute: false
      };
    }
    
    // Low risk - Normal traffic
    return {
      action: 'LOG_ONLY',
      reason: `Normal traffic from ${ip}. No action needed.`,
      severity: 'Low',
      autoExecute: false
    };
  }
  
  // Execute response action
  async executeAction(
    action: ResponseAction, 
    ip: string, 
    reason: string
  ): Promise<{ success: boolean; message: string }> {
    
    switch (action) {
      case 'BLOCK_IP':
        return this.blockIP(ip, reason);
        
      case 'RATE_LIMIT':
        return this.applyRateLimit(ip, reason);
        
      case 'CAPTCHA_CHALLENGE':
        return this.addCaptchaChallenge(ip, reason);
        
      case 'ALERT_ONLY':
        return this.sendAlert(ip, reason);
        
      case 'LOG_ONLY':
        return this.logOnly(ip, reason);
        
      default:
        return {
          success: true,
          message: `No action taken for ${ip}`
        };
    }
  }
  
  // Block an IP address
  private async blockIP(ip: string, reason: string): Promise<{ success: boolean; message: string }> {
    if (!this.isIPBlocked(ip)) {
      blockedIPs.push({
        ip,
        blockedAt: new Date(),
        reason,
        attackType: 'Unknown',
        riskScore: 0
      });
      console.log(`🚫 BLOCKED IP: ${ip} - ${reason}`);
      return {
        success: true,
        message: `IP ${ip} has been blocked. Reason: ${reason}`
      };
    }
    return {
      success: true,
      message: `IP ${ip} is already blocked`
    };
  }
  
  // Apply rate limiting
  private async applyRateLimit(ip: string, reason: string): Promise<{ success: boolean; message: string }> {
    console.log(`⏱️ RATE LIMITED: ${ip} - ${reason}`);
    return {
      success: true,
      message: `Rate limiting applied to ${ip}. Reason: ${reason}`
    };
  }
  
  // Add CAPTCHA challenge
  private async addCaptchaChallenge(ip: string, reason: string): Promise<{ success: boolean; message: string }> {
    console.log(`🤖 CAPTCHA REQUIRED: ${ip} - ${reason}`);
    return {
      success: true,
      message: `CAPTCHA challenge added for ${ip}. Reason: ${reason}`
    };
  }
  
  // Send alert
  private async sendAlert(ip: string, reason: string): Promise<{ success: boolean; message: string }> {
    console.log(`⚠️ ALERT: ${ip} - ${reason}`);
    return {
      success: true,
      message: `Alert generated for ${ip}. Reason: ${reason}`
    };
  }
  
  // Log only
  private async logOnly(ip: string, reason: string): Promise<{ success: boolean; message: string }> {
    console.log(`📝 LOGGED: ${ip} - ${reason}`);
    return {
      success: true,
      message: `Activity from ${ip} logged. No action taken.`
    };
  }
  
  // Check if IP is blocked
  isIPBlocked(ip: string): boolean {
    return blockedIPs.some(b => b.ip === ip);
  }
  
  // Get all blocked IPs
  getBlockedIPs(): BlockedIP[] {
    return blockedIPs;
  }
  
  // Unblock an IP
  unblockIP(ip: string): boolean {
    const initialLength = blockedIPs.length;
    blockedIPs = blockedIPs.filter(b => b.ip !== ip);
    return blockedIPs.length < initialLength;
  }
}

// Create singleton instance
export const responseEngine = new AutonomousResponseEngine();
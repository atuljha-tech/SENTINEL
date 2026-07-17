import { NextRequest, NextResponse } from 'next/server';
import { 
  retrieveKnowledge, 
  getAllAttackTypes, 
  searchKnowledge,
  getMitigationSteps,
  getPreventionTips
} from '@/lib/rag-knowledge';

// GET: Retrieve knowledge about an attack
export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams;
    const attackType = searchParams.get('attackType');
    const keyword = searchParams.get('search');
    const action = searchParams.get('action');
    
    // Search by keyword
    if (keyword) {
      const results = searchKnowledge(keyword);
      return NextResponse.json({
        success: true,
        results,
        count: results.length
      });
    }
    
    // Get mitigation steps
    if (action === 'mitigation' && attackType) {
      const steps = getMitigationSteps(attackType);
      return NextResponse.json({
        success: true,
        attackType,
        mitigation: steps
      });
    }
    
    // Get prevention tips
    if (action === 'prevention' && attackType) {
      const tips = getPreventionTips(attackType);
      return NextResponse.json({
        success: true,
        attackType,
        prevention: tips
      });
    }
    
    // Get all attack types
    if (action === 'list') {
      const types = getAllAttackTypes();
      return NextResponse.json({
        success: true,
        attackTypes: types
      });
    }
    
    // Get knowledge for specific attack type
    if (attackType) {
      const knowledge = retrieveKnowledge(attackType);
      
      if (!knowledge) {
        return NextResponse.json({
          success: false,
          message: `No knowledge found for attack type: ${attackType}`
        }, { status: 404 });
      }
      
      return NextResponse.json({
        success: true,
        knowledge
      });
    }
    
    // Default: return all knowledge
    return NextResponse.json({
      success: true,
      message: 'Use attackType parameter to get specific knowledge',
      availableTypes: getAllAttackTypes()
    });
    
  } catch (error) {
    console.error('RAG error:', error);
    return NextResponse.json({
      success: false,
      message: 'Failed to retrieve knowledge'
    }, { status: 500 });
  }
}

// POST: Get AI-powered recommendations based on detection
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { attackType, riskScore, threatStatus, reasons } = body;
    
    if (!attackType || attackType === 'None') {
      return NextResponse.json({
        success: true,
        message: 'No attack detected. Traffic appears normal.',
        recommendations: ['Continue monitoring', 'No immediate action required']
      });
    }
    
    const knowledge = retrieveKnowledge(attackType);
    
    if (!knowledge) {
      return NextResponse.json({
        success: false,
        message: `Unknown attack type: ${attackType}`,
        recommendations: ['Investigate manually', 'Check security logs']
      });
    }
    
    // Generate AI-enhanced response
    const response = {
      success: true,
      attack: {
        type: attackType,
        title: knowledge.title,
        severity: knowledge.severity,
        riskScore: riskScore
      },
      description: knowledge.description,
      howItWorks: knowledge.howItWorks,
      indicators: knowledge.indicators,
      impact: knowledge.impact,
      immediateActions: knowledge.mitigation.slice(0, 3),
      longTermPrevention: knowledge.prevention.slice(0, 3),
      tools: knowledge.tools,
      threatStatus: threatStatus,
      detectedReasons: reasons
    };
    
    return NextResponse.json(response);
    
  } catch (error) {
    console.error('RAG POST error:', error);
    return NextResponse.json({
      success: false,
      message: 'Failed to generate recommendations'
    }, { status: 500 });
  }
}
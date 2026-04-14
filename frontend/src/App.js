import { useState, useEffect } from "react";
import axios from "axios";
import "./App.css";

// ============================================
// ✅ ENVIRONMENT CONFIGURATION - PRODUCTION READY
// ============================================
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000";

function App() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [analysisResults, setAnalysisResults] = useState(null);
  const [activeTab, setActiveTab] = useState("analyzer");
  const [analysisHistory, setAnalysisHistory] = useState([]);
  const [xssResults, setXssResults] = useState(null);
  const [xssLoading, setXssLoading] = useState(false);
  const [discoveredParams, setDiscoveredParams] = useState([]);

  // ============================================
  // LOAD HISTORY FROM LOCAL STORAGE
  // ============================================
  useEffect(() => {
    const saved = localStorage.getItem("shieldaiHistory");
    if (saved) setAnalysisHistory(JSON.parse(saved));
  }, []);

  // ============================================
  // SECURITY ANALYSIS FUNCTION
  // ============================================
  const startSecurityAnalysis = async () => {
    setLoading(true);
    setAnalysisResults(null);
    
    try {
      const res = await axios.post(`${API_BASE_URL}/api/security/analyze`, {
        url: url,
        deepAnalysis: true
      });
      
      setAnalysisResults(res.data.analysis);
      
      const newHistory = [{
        url: url,
        date: new Date().toISOString(),
        score: res.data.analysis.attackSurfaceScore,
        observations: res.data.analysis.observations.length
      }, ...analysisHistory].slice(0, 10);
      
      setAnalysisHistory(newHistory);
      localStorage.setItem("shieldaiHistory", JSON.stringify(newHistory));
      
    } catch (error) {
      alert("Analysis failed: " + (error.response?.data?.error || error.message));
    } finally {
      setLoading(false);
    }
  };

  // ============================================
  // XSS ANALYSIS FUNCTION
  // ============================================
  const startXSSAnalysis = async () => {
    setXssLoading(true);
    setXssResults(null);
    
    try {
      const res = await axios.post(`${API_BASE_URL}/api/xss/analyze`, {
        url: url,
        params: discoveredParams.length > 0 ? discoveredParams : null
      });
      setXssResults(res.data.results);
    } catch (error) {
      alert("XSS analysis failed: " + (error.response?.data?.error || error.message));
    } finally {
      setXssLoading(false);
    }
  };

  // ============================================
  // DISCOVER PARAMETERS FUNCTION
  // ============================================
  const discoverParameters = async () => {
    setXssLoading(true);
    try {
      const res = await axios.post(`${API_BASE_URL}/api/params/discover`, { url: url });
      setDiscoveredParams(res.data.parameters);
      alert(`Discovered ${res.data.parameters.length} parameters for analysis`);
    } catch (error) {
      alert("Parameter discovery failed");
    } finally {
      setXssLoading(false);
    }
  };

  // ============================================
  // HELPER FUNCTION FOR CONFIDENCE CLASS
  // ============================================
  const getConfidenceClass = (confidence) => {
    switch(confidence) {
      case 'High': return 'confidence-high';
      case 'Medium': return 'confidence-medium';
      default: return 'confidence-low';
    }
  };

  // ============================================
  // RENDER COMPONENT
  // ============================================
  return (
    <div className="app">
      {/* SIDEBAR */}
      <div className="sidebar">
        <div className="logo">
          <h2>🛡️ ShieldAI</h2>
          <p>Security Observation Platform</p>
          <span className="badge-pro">REALISTIC</span>
        </div>
        
        <nav className="nav-menu">
          <button 
            className={`nav-item ${activeTab === "analyzer" ? "active" : ""}`} 
            onClick={() => setActiveTab("analyzer")}
          >
            <span>🛡️</span> Security Analyzer
          </button>
          <button 
            className={`nav-item ${activeTab === "xss" ? "active" : ""}`}
            onClick={() => setActiveTab("xss")}
          >
            <span>🔬</span> XSS Analysis
          </button>
          <button 
            className={`nav-item ${activeTab === "dashboard" ? "active" : ""}`}
            onClick={() => setActiveTab("dashboard")}
          >
            <span>📊</span> Dashboard
          </button>
        </nav>
        
        <div className="sidebar-footer">
          <p>🔐 No Fake Vulnerabilities</p>
          <p className="version">Professional Security Tool v3.0</p>
          <p className="disclaimer-small">Manual verification required</p>
        </div>
      </div>
      
      {/* MAIN CONTENT */}
      <div className="main-content">
        
        {/* ============================================ */}
        {/* SECURITY ANALYZER TAB */}
        {/* ============================================ */}
        {activeTab === "analyzer" && (
          <>
            <header className="header">
              <h1>🛡️ Security Posture Analyzer</h1>
              <p>Automated security observations requiring manual verification</p>
            </header>
            
            <div className="scan-card">
              <div className="input-group">
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onKeyPress={(e) => e.key === "Enter" && startSecurityAnalysis()}
                  placeholder="https://example.com"
                  disabled={loading}
                />
                <button onClick={startSecurityAnalysis} disabled={loading}>
                  {loading ? "🔍 Analyzing..." : "🛡️ Run Security Analysis"}
                </button>
              </div>
            </div>
            
            {loading && (
              <div className="loading-container">
                <div className="loading-spinner"></div>
                <p>🔬 Analyzing target security posture...</p>
                <p className="loading-hint">Checking headers • Analyzing JavaScript • Testing for reflections</p>
              </div>
            )}
            
            {analysisResults && (
              <div className="results-container">
                <div className="disclaimer-banner">
                  ⚠️ Automated security observations only. Manual verification required.
                </div>
                
                <div className="result-card">
                  <h3>📋 Executive Summary</h3>
                  <p className="executive-summary">{analysisResults.executiveSummary}</p>
                  <div className="score-container">
                    <span className="score-label">Attack Surface Score:</span>
                    <span className={`score-value ${analysisResults.attackSurfaceScore > 70 ? 'score-good' : analysisResults.attackSurfaceScore > 40 ? 'score-medium' : 'score-bad'}`}>
                      {analysisResults.attackSurfaceScore}/100
                    </span>
                    <span className="score-note">(Based on automated observations)</span>
                  </div>
                </div>
                
                {analysisResults.observations?.length > 0 && (
                  <div className="result-card">
                    <h3>🔍 Security Observations ({analysisResults.observations.length})</h3>
                    {analysisResults.observations.map((obs, idx) => (
                      <div key={idx} className={`observation-card ${getConfidenceClass(obs.confidence)}`}>
                        <div className="observation-header">
                          <span className="observation-name">{obs.name}</span>
                          <div className="observation-badges">
                            <span className={`severity-badge ${obs.severity.toLowerCase().replace(' ', '-')}`}>
                              {obs.severity}
                            </span>
                            <span className={`confidence-badge ${obs.confidence.toLowerCase()}`}>
                              {obs.confidenceLabel}
                            </span>
                          </div>
                        </div>
                        <div className="observation-body">
                          <p className="observation-description">{obs.description}</p>
                          {obs.location && (
                            <p className="observation-location">📍 {obs.location}</p>
                          )}
                          {obs.remediation && (
                            <p className="observation-remediation">🔧 Suggestion: {obs.remediation}</p>
                          )}
                          {obs.requiresManualVerification && (
                            <p className="observation-manual">⚠️ Manual verification required</p>
                          )}
                          {obs.bountyEstimate && (
                            <p className="observation-bounty">💰 {obs.bountyEstimate}</p>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
                
                <div className="result-card next-steps-card">
                  <h3>📝 Recommended Next Steps</h3>
                  <ul className="next-steps-list">
                    {analysisResults.nextSteps?.map((step, idx) => (
                      <li key={idx}>{step}</li>
                    ))}
                  </ul>
                </div>
                
                <div className="footer-disclaimer">
                  <small>{analysisResults.disclaimer}</small>
                </div>
              </div>
            )}
          </>
        )}
        
        {/* ============================================ */}
        {/* XSS ANALYSIS TAB */}
        {/* ============================================ */}
        {activeTab === "xss" && (
          <>
            <header className="header">
              <h1>🔬 XSS Reflection Analysis</h1>
              <p>Input reflection testing - Manual verification required</p>
            </header>
            
            <div className="scan-card">
              <div className="input-group">
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://example.com/page.php"
                  disabled={xssLoading}
                />
                <button onClick={discoverParameters} disabled={xssLoading}>
                  🔍 Discover Parameters
                </button>
                <button onClick={startXSSAnalysis} disabled={xssLoading}>
                  {xssLoading ? "Analyzing..." : "🔬 Analyze XSS"}
                </button>
              </div>
              
              {discoveredParams.length > 0 && (
                <div className="params-discovered">
                  <h4>📊 Discovered Parameters ({discoveredParams.length})</h4>
                  <div className="params-list">
                    {discoveredParams.slice(0, 20).map((param, idx) => (
                      <span key={idx} className="param-badge">{param}</span>
                    ))}
                    {discoveredParams.length > 20 && (
                      <span className="param-badge">+{discoveredParams.length - 20} more</span>
                    )}
                  </div>
                  <p className="params-note">Manual investigation recommended for each parameter</p>
                </div>
              )}
            </div>
            
            {xssLoading && (
              <div className="loading-container">
                <div className="loading-spinner"></div>
                <p>🔬 Testing {discoveredParams.length || "potential"} parameters for input reflection...</p>
                <p className="loading-hint">Testing basic and advanced payload patterns</p>
              </div>
            )}
            
            {xssResults && (
              <div className="results-container">
                <div className="result-card">
                  <h3>📊 XSS Analysis Summary</h3>
                  <div className="xss-stats">
                    <div className="stat">
                      <span className="stat-label">Parameters Tested:</span>
                      <span className="stat-value">{xssResults.totalParamsTested}</span>
                    </div>
                    <div className="stat">
                      <span className="stat-label">Reflections Found:</span>
                      <span className={`stat-value ${xssResults.reflections?.length > 0 ? 'warning' : 'success'}`}>
                        {xssResults.reflections?.length || 0}
                      </span>
                    </div>
                    <div className="stat">
                      <span className="stat-label">Requires Manual Review:</span>
                      <span className="stat-value warning">
                        {xssResults.requiresManual || 0}
                      </span>
                    </div>
                  </div>
                  <div className="xss-summary">
                    <p><strong>Recommendation:</strong> {xssResults.summary?.recommendation}</p>
                  </div>
                </div>
                
                {xssResults.reflections?.length > 0 && (
                  <div className="result-card">
                    <h3>⚠️ Input Reflections Found ({xssResults.reflections.length})</h3>
                    <p className="observation-manual">Manual verification required in browser</p>
                    {xssResults.reflections.slice(0, 10).map((ref, idx) => (
                      <div key={idx} className="reflection-item">
                        <div className="reflection-header">
                          <span className="reflection-param">{ref.parameter}</span>
                          <span className={`reflection-type ${ref.reflectionType}`}>
                            {ref.reflectionType} reflection
                          </span>
                        </div>
                        <code className="reflection-url">{ref.url.substring(0, 100)}...</code>
                        <div className="reflection-actions">
                          <button onClick={() => window.open(ref.url, '_blank')}>
                            🔬 Test in Browser
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
                
                <div className="result-card">
                  <h3>📋 Manual Testing Guide</h3>
                  <ul className="next-steps-list">
                    <li>Open each reflected URL in a browser with Developer Tools (F12)</li>
                    <li>Check if JavaScript executes (alert dialog appears)</li>
                    <li>Use Burp Suite Repeater for advanced testing</li>
                    <li>Test different payloads based on context</li>
                  </ul>
                </div>
              </div>
            )}
          </>
        )}
        
        {/* ============================================ */}
        {/* DASHBOARD TAB */}
        {/* ============================================ */}
        {activeTab === "dashboard" && (
          <div className="dashboard">
            <h2>📊 Analysis Dashboard</h2>
            <div className="stats-grid">
              <div className="stat-card">
                <h3>Total Analyses</h3>
                <p className="stat-number">{analysisHistory.length}</p>
              </div>
              <div className="stat-card">
                <h3>Average Score</h3>
                <p className="stat-number">
                  {Math.round(analysisHistory.reduce((acc, s) => acc + (s.score || 0), 0) / (analysisHistory.length || 1))}
                </p>
              </div>
              <div className="stat-card">
                <h3>Total Observations</h3>
                <p className="stat-number">
                  {analysisHistory.reduce((acc, s) => acc + (s.observations || 0), 0)}
                </p>
              </div>
            </div>
            
            <div className="history-list">
              <h3>Recent Security Analyses</h3>
              {analysisHistory.map((scan, idx) => (
                <div key={idx} className="history-item">
                  <div className="history-url">{scan.url}</div>
                  <div className="history-details">
                    <span className="history-score">Score: {scan.score}</span>
                    <span className="history-observations">{scan.observations} observations</span>
                    <span className="history-date">{new Date(scan.date).toLocaleString()}</span>
                  </div>
                </div>
              ))}
            </div>
            
            <div className="info-box">
              <h4>📖 About ShieldAI</h4>
              <p>ShieldAI is a security observation tool that helps identify potential attack surfaces.</p>
              <p><strong>Important:</strong> All findings require manual verification by a qualified security professional.</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
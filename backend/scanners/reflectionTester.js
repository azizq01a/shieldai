import axios from 'axios';

export class ReflectionTester {
  
  async testXSSReflection(url) {
    const testPayloads = [
      { payload: 'SHIELDAI_OBSERVATION_12345', type: 'simple', value: 'SHIELDAI_OBSERVATION_12345' },
      { payload: '<script>alert("Observation")</script>', type: 'xss_basic', value: '<script>alert("Observation")</script>' },
      { payload: '<img src=x onerror=alert("Observation")>', type: 'xss_img', value: '<img src=x onerror=alert("Observation")>' }
    ];
    
    const testParams = ['q', 'search', 's', 'id', 'page', 'query', 'keyword', 'term', 'name'];
    const results = [];
    
    console.log(`🔬 Testing ${testParams.length} parameters for input reflection...`);
    
    for (const param of testParams) {
      for (const test of testPayloads) {
        try {
          const testUrl = `${url}?${param}=${encodeURIComponent(test.payload)}`;
          const response = await axios.get(testUrl, { 
            timeout: 5000, 
            validateStatus: (status) => status < 500 
          });
          
          if (response.data.includes(test.value)) {
            results.push({
              parameter: param,
              payload: test.payload,
              type: test.type,
              reflected: true,
              url: testUrl,
              statusCode: response.status,
              confidence: 'Medium',
              note: 'Manual verification required'
            });
            break;
          }
        } catch(e) {}
      }
    }
    
    return {
      reflections: results,
      summary: results.length > 0 ? 
        `⚠️ ${results.length} parameter(s) reflect input. Manual security testing recommended.` : 
        '✅ No immediate reflection detected with basic payloads',
      recommendation: 'Use Burp Suite for comprehensive testing'
    };
  }
}
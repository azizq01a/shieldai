import PDFDocument from 'pdfkit';
import fs from 'fs';

export async function generatePDFReport(scanData, outputPath) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50, size: 'A4' });
    const stream = fs.createWriteStream(outputPath);
    
    doc.pipe(stream);
    
    // Header
    doc.fontSize(24)
       .font('Helvetica-Bold')
       .fillColor('#667eea')
       .text('ShieldAI Security Report', { align: 'center' });
    
    doc.moveDown();
    doc.fontSize(12)
       .font('Helvetica')
       .fillColor('#666666')
       .text(`Generated: ${new Date().toLocaleString()}`, { align: 'center' });
    
    doc.moveDown(2);
    
    // Target Information
    doc.fontSize(16)
       .font('Helvetica-Bold')
       .fillColor('#333333')
       .text('Target Information');
    
    doc.moveDown(0.5);
    doc.fontSize(12)
       .font('Helvetica')
       .text(`URL: ${scanData.url}`);
    doc.text(`Scan Date: ${new Date(scanData.timestamp).toLocaleString()}`);
    
    doc.moveDown();
    
    // Risk Score
    doc.fontSize(16)
       .font('Helvetica-Bold')
       .text('Risk Assessment');
    
    doc.moveDown(0.5);
    doc.fontSize(14)
       .font('Helvetica-Bold')
       .fillColor(getRiskColor(scanData.riskScore))
       .text(`Risk Score: ${scanData.riskScore}/100 - ${scanData.riskLevel}`);
    
    doc.fontSize(12)
       .font('Helvetica')
       .fillColor('#666666')
       .text(scanData.summary);
    
    doc.moveDown();
    
    // Issues Found
    if (scanData.issues && scanData.issues.length > 0) {
      doc.fontSize(16)
         .font('Helvetica-Bold')
         .fillColor('#333333')
         .text('Detected Issues');
      
      doc.moveDown(0.5);
      scanData.issues.forEach((issue, index) => {
        doc.fontSize(11)
           .font('Helvetica')
           .text(`${index + 1}. ${issue}`);
        doc.moveDown(0.3);
      });
    }
    
    doc.moveDown();
    
    // Vulnerabilities
    if (scanData.vulnerabilities && scanData.vulnerabilities.length > 0) {
      doc.fontSize(16)
         .font('Helvetica-Bold')
         .text('Vulnerabilities Found');
      
      doc.moveDown(0.5);
      scanData.vulnerabilities.forEach((vuln, index) => {
        doc.fontSize(11)
           .font('Helvetica')
           .fillColor('#dc3545')
           .text(`${index + 1}. ${vuln}`);
        doc.moveDown(0.3);
      });
    }
    
    doc.moveDown();
    
    // Recommendations
    if (scanData.fixes && scanData.fixes.length > 0) {
      doc.fontSize(16)
         .font('Helvetica-Bold')
         .fillColor('#28a745')
         .text('Recommended Fixes');
      
      doc.moveDown(0.5);
      scanData.fixes.forEach((fix, index) => {
        doc.fontSize(11)
           .font('Helvetica')
           .fillColor('#666666')
           .text(`✓ ${fix}`);
        doc.moveDown(0.3);
      });
    }
    
    doc.moveDown();
    
    // Exploit Risk
    doc.fontSize(16)
       .font('Helvetica-Bold')
       .fillColor('#333333')
       .text('Exploit Risk Assessment');
    
    doc.moveDown(0.5);
    doc.fontSize(12)
       .font('Helvetica')
       .fillColor('#666666')
       .text(scanData.exploitRisk);
    
    // Footer
    const pageCount = doc.bufferedPageRange().count;
    for (let i = 0; i < pageCount; i++) {
      doc.switchToPage(i);
      doc.fontSize(8)
         .fillColor('#999999')
         .text(
           `ShieldAI Security Report - Page ${i + 1} of ${pageCount}`,
           50,
           doc.page.height - 50,
           { align: 'center' }
         );
    }
    
    doc.end();
    
    stream.on('finish', () => {
      console.log(`PDF Report generated: ${outputPath}`);
      resolve(outputPath);
    });
    
    stream.on('error', reject);
  });
}

function getRiskColor(score) {
  if (score <= 20) return '#28a745';
  if (score <= 50) return '#ffc107';
  if (score <= 80) return '#fd7e14';
  return '#dc3545';
}

export function generateJSONReport(scanData) {
  return JSON.stringify(scanData, null, 2);
}

export function generateCSVReport(scanData) {
  const rows = [];
  
  // Header
  rows.push(['Type', 'Finding', 'Severity'].join(','));
  
  // Issues
  if (scanData.issues) {
    scanData.issues.forEach(issue => {
      rows.push(['Issue', issue, 'Medium'].join(','));
    });
  }
  
  // Vulnerabilities
  if (scanData.vulnerabilities) {
    scanData.vulnerabilities.forEach(vuln => {
      rows.push(['Vulnerability', vuln, 'High'].join(','));
    });
  }
  
  // Fixes
  if (scanData.fixes) {
    scanData.fixes.forEach(fix => {
      rows.push(['Recommendation', fix, 'Info'].join(','));
    });
  }
  
  return rows.join('\n');
}
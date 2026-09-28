import unittest
from io import BytesIO
from pypdf import PdfReader
from pdf_report import build_pdf


class PDFTests(unittest.TestCase):
    def test_historical_empty_report(self):
        reader = PdfReader(BytesIO(build_pdf({'findings': []})))
        text = '\n'.join(page.extract_text() for page in reader.pages)
        self.assertIn('No detections', text)
        self.assertIn('Risk profile unavailable', text)
        self.assertIn('No audit reference', text)

    def test_large_partial_report_escapes_markup_and_bounds_output(self):
        findings = [{'pattern': '<img src="https://example.invalid/a">', 'severity': 'high',
                     'file': 'x' * 2000, 'recommendation': 'Review & replace <weak> crypto.'} for _ in range(20000)]
        findings.append({'pattern': 'Critical asset', 'severity': 'critical'})
        report = {'source': '<b>Untrusted & literal</b>', 'partial': True, 'findings': findings,
                  'warnings': ['Skipped <file>'], 'audit_error': 'Preserved damaged chain'}
        pdf = build_pdf(report)
        reader = PdfReader(BytesIO(pdf))
        text = '\n'.join(page.extract_text() for page in reader.pages)
        self.assertIn('<b>Untrusted & literal</b>', text)
        self.assertIn('PARTIAL', text)
        self.assertIn('Critical asset', text)
        self.assertIn('Showing up to 20 of 20001', text)
        self.assertIn('Preserved damaged chain', text)
        self.assertGreater(len(reader.pages), 1)
        self.assertLess(len(reader.pages), 20)
        self.assertLess(len(pdf), 200000)


if __name__ == '__main__':
    unittest.main()

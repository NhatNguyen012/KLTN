import re
import unittest
from pathlib import Path

PAGE = (Path(__file__).resolve().parents[1] / 'central/app/soc.html').read_text()


class SocPage(unittest.TestCase):
    def test_no_html_injection_sinks(self):
        script = PAGE.split('<script>', 1)[1]
        for sink in ('innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval('):
            self.assertFalse(sink in script, f'HTML injection sink {sink} in the SOC page script')

    def test_export_uses_authenticated_fetch(self):
        self.assertNotRegex(PAGE, r'href="/v1/')
        self.assertIn("api('/v1/soc/verified-dataset')", PAGE)

    def test_csp_present(self):
        self.assertTrue(re.search(r'Content-Security-Policy', PAGE))


if __name__ == '__main__':
    unittest.main()

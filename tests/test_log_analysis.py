import unittest
from unittest.mock import mock_open, patch
from examples.log_analysis import analyze_log

class TestLogAnalysis(unittest.TestCase):

    @patch("builtins.open", new_callable=mock_open, read_data="""
    Failed password for user1 from 192.168.1.10
    Failed password for user1 from 192.168.1.10
    Failed password for user1 from 192.168.1.10
    Failed password for user1 from 192.168.1.10
    Failed password for user1 from 192.168.1.10
    Failed password for user1 from 192.168.1.10
    """)
    @patch("sys.stdout")
    def test_brute_force_detection(self, mock_stdout, mock_file):
        analyze_log("fake_log.txt")
        output = mock_stdout.write.call_args_list
        output_text = "".join(call[0][0] for call in output)
        self.assertIn("Suspicious IP: 192.168.1.10", output_text)

if __name__ == "__main__":
    unittest.main()

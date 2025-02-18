import unittest
import subprocess
import os
import shutil
from examples.github_secret_scanner import scan_repo

TEST_REPO_URL = "https://github.com/mikeful92/security-automation"
TEST_CLONE_DIR = "test_repo_clone"

class TestGitHubSecretScannerClone(unittest.TestCase):

    def setUp(self):
        """Clone the test repository before running the test"""
        if os.path.exists(TEST_CLONE_DIR):
            shutil.rmtree(TEST_CLONE_DIR)

        print(f"Cloning {TEST_REPO_URL} into {TEST_CLONE_DIR}...")
        subprocess.run(["git", "clone", TEST_REPO_URL, TEST_CLONE_DIR], check=True)

    def test_scan_cloned_repo(self):
        """Run the secret scanner on the cloned repository"""
        scan_repo(TEST_CLONE_DIR)
        self.assertTrue(os.path.exists(TEST_CLONE_DIR), "Repo was not cloned successfully")

    def tearDown(self):
        """Clean up the cloned repo after the test"""
        print(f"Removing cloned repo: {TEST_CLONE_DIR}")
        shutil.rmtree(TEST_CLONE_DIR, ignore_errors=True)

if __name__ == "__main__":
    unittest.main()
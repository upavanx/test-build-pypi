import unittest
import subprocess

class TestESBCLI(unittest.TestCase):
    def setUp(self):
        pass

    def test_help_command(self):
        ret = subprocess.run(["edgesoftware", "--help"],
                stdout = subprocess.DEVNULL)
        self.assertEqual(ret.returncode, 0)

    def test_help_command_failure(self):
        ret = subprocess.run(["edgesoftware", "help"],
                stderr = subprocess.DEVNULL)
        self.assertNotEqual(ret.returncode, 0)

    def test_log_command(self):
        ret = subprocess.run(["edgesoftware", "log"],
                stdout = subprocess.DEVNULL)
        self.assertEqual(ret.returncode, 0)

    def test_list_command(self):
        ret = subprocess.run(["edgesoftware", "list"],
                stdout = subprocess.DEVNULL)
        self.assertEqual(ret.returncode, 0)


if __name__ == "__main__":
    unittest.main()


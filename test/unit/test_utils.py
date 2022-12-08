import unittest
from edgesoftware.common import utils

class TestUtils(unittest.TestCase):
    def setUp(self):
        pass

    def test_format_component_name_success(self):
        test = ["test_add", "aaa", "", "_", "-"]
        ret = utils.format_component_name(test)
        self.assertEquals(ret, None)
        self.assertEquals(test, ["test add", "aaa", "", " ", "-"])

if __name__ == "__main__":
    unittest.main()

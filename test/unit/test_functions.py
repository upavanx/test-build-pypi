from edgesoftware import functions
import unittest


class TestList(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_list_packages_json(self):
        # TODO: Create dummy json file and test with different data
        ret = functions.list_packages()
        self.assertTrue(ret)
        ret = functions.list_packages(json_out=True)
        self.assertTrue(ret)
        ret = functions.list_packages(default=True, json_out=True)
        self.assertTrue(ret)




# Logger file to generate log statements
import logging
from edgesoftware.common import constants
import sys


class Logger(object):
    def __init__(self, file_name):
        self.LOGGER = logging.getLogger(__file__)
        self.LOGGER.setLevel(logging.DEBUG)
        FORMATTER = logging.Formatter(
            "%(asctime)s - %(levelname)-4s -" " %(message)s",
            datefmt="%a %b %d %I:%M:%S IST %Y",
        )
        self.file_handler = logging.FileHandler(file_name, "a+")
        self.file_handler.setFormatter(FORMATTER)
        self.LOGGER.addHandler(self.file_handler)

    def info(self, msg):
        """
        Method to define logging info
        :return: None
        """
        self.LOGGER.info(msg)

    def error(self, msg):
        """
        Method to define logging error
        :return: None
        """
        self.LOGGER.error(msg)

    def warn(self, msg):
        """
        Method to define logging warning
        :return: None
        """
        self.LOGGER.warning(msg)

    def console(
        self,
        log_msg,
        print_msg=None,
        error=False,
        color_code=None,
        new_line=True,
        flush=False,
    ):
        """
        Helper method to log and print the message
        :param print_msg: Message to print on the terminal
        :param log_msg: Message to log to file
        """
        if print_msg == None:
            print_msg = log_msg
        if new_line:
            if error:
                print(constants.RED.format(print_msg))
                self.error(log_msg)
            elif color_code:
                print(color_code.format(print_msg))
                self.info(log_msg)
            else:
                print(print_msg)
                self.info(log_msg)
        else:
            # FIXME: When new_line false, how to handle error and color_code
            if flush:
                print(print_msg, end="")
                sys.stdout.flush()
            else:
                print(print_msg, end="")

    def clean(self):
        self.LOGGER.removeHandler(self.file_handler)

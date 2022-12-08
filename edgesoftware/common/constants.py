import platform
import subprocess


def get_os_version():
    os_version = subprocess.run(
        "hostnamectl | grep Operating | " "cut -d':' -f2 | awk '{$1=$1};$1'",
        stdout=subprocess.PIPE,
        shell=True,
    )
    os_name = os_version.stdout.decode("ascii").strip("\n")
    if "Ubuntu 18.04" in os_name:
        os_name = "Ubuntu 18.04"
    elif "Ubuntu 20.04" in os_name:
        os_name = "Ubuntu 20.04"
    elif "Ubuntu 22.04" in os_name:
        os_name = "Ubuntu 22.04"
    elif "CentOS" in os_name:
        os_name = "CentOS 7"
    elif "Red Hat" in os_name:
        os_name = "RHEL 8"
    elif "Debian GNU/Linux 10" in os_name:
        os_name = "Debian 10"
    elif "Debian GNU/Linux 11" in os_name:
        os_name = "Debian 11"
    return os_name


# Log colors
CYAN = "\033[36m{}\033[00m"
GREEN = "\033[92m{}\033[00m"
BICYAN = "\033[1;96m{}\033[00m"
RED = "\033[91m{}\033[00m"
WHITE = "\033[37m{}\033[00m"
YELLOW = "\033[93m{}\033[00m"

# HTTP Status Codes

HTTP_STATUS = {
    "OK": 200,
    "CREATED": 201,
    "ACCEPTED": 202,
    "NO_CONTENT": 204,
    "NOT_MODIFIED": 304,
    "BAD_REQUEST": 400,
    "UNAUTHORIZED": 401,
    "NOT_FOUND": 404,
    "NOT_ALLOWED": 405,
    "CONFLICT": 409,
    "UNPROCESSABLE_ENTITY": 422,
    "TOO_MANY_REQUESTS": 429,
    "SERVER_ERR": 500,
    "BAD_GATEWAY": 502,
}

# Operating system
Operating_system = platform.system()
# Build env
if Operating_system == "Windows":
    BUILD_OS = "Windows"
elif Operating_system == "Linux":
    BUILD_OS = get_os_version()

# CLI version-tag

VERSION = "2022.3"
DATE = "19 August 2022"

VERSION_TAG = "{}, build date: {}, target OS: {}".format(VERSION, DATE, BUILD_OS)

# Domains
DOMAINS = ["http://www.google.com", "http://www.baidu.com", "http://www.intel.com"]

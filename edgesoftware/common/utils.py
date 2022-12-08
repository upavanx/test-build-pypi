from __future__ import print_function
import os
import subprocess
from subprocess import run, PIPE, check_output, Popen, DEVNULL, STDOUT
import sys
import tempfile
import urllib.request
import socket
import random
import string
import json
import shutil
import uuid
import requests
import re
import psutil
import math
import tarfile
import shutil
import base64
import hashlib
import wget
import platform
import docker
import csv

from inputimeout import inputimeout, TimeoutOccurred
from collections import OrderedDict
from configparser import ConfigParser
import defusedxml.ElementTree as ET
from zipfile import ZipFile
from pathlib2 import Path
from kubernetes import client, config
from kubernetes.client.rest import ApiException

from edgesoftware.common import constants
from edgesoftware.common import service_layer_api as api
from tqdm import tqdm


import argparse
from datetime import datetime, timedelta

# APP_VERSION registers ESH CLI version into LanternRock portal
APP_VERSION = constants.VERSION
# TID of ESH-CLI-PROD for LanternRock Analytics portal
ESH_CLI_PROD = "155f9474-9241-4336-abd0-c6f557775001"

if constants.Operating_system == "Linux":
    output_dir = "/var/log/esb-cli"
elif constants.Operating_system == "Windows":
    output_dir = "/log/esb-cli"
install_status_log = "install_status.json"
manifest_file = "edgesoftware_configuration.xml"
# TODO: check if LR_data and telemetry_data can be made one variable
LR_data = {}
LR_INSTALLED = False
success_container_ids = []
success_container_names = []
telemetry_data = {}
source_list = "/etc/apt/sources.list"
pip_conf_file = "pip.conf"
OS_Version = ""
if constants.Operating_system == "Linux":
    layers_dir = "/.intel/esh-layers/"
elif constants.Operating_system == "Windows":
    layers_dir = "/Intel/esh-layers/"
component_valid = {}
whitelist_components = []
region_flag = 0
china_supported_modules = []
if constants.Operating_system == "Windows":
    command = subprocess.run("where python", shell=True, stdout=subprocess.PIPE)
    site_package = command.stdout.decode("ascii").strip("\n")
    sitepackage_location = site_package.splitlines()[0].strip("python.exe")


def get_lanternrock_tid(log):
    """
    Get tid for ESH-CLI dev from config.ini or
    tid for ESH-CLI prod

    :returns: GUID for Lanternrock analytics portal
    """
    try:
        parser = ConfigParser()
        lanternrock_tid = None
        if os.path.exists("config.ini"):
            parser.read("config.ini")
            lanternrock_tid = parser.get("default", "esh_cli_dev")
        lanternrock_tid = lanternrock_tid if lanternrock_tid else ESH_CLI_PROD
        return lanternrock_tid
    except Exception as e:
        log.console("Exiting. LanternRock TID is missing.")
        sys.exit(-1)


def get_geolocation(log):
    geo_services_info = [
        ["http://ip-api.com/json/", "countryCode", "country"],
        ["https://ipapi.co/json/", "country_code", "country_name"],
        ["https://ip.useragentinfo.com/json/", "short_name", "country"],
    ]
    for url, code, country in geo_services_info:
        try:
            resp = requests.get(url, timeout=5)
            if resp.ok:
                ret = resp.json()
                country_name, country_code = ret[country], ret[code]
                log.info(f"Connected to a network in {country_name}")
                return country_code
            else:
                log.info(f"Server {url} returns {resp.status_code}.")
        except KeyError:
            log.info(f"Failed to get country name from server {url}.")
        except Exception as e:
            log.info(f"Failed to connect to {url}: {e}")
    log.info("Could not detect the geographic location.")
    return None

def identify_geolocation(log):
    country_code = get_geolocation(log)
    if country_code is None:
        return
    if country_code.lower() == "cn":
        global region_flag
        global china_supported_modules
        region_flag = 1
        package_id = get_recipe_details(manifest_file)["id"]
        os_id = get_recipe_details(manifest_file)["osId"]
        china_supported_modules = api.get_modules_list(
            package_id, os_id, country_code, log
        )
        tree = ET.parse(manifest_file)
        root = tree.getroot()
        for child in root:
            if child.tag in ["project", "default"]:
                name = child.attrib["label"]
                comp_id = child.attrib["id"]
                if china_supported_modules is not None:
                    if comp_id in china_supported_modules:
                        whitelist_components.append(name)
                else:
                    whitelist_components.append(name)
        display_list = whitelist_components
        log.console(
            "Connected to a network in China. Module availability is restricted in your region.",
            color_code=constants.YELLOW,
        )
        log.console(
            "Modules available for download in your region:", color_code=constants.CYAN
        )
        for comp in display_list:
            log.console(" {}".format(comp), color_code=constants.CYAN)
        check_count = 0
        while True:
            if check_count > 9:
                log.error("Maximum retries exceeded to override settings.")
                break
            check_count = check_count + 1
            try:
                log.console(
                    "For a successful installation, enter the URL for a local mirror site"
                    " for pip and apt package managers"
                )
                option = input(
                    constants.BICYAN.format(
                        "Do you want to override settings? Enter Yes or No: "
                    )
                )
                if option.lower() == "yes" or option.lower() == "y":
                    mirror = input(
                        constants.BICYAN.format(
                            "Please enter the URL for a local mirror site for pip and apt package managers: "
                        )
                    )
                    log.info("Mirror site entered: {}".format(mirror))
                    from urllib.parse import urlparse
                    import re

                    domain = "".join(["http://", mirror])
                    connection = urllib.request.urlopen(domain, timeout=10)
                    if connection.status == constants.HTTP_STATUS.get("OK"):
                        reg = "http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\), ]|(?:%[0-9a-fA-F][0-9a-fA-F]))"
                        if re.search(reg, mirror, re.IGNORECASE):
                            mirror = urlparse(mirror).netloc

                        log.console("Modifying settings")

                        command = [
                            "sudo",
                            "sed",
                            "-i",
                            "-e",
                            f"s/http:\/\/.*archive\.ubuntu\.com/http:\/\/{mirror}/g",
                            source_list,
                        ]
                        ret = run(command, stdout=PIPE, stderr=PIPE)

                        if ret.returncode:
                            log.console(
                                "Failed to modify settings for Ubuntu", error=True
                            )

                        pip_conf_path = os.path.join(Path.home(), ".config/pip")
                        if not os.path.isdir(pip_conf_path):
                            Path(pip_conf_path).mkdir(parents=True, exist_ok=True)

                        with open(
                            os.path.join(pip_conf_path, pip_conf_file), "w"
                        ) as fd:
                            fd.write("[global]\n")
                            fd.write("trusted-host = {0}\n".format(mirror))
                            fd.write(
                                "index-url = http://{0}/pypi/simple\n".format(mirror)
                            )
                        break
                    else:
                        log.console("Failed to connect")
                elif option.lower() == "no" or option.lower() == "n":
                    break
                else:
                    log.console(
                        "Invalid option. Valid " "options are YES or NO.\n", error=True
                    )
            except KeyboardInterrupt:
                log.console(
                    "Installation aborted by user. Exiting installation", error=True
                )
                sys.exit(-1)
            except Exception as e:
                log.console(
                    "Failed to modify settings. Please enter a valid URL. {}".format(e),
                    error=True,
                )


def install_git(log):
    """
    Install latest version of git
    """
    log.info("Installing Git")
    try:
        if constants.Operating_system == "Linux":
            git_link = (
                "https://packages.endpoint.com/rhel/7/os/x86_64/"
                "endpoint-repo-1.7-1.x86_64.rpm"
            )
            command = ["sudo", "yum", "remove", "-y", "git*"]
            ret = run(command, stdout=PIPE, stderr=PIPE)
            if ret.returncode:
                log.console(
                    "Failed to remove existing git", color_code=constants.YELLOW
                )
            command = ["sudo", "yum", "-y", "install", git_link]
            ret = run(command, stdout=PIPE, stderr=PIPE)
            command = ["sudo", "yum", "install", "-y", "git"]
            ret = run(command, stdout=PIPE, stderr=PIPE)
        elif constants.Operating_system == "Windows":
            git_link = (
                "https://github.com/git-for-windows/git/releases/download/"
                "v2.29.2.windows.2/Git-2.29.2.2-64-bit.exe"
            )
            wget.download(git_link)
            ret = subprocess.run(
                "Git-2.29.2.2-64-bit.exe /VERYSILENT /NORESTART", shell=True
            )
        if ret.returncode:
            msg = "Failed to install prerequisites. Exiting installation. {}"
            print_msg = "Failed to install prerequisites. Exiting installation."
            log.console(msg.format(ret.stderr), print_msg, error=True)
            sys.exit(-1)
    except Exception as e:
        msg = "Failed to install prerequisites. Exiting installation. {}"
        print_msg = "Failed to install prerequisites. Exiting installation."
        log.console(msg.format(e), print_msg, error=True)
        sys.exit(-1)


def check_installed(log, check_component):
    """
    Check the installation status of the component
    :param check_component: The component's status that is checked
    """
    output_dir_path = create_output_dir(manifest_file)
    install_status_json_path = os.path.join(output_dir_path, install_status_log)
    try:
        if (
            os.path.exists(install_status_json_path)
            and os.stat(install_status_json_path).st_size != 0
        ):
            with open(install_status_json_path, "r") as file:
                components = json.load(file)
            if check_component not in list(components.keys()):
                return False
            for component, val in components.items():
                if component == check_component:
                    if val["status"] == "FAILED":
                        return False
            return True
    except Exception as e:
        log.error(
            "Failed to verify the installation status of the component due to error {}".format(
                e
            )
        )


def get_network_time():
    try:
        res = urllib.request.urlopen("http://worldclockapi.com/api/json/utc/now")
        date_time = json.loads(res.read())
        return date_time["currentDateTime"]
    except Exception as e:
        return None


def format_component_name(component_name):
    length = len(component_name)
    for index in range(0, length):
        component_name[index] = component_name[index].replace("_", " ")


def validate_product_key(
    log, product_key, component_key, update=False, upgrade=False, download=False
):
    """
    Validate the given product key
    :param product_key: product key
    """
    output_dir_path = create_output_dir(manifest_file)
    install_status_log_path = os.path.join(output_dir_path, install_status_log)
    resp = api.validate_product_key(log, product_key, component_key)
    if not resp:
        if update or upgrade or download:
            log.console("Invalid Product Key. Exiting installation", error=True)
            return False
        else:
            if os.path.getsize(install_status_log_path):
                log.console(
                    "[WARNING] Invalid Product Key. Continuing "
                    "installation with local files",
                    color_code=constants.YELLOW,
                )
                return True
            else:
                log.console("Invalid Product Key. Exiting installation", error=True)
                return False
    else:
        log.console("Successfully validated Product Key", color_code=constants.GREEN)
        return True


def print_time(seconds):
    """
    Prints the time taken to install the component
    """
    hour = seconds // 3600
    seconds %= 3600
    minutes = seconds // 60
    seconds %= 60
    if minutes == 0:
        return_time = "{:.2f} seconds".format(seconds)
    elif hour == 0:
        if seconds == 0:
            return_time = "{:.0f} minutes".format(minutes)
        else:
            return_time = "{:.0f} minutes {:.2f} seconds".format(minutes, seconds)
    else:
        if minutes == 0:
            return_time = "{:.0f} hours".format(hour)
        else:
            return_time = "{:.0f} hour {:.2f} minutes".format(hour, minutes)
    return return_time


def python_version(log):
    """Recommended python version for ESB Cli"""

    RECOMMENDED_PYTHON_VERSION = (3, 6)

    python_ver = sys.version_info
    major_version = python_ver.major
    minor_version = python_ver.minor
    micro_version = python_ver.micro

    log.console(
        "Python version: {}.{}.{}".format(major_version, minor_version, micro_version),
        color_code=constants.WHITE,
    )

    # Abort on Python 2 and older versions.

    if (major_version, minor_version) < (3, 0):
        log.console(
            'Exiting installation. Update to Python {}.{} or above "\
                "and restart installation.'.format(
                *RECOMMENDED_PYTHON_VERSION
            ),
            error=True,
        )
        sys.exit(-1)


def get_component_list(file_name=None, xmlstring=None):
    component_list = OrderedDict()
    if file_name and os.path.exists(file_name):
        tree = ET.parse(file_name)
        root = tree.getroot()
        details = get_recipe_details(file_name)
    elif xmlstring:
        root = ET.fromstring(xmlstring)
        details = get_recipe_details(xml=root)
    else:
        return []
    label = details.get("label")
    version = details.get("version")
    dir_name = "_".join([label, version])
    for child in root:
        if child.tag in ["project", "default"]:
            name = child.attrib["label"]
            comp_id = child.attrib["id"]
            path = os.path.join(os.getcwd(), dir_name)
            if region_flag:
                if china_supported_modules is not None:
                    if name != "esb_common" and comp_id not in china_supported_modules:
                        continue
                    else:
                        pass
            component_list[comp_id] = {"path": path, "label": name}
            install = child.attrib.get("esb_install")
            if install == "true":
                component_list[comp_id].update({"esb_install": True})
        if child.tag in ["image"]:
            image_id = child.attrib["id"]
            label = child.attrib["label"]
            tag = child.attrib["tag"]
            component_list[image_id] = {"label": label, "tag": tag, "type": "image"}
        if child.tag in ["helm"]:
            helm_id = child.attrib["id"]
            label = child.attrib["label"]
            tag = child.attrib["tag"]
            path = os.path.join(os.getcwd(), dir_name)
            component_list[helm_id] = {
                "label": label,
                "tag": tag,
                "type": "helm",
                "path": path,
            }
    return component_list


def get_recipe_details(file_name=None, xml=None, common=False):
    if file_name:
        if os.path.exists(file_name):
            tree = ET.parse(file_name)
            root = tree.getroot()
        else:
            print(
                "Exiting Installation. Failed to find manifest file {}. "
                "Check the file location and run the command from the "
                "folder where the file is located.".format(file_name)
            )
            sys.exit(-1)
    if xml:
        root = xml

    details = {}
    for child in root:
        if child.tag == "main":
            details["label"] = child.attrib.get("label")
            details["id"] = child.attrib.get("id")
            details["version"] = child.attrib.get("version")
            details["packageId"] = child.attrib.get("packageId")
            details["osId"] = child.attrib.get("osId")
        if common and child.tag == "default":
            details["common_id"] = child.attrib.get("id")
            details["label"] = child.attrib.get("label")
    return details


def get_package_from_url(xml_details):
    package_id = xml_details.get("id")
    package_url = os.path.join(api.get_service_layer_url(), "recipe")
    api_packages = requests.get(package_url).json()
    package_label = ""
    if api_packages:
        for items in api_packages:
            if items.get("id", "") == package_id:
                package_version = items.get("version", "")
                package_label = items.get("name", "")
        if package_label != "":
            package_label = package_label["en"]
            return package_label, package_version
    if package_label == "":
        return "", ""


def find_element(root, element):
    """
    Finds element in the root Tree

    :param root: Root of the tree
    :param element: The element to find
    :returns: True if found. False otherwise
    """
    for child in root:
        if child.tag == "project" or child.tag == "image" or child.tag == "helm":
            if child.attrib["label"] == element:
                return True
    return False


def update_xml(file_name, element, log):
    """
    Updates the XML file

    :param file_name: XML file path
    :param element: List of elements to append
    """
    try:
        if os.path.exists(file_name):
            tree = ET.parse(file_name)
            installed_root = tree.getroot()
        else:
            log.console(
                "Manifest XML file {} not found. Exiting "
                "installation.".format(file_name),
                error=True,
            )
            sys.exit(-1)
    except ET.ParseError as e:
        log.console(
            "Failed to parse manifest file {}. {}. The manifest file "
            "should not be edited manually. Go to the Edge"
            "Software Hub to customize the configuration of the "
            "platform.".format(file_name, e),
            error=True,
        )
        sys.exit(-1)
    update_root = ET.fromstring(element)
    for child in update_root:
        if child.tag == "project" or child.tag == "image" or child.tag == "helm":
            comp_name = child.attrib["label"]
            if not find_element(installed_root, comp_name):
                installed_root.append(child)
    tree.write(file_name)


def write_xml(content):
    """
    Writes content to an temporary XML file.

    :param content: An XML string
    :returns: File name
    """
    scriptFile = tempfile.NamedTemporaryFile(delete=False)
    root = ET.fromstring(content)
    tree = ET.ElementTree(root)
    with open(scriptFile.name, "w") as f:
        tree.write(scriptFile.name)
    scriptFile.file.close()
    return scriptFile.name


def download_component(log, product_key, components, recipe_id, os_id):
    for component_id, value in components.items():
        if not is_image(value) and not is_helm(value):
            src_name = value["label"]
            src_path = value["path"]
            src_id = component_id
            log.console("Downloading component {}".format(src_name))
            try:
                if not os.path.isdir(src_path):
                    os.makedirs(src_path)
                api.fetch_ingredient(
                    product_key, src_name, recipe_id, os_id, src_id, src_path, log
                )
            except Exception as e:
                log.console(
                    "Failed to download component {} due to error "
                    "{}".format(src_name, e),
                    error=True,
                )

        if is_helm(value):
            name = value["label"]
            tag = value["tag"]
            src_path = value["path"]
            src_id = component_id
            log.console("Downloading Helm chart {}-{}".format(name, tag))
            try:
                if not os.path.isdir(src_path):
                    os.makedirs(src_path)
                api.fetch_helm(log, product_key, name, tag, src_id, src_path)
            except Exception as e:
                log.console(
                    "Failed to download Helm chart {} due to error "
                    "{}".format(src_name, e),
                    error=True,
                )


def extract_file(zf, info, extract_dir):
    """
    extracts a zip file with file permissions intact

    :param zf: ZipFile object
    :param info: elements of list containing ZipInfo objects
    :param extract_dir: directory where unzipped file will be extracted
    """
    zf.extract(info.filename, path=extract_dir)
    out_path = os.path.join(extract_dir, info.filename)
    perm = info.external_attr >> 16
    os.chmod(out_path, perm)


def install_common(src, manifest, log):
    log.console("Installing shared module 'esb_common'", color_code=constants.GREEN)
    common_id = get_recipe_details(manifest, common=True)["common_id"]
    try:
        cwd = os.getcwd()
        abs_src_path = os.path.abspath(src["path"])
        zip_file_path = os.path.join(abs_src_path, common_id)
        module = src["label"]
        zip_file = zip_file_path + ".zip"
        module_path = os.path.join(abs_src_path, module)

        if os.path.exists(zip_file):
            from zipfile import ZipFile

            with ZipFile(zip_file, "r") as zipObj:
                # Extract all the contents of zip file
                log.console(
                    "Unzipping the shared module 'esb_common'...",
                    color_code=constants.GREEN,
                )
                zipObj.extractall(module_path)
        else:
            log.console(
                "Failed to find shared module 'esb_common'. " "Exiting installation.",
                error=True,
            )
            return False

        os.chdir(os.path.join(module_path))
        if constants.Operating_system == "Linux":
            ret = subprocess.run(["sudo", "python3", "setup.py", "install"])
        elif constants.Operating_system == "Windows":
            ret = subprocess.run(["python", "setup.py", "install"])
        if ret.returncode:
            msg = "Failed to install shared module" " 'esb_common'. {}".format(
                ret.stderr
            )
            print(constants.RED.format(msg))
            log.error("Failed to run setup.py for esb_common. {}".format(ret.stderr))

        python_ver = (
            "python" + str(sys.version_info[0]) + "." + str(sys.version_info[1])
        )
        if constants.Operating_system == "Linux":
            if "CentOS" in OS_Version or "Red Hat" in OS_Version:
                python_lib_path = os.path.join(
                    "/usr/local/lib/", python_ver, "site-packages/esb_common"
                )
            else:
                python_lib_path = os.path.join(
                    "/usr/local/lib/", python_ver, "dist-packages/esb_common"
                )
            ret = subprocess.run(["sudo", "mkdir", "-p", python_lib_path])

            if ret.returncode:
                msg = "Failed to install shared module" " 'esb_common'. {}".format(
                    ret.stderr
                )
                print(constants.RED.format(msg))
                log.error(
                    "Failed to create 'esb_common' directory. {}".format(ret.stderr)
                )
                return False
            ret = subprocess.run(
                [
                    "sudo",
                    "cp",
                    module_path + "/esb_common/logger.py",
                    module_path + "/esb_common/locale.py",
                    module_path + "/esb_common/util.py",
                    python_lib_path,
                ]
            )
            if ret.returncode:
                msg = "Failed to install shared module" " 'esb_common'. {}".format(
                    ret.stderr
                )
                print(constants.RED.format(msg))
                log.error("Failed to copy 'esb_common' files. {}".format(ret.stderr))
                return False
        elif constants.Operating_system == "Windows":
            norm_path = os.path.join(
                sitepackage_location, "Lib", "site-packages", "esb_common"
            )
            python_lib_path = os.path.normpath(norm_path)
            if not os.path.exists(python_lib_path):
                try:
                    os.mkdir(python_lib_path)

                except Exception as e:
                    msg = "Failed to install shared module" " 'esb_common'. {}".format(
                        e
                    )
                    print(constants.RED.format(msg))
                    log.error("Failed to create 'esb_common' directory. {}".format(e))
                    return False

            esb_common_files = os.listdir(os.path.join(module_path, "esb_common"))
            if len(esb_common_files):
                for file in esb_common_files:
                    if (
                        file == "logger.pyd"
                        or file == "util.pyd"
                        or file == "locale.pyd"
                    ):
                        shutil.copy(os.path.join(module_path, "esb_common", file), python_lib_path)
            else:
                msg = "Failed to copy shared module 'esb_common'."
                print(constants.RED.format(msg))
                log.error("Failed to copy 'esb_common' files.")
                return False
    except Exception as e:
        msg = "Failed to install shared module 'esb_common'. {}".format(e)
        log.console(msg, error=True)
        return False
    finally:
        os.chdir(cwd)
    log.console(
        "Successfully installed shared module 'esb_common'.", color_code=constants.GREEN
    )
    return True


def create_output_dir(manifest=None):
    """
    Create output directory

    :param manifest: Manifest file
    :returns: The path of the output directory
    """
    try:
        path = os.path.join(output_dir)
        if manifest:
            details = get_recipe_details(manifest)
            label = details.get("label")
            version = details.get("version")
            if not label or not version:
                print(
                    "Failed to get label or version from Manifest XML file. "
                    "Please check your XML file."
                )
                sys.exit(-1)
            dir_name = "_".join([label, version])
            path = os.path.join(output_dir, dir_name)
        if not os.path.isdir(path):
            if constants.Operating_system == "Windows":
                os.makedirs(path)
            elif constants.Operating_system == "Linux":
                subprocess.run(["sudo", "mkdir", "-p", path])
                subprocess.run(["sudo", "chown", os.environ["USER"], path])
        return path
    except Exception as e:
        print(constants.RED.format("Failed to create log directory. {}".format(e)))
        sys.exit(-1)


def sys_info(log):
    """
    Target system information
    """
    try:
        system_info = {}
        global OS_Version
        if constants.Operating_system == "Linux":
            os_version = subprocess.run(
                "hostnamectl | grep Operating | " "cut -d':' -f2 | awk '{$1=$1};$1'",
                stdout=subprocess.PIPE,
                shell=True,
            )
            os_name = os_version.stdout.decode("ascii").strip("\n")
            OS_Version = os_name
            kernel_version = subprocess.run(
                "uname -r", stdout=subprocess.PIPE, shell=True
            )
            dec_kernel_version = kernel_version.stdout.decode("ascii").strip("\n")
            hardware_arch = subprocess.run(
                "uname -p", stdout=subprocess.PIPE, shell=True
            )
            dec_hardware_arch = hardware_arch.stdout.decode("ascii").strip("\n")
            processor = subprocess.run(
                "cat /proc/cpuinfo | grep 'model name' \
                                       | uniq | cut -d"
                ":"
                " -f2 | "
                "awk '{$1=$1};$1'",
                stdout=subprocess.PIPE,
                shell=True,
            )
            processor_name = processor.stdout.decode("ascii").strip("\n")
            vendor = subprocess.run(
                "cat /proc/cpuinfo | grep 'vendor' | uniq | cut -d"
                ":"
                " -f2 | "
                "awk '{$1=$1};$1'",
                stdout=subprocess.PIPE,
                shell=True,
            )
            vendor_id = vendor.stdout.decode("ascii").strip("\n")
            vendor_id = vendor_id.strip("\t")
            memory_size = psutil.virtual_memory()
            dec_memory = math.ceil(memory_size.total / (1024 ** 3))
            total = shutil.disk_usage("/").total / (1024 ** 3)
            free = shutil.disk_usage("/").free / (1024 ** 3)

            vpu = subprocess.run(
                'lsusb | grep "03e7" | wc -l', shell=True, stdout=subprocess.PIPE
            )
            dec_vpu = int(vpu.stdout.decode("utf-8").strip("\n"))
            fpga = subprocess.run(
                'lspci | grep "Processing accelerators:.*.Altera" \
                    | wc -l',
                shell=True,
                stdout=subprocess.PIPE,
            )
            dec_fpga = int(fpga.stdout.decode("utf-8"))

            cpu_util = psutil.cpu_percent()
            manu = subprocess.run(
                "sudo dmidecode -t system | grep 'Manufacturer' | cut -d"
                ":"
                " -f2 | "
                "awk '{$1=$1};$1'",
                stdout=subprocess.PIPE,
                shell=True,
            )
            manufacturer_info = manu.stdout.decode("ascii").strip("\n")
            prod = subprocess.run(
                "sudo dmidecode -t system | grep 'Product Name' | cut -d"
                ":"
                " -f2 | "
                "awk '{$1=$1};$1'",
                stdout=subprocess.PIPE,
                shell=True,
            )
            prod_info = prod.stdout.decode("ascii").strip("\n")
            platform_info = manufacturer_info + " " + prod_info
            system_info.update(
                {
                    "os_name": os_name,
                    "kernel": dec_kernel_version,
                    "hardware": dec_hardware_arch,
                    "processor": processor_name,
                    "vendor_id": vendor_id,
                    "memory": dec_memory,
                    "total_size": total,
                    "free_size": free,
                    "vpu": dec_vpu,
                    "fpga": dec_fpga,
                    "cpu_util": cpu_util,
                    "platform_info": platform_info,
                }
            )
        elif constants.Operating_system == "Windows":
            command = platform.platform().split("-")
            os_name = command[0] + " " + command[1]
            OS_Version = os_name
            dec_hardware_arch = platform.architecture()[0]
            processor_name = platform.processor()
            vendor_id = platform.processor().strip().split(",")[1]
            memory_size = psutil.virtual_memory()
            dec_memory = math.ceil(memory_size.total / (1024 ** 3))
            total = shutil.disk_usage("/").total / (1024 ** 3)
            free = shutil.disk_usage("/").free / (1024 ** 3)
            cpu_util = psutil.cpu_percent()
            cmd = ["wmic", "computersystem", "get", "model"]
            status = subprocess.run(cmd, stdout=subprocess.PIPE)
            platform_info = status.stdout.decode("ascii").strip("\n").splitlines()[2]
            system_info.update(
                {
                    "os_name": os_name,
                    "hardware": dec_hardware_arch,
                    "processor": processor_name,
                    "vendor_id": vendor_id,
                    "cpu_util": cpu_util,
                    "memory": dec_memory,
                    "total_size": total,
                    "free_size": free,
                    "platform_info": platform_info,
                }
            )
    except Exception as e:
        log.console("Failed to read System Information. {}".format(e), error=True)
    return system_info


def print_system_info(system_info, log):
    """
    Target system information
    """
    os_name = system_info["os_name"]
    hardware = system_info["hardware"]
    processor = system_info["processor"]
    memory = system_info["memory"]
    total = system_info["total_size"]
    free = system_info["free_size"]
    vendor = system_info["vendor_id"]
    cpu_util = system_info["cpu_util"]
    platform_info = system_info["platform_info"]
    if constants.Operating_system == "Linux":
        kernel = system_info["kernel"]
        vpu = system_info["vpu"]
        fpga = system_info["fpga"]
    try:
        if (
            "Ubuntu 18.04" not in os_name
            and "Ubuntu 20.04" not in os_name
            and "Ubuntu 22.04" not in os_name
            and "CentOS" not in os_name
            and "Windows" not in os_name
            and "Red Hat" not in os_name
            and "Debian" not in os_name
        ):
            log.console("Unsupported OS. Please check your OS version", error=True)
            sys.exit(-1)
        if "GenuineIntel" not in vendor:
            log.console(
                "Intel® Edge Software Hub packages are only "
                "supported on Intel® architecture",
                error=True,
            )
            sys.exit(-1)
        if constants.Operating_system == "Linux":
            if "CentOS" in os_name or "Red Hat" in os_name:
                command = ["sudo", "yum", "install", "usbutils", "-y"]
                ret = run(command, stdout=PIPE, stderr=PIPE)
                command = ["sudo", "yum", "install", "pciutils", "-y"]
                ret = run(command, stdout=PIPE, stderr=PIPE)
            hardware_acc_status = False
            if vpu != 0:
                hardware_acc_status = True
            if fpga != 0:
                hardware_acc_status = True

        xml_details = get_recipe_details(manifest_file)
        package_label, package_version = get_package_from_url(xml_details)
        if package_label == "":
            log.error("Failed to retrieve package information from url")
        log.console("SYSTEM INFO".center(50, "-"), color_code=constants.CYAN)
        if package_label != "":
            log.console("Package Name: {} {}".format(package_label, package_version))
        else:
            package_label = xml_details["label"]
            package_version = xml_details["version"]
            package_label = package_label.replace("_", " ")
            log.console("Package Name: {} {}".format(package_label, package_version))
        log.console("Product Name: {}".format(platform_info))
        log.console("CPU SKU: {}".format(processor))
        log.console("Memory Size: {} GB".format(round(memory)))
        log.console("Operating System: {}".format(os_name))
        if constants.Operating_system == "Linux":
            log.console("Kernel Version: {}".format(kernel))
            if vpu != 0:
                log.console("Accelerator(VPU): {}".format(vpu))
            if fpga != 0:
                log.console("Accelerator(FPGA): {}".format(fpga))
            if not hardware_acc_status:
                log.console("Accelerator: None")
        log.console("CPU Utilization: {}%".format(cpu_util))
        log.console("Available Disk Space: {:.0f} GB".format(free))

    except Exception as e:
        log.console("Failed to read System Information. {}".format(e), error=True)


def check_enough_memory(system_info, package_id, log):
    avail_memory = system_info["memory"]
    avail_disk = system_info["free_size"]
    memory_details = api.get_recipe_details(package_id, log)
    if memory_details is not None:
        min_memory = memory_details.get("memoryRequired", "")
        min_disk = memory_details.get("diskRequired", "")
        if min_memory == "" and min_disk == "":
            return
        if float(avail_memory) < float(min_memory) or float(avail_disk) < float(
            min_disk
        ):
            log.console(
                "WARNING: Installation may fail. The target device"
                " does not meet the minimum system requirement.",
                color_code=constants.YELLOW,
            )
            log.console(
                "Minimum memory requirement for this package: {} GB.".format(
                    min_memory
                ),
                color_code=constants.YELLOW,
            )
            log.console(
                "Minimum disk requirement for this package: {} GB.".format(min_disk),
                color_code=constants.YELLOW,
            )
    else:
        return


def modify_module_package_label(label):
    """
    Gets a package or module label and modifies
    it as per LR portal norms.
    :param label: module or package name with version
    """
    label = "".join(
        char
        for char in label
        if char.isalnum()
        or char == " "
        or char == "."
        or char == "-"
        or char == "_"
        or char == ":"
    )
    return label


def send_LR_data(data, log):
    """
    Send telemetry data to LanternRock portal
    :param data: Dictionary with telemetry info
    """
    LR_data.update(data)
    if (
        LR_data.get("success_ids")
        or LR_data.get("failed_ids")
        or LR_data.get("image_name")
        or LR_data.get("helm_chart")
        or LR_data.get("success_helm_ids")
        or LR_data.get("failed_helm_ids")
        or LR_data.get("success_container_ids")
        or LR_data.get("failed_container_ids")
    ):
        TID = get_lanternrock_tid(log)
        if os.path.isfile(manifest_file):
            xml_details = get_recipe_details(manifest_file)
            recipe_id = get_recipe_details(manifest_file)["id"]
            if "type" in LR_data and LR_data["type"] == "upgrade":
                recipe_id = LR_data["recipe_id"]
            try:
                package_details = api.get_recipe_details(recipe_id, log)
                package_label = package_details["name"]["en"]
                package_version = package_details["version"]
                all_modules = {}
                all_ingredients = package_details["ingredients"]
                for index in range(len(all_ingredients)):
                    module_id_key = all_ingredients[index]["id"]
                    module_id_label = all_ingredients[index]["name"]["en"]
                    module_id_version = all_ingredients[index]["version"]
                    module_id_label = module_id_label + ":" + module_id_version
                    all_modules[module_id_key] = module_id_label
            except Exception as e:
                log.error("Failed to get package and modules details.".format(e))

        import_LR_helper(log)

        global LR_INSTALLED
        if not LR_INSTALLED:
            return

        try:
            from lanternrock import (
                LanternRock,
                LanternRockArgumentError,
                LanternRockError,
                LanternRockInitializationError,
            )

            lr = LanternRock()
            log.info("Initializing LanternRock")
            log.info("CLI version: {}".format(APP_VERSION))
            lr.Initialize("ESH-CLI", APP_VERSION, TID, None, None)
            if "type" not in LR_data:
                LR_data.update({"type": "install"})
            if "configuration_id" in LR_data:
                ESH_configuration_id = {
                    "esh_configuration_id": LR_data["configuration_id"],
                    "esh_command_type": LR_data["type"],
                }
                lr.RecordEventEx(
                    None, "ESH_configuration_id", 1, 1.0, ESH_configuration_id
                )
            if "product_key" in LR_data:
                ESH_product_key = {"esh_product_key": LR_data["product_key"]}
                lr.RecordEventEx(None, "ESH_product_key", 1, 1.0, ESH_product_key)
            package_info = None
            if "recipe_id" in LR_data:
                label = modify_module_package_label(package_label)
                package_info = label + ":" + package_version
                ESH_package = {
                    "esh_package": package_info,
                    "esh_command_type": LR_data["type"],
                }
                log.info("Package: {}".format(package_info))
                lr.RecordEventEx(None, "ESH_package", 1, 1.0, ESH_package)
            if "type" in LR_data:
                log.info("Command type: {}".format(LR_data["type"]))
                ESH_command_type = {
                    "esh_command_type": LR_data["type"],
                    "esh_package": package_info,
                }
                lr.RecordEventEx(None, "ESH_command_type", 1, 1.0, ESH_command_type)
            if "image_name" in LR_data:
                log.info("Image pulled successfully: {}".format(LR_data["image_name"]))
                for image_name in LR_data["image_name"]:
                    label = modify_module_package_label(image_name)
                    ESH_pulled_images = {"esh_pulled_images": image_name}
                lr.RecordEventEx(None, "ESH_pulled_images", 1, 1.0, ESH_pulled_images)
                ESH_command_type_success = {"esh_command_type_success": LR_data["type"]}
                lr.RecordEventEx(
                    None,
                    "ESH_command_type_success",
                    1,
                    1.0,
                    ESH_command_type_success,
                )
            if "helm_chart" in LR_data:
                log.info(
                    "Helm chart downloaded successfully: {}".format(
                        LR_data["helm_chart"]
                    )
                )
                for helm_chart in LR_data["helm_chart"]:
                    label = modify_module_package_label(helm_chart)
                    ESH_downloaded_helm_charts = {"esh_downloaded_helm_charts": label}
                lr.RecordEventEx(
                    None,
                    "ESH_downloaded_helm_charts",
                    1,
                    1.0,
                    ESH_downloaded_helm_charts,
                )
                ESH_command_type_success = {"esh_command_type_success": LR_data["type"]}
                lr.RecordEventEx(
                    None,
                    "ESH_command_type_success",
                    1,
                    1.0,
                    ESH_command_type_success,
                )

            if "success_ids" in LR_data and LR_data["success_ids"]:
                record_LR_modules(
                    "success_ids",
                    all_modules,
                    lr,
                    "ESH_module_success",
                    "esh_module_success",
                    "esh_command_type_success",
                )

            if "success_helm_ids" in LR_data and LR_data["success_helm_ids"]:
                record_LR_modules(
                    "success_helm_ids",
                    all_modules,
                    lr,
                    "ESH_helm_success",
                    "esh_helm_success",
                    "esh_command_type_success",
                )

            if "success_container_ids" in LR_data and LR_data["success_container_ids"]:
                record_LR_modules(
                    "success_container_ids",
                    all_modules,
                    lr,
                    "ESH_container_success",
                    "esh_container_success",
                    "esh_command_type_success",
                )

            if (
                "failed_ids" in LR_data
                or "failed_helm_ids" in LR_data
                or "failed_container_ids" in LR_data
            ):
                if (
                    not LR_data["failed_ids"]
                    and not LR_data["failed_helm_ids"]
                    and not LR_data["failed_container_ids"]
                ):
                    log.info("Package status: success")
                    success_package = ESH_package["esh_package"]
                    ESH_package_success = {
                        "esh_package_success": success_package,
                        "esh_command_type_success": LR_data["type"],
                    }
                    lr.RecordEventEx(
                        None, "ESH_package_success", 1, 1.0, ESH_package_success
                    )
                    ESH_command_type_success = {
                        "esh_command_type_success": LR_data["type"],
                        "esh_package_success": success_package,
                    }
                    lr.RecordEventEx(
                        None,
                        "ESH_command_type_success",
                        1,
                        1.0,
                        ESH_command_type_success,
                    )
                else:
                    log.info("Package status: failed")
                    failed_package = ESH_package["esh_package"]
                    ESH_package_failed = {
                        "esh_package_failed": failed_package,
                        "esh_command_type_failed": LR_data["type"],
                    }
                    lr.RecordEventEx(
                        None, "ESH_package_failed", 1, 1.0, ESH_package_failed
                    )
                    ESH_command_type_failed = {
                        "esh_command_type_failed": LR_data["type"],
                        "esh_package_failed": failed_package,
                    }
                    lr.RecordEventEx(
                        None, "ESH_command_type_failed", 1, 1.0, ESH_command_type_failed
                    )

            if "failed_ids" in LR_data and LR_data["failed_ids"]:
                record_LR_modules(
                    "failed_ids",
                    all_modules,
                    lr,
                    "ESH_module_failed",
                    "esh_module_failed",
                    "esh_command_type_failed",
                )

            if "failed_helm_ids" in LR_data and LR_data["failed_helm_ids"]:
                record_LR_modules(
                    "failed_helm_ids",
                    all_modules,
                    lr,
                    "ESH_helm_failed",
                    "esh_helm_failed",
                    "esh_command_type_failed",
                )

            if "failed_container_ids" in LR_data and LR_data["failed_container_ids"]:
                record_LR_modules(
                    "failed_container_ids",
                    all_modules,
                    lr,
                    "ESH_container_failed",
                    "esh_container_failed",
                    "esh_command_type_failed",
                )

            log.info("De-Initializing LanternRock")
            lr.Deinitialize()
            log.info("Uploading data to the LanternRock portal")
            lr.Upload(TID, {"show": False})
        except Exception as e:
            log.error("Failed to send telemetry report to LanternRock {}".format(e))


def record_LR_modules(
    id_collection,
    all_modules,
    lr,
    ESH_module_status,
    esh_module_status,
    esh_command_type_status,
):
    """
    Uses record API from LR SDK to keep log of modules, helm_charts and
    images to be uploaded on LR portal.

    :params id_collection: string to retrieve modules/helm/container ids from LR_data
    :params all_modules: list of all modules within a package
    :params ESH_module_status: name of the dictionary to be uploaded on LR portal
    :params esh_module_status: status of module/helm/containers
    :params esh_command_type_status: status of corresponding command type
    """

    global LR_data
    for guid in LR_data.get(id_collection):
        if guid in all_modules:
            label = all_modules[guid]
            label = modify_module_package_label(label)
            ESH_module_dict = {
                esh_module_status: label,
                esh_command_type_status: LR_data["type"],
            }
            lr.RecordEventEx(None, ESH_module_status, 1, 1.0, ESH_module_dict)


def send_telemetry_data(data, log):
    """
    Send installation report to service layer
    :param data: Dictionary with telemetry info
    """
    try:
        telemetry_data.update(data)
        if (
            telemetry_data.get("success_ids")
            or telemetry_data.get("failed_ids")
            or telemetry_data.get("successHelmIds")
            or telemetry_data.get("failedHelmIds")
            or telemetry_data.get("successContainerIds")
            or telemetry_data.get("failedContainerIds")
        ):
            system_info = sys_info(log)
            os_name = system_info["os_name"]
            hardware = system_info["hardware"]
            processor = system_info["processor"]
            vendor = system_info["vendor_id"]
            network_time = get_network_time()
            if constants.Operating_system == "Linux":
                kernel = system_info["kernel"]
            if "type" not in telemetry_data:
                telemetry_data.update({"type": "install"})
            if constants.Operating_system == "Linux":
                telemetry_data.update(
                    {
                        "os_name": os_name,
                        "kernel": kernel,
                        "hardware": hardware,
                        "processor": processor,
                        "vendor_id": vendor,
                        "network_time": network_time,
                    }
                )
            elif constants.Operating_system == "Windows":
                telemetry_data.update(
                    {
                        "os_name": os_name,
                        "hardware": hardware,
                        "processor": processor,
                        "vendor_id": vendor,
                        "network_time": network_time,
                    }
                )
            api.send_telemetry_data(telemetry_data, log)
            telemetry_data.clear()
    except Exception as e:
        log.error("Failed to send installation report")


def checkInternetConnection(log):
    """
    Check for internet connection
    """
    num_tries = 0
    log.console("Checking Internet connection", color_code=constants.CYAN)
    while num_tries < 3:
        try:
            url = constants.DOMAINS[num_tries]
            if url.lower().startswith("http"):
                req = urllib.request.Request(url)
            connection = urllib.request.urlopen(req, timeout=10)
            if connection.status == constants.HTTP_STATUS.get("OK"):
                log.console("Connected to the Internet", color_code=constants.GREEN)
                break
            else:
                log.console("Not connected to the Internet", error=True)
        except KeyboardInterrupt:
            log.console(
                "Installation aborted by user. Exiting installation", error=True
            )
            sys.exit(-1)
        except urllib.error.HTTPError as e:
            log.console("Failed to verify internet connection {}".format(e), error=True)
        except urllib.error.URLError as e:
            if isinstance(e.reason, socket.timeout):
                log.console(
                    "Check for Internet connection request timed out", error=True
                )
        except Exception as e:
            log.console("Failed to verify Internet connection {}".format(e), error=True)
        if num_tries == 2:
            log.console(
                "Please check the Internet connection and proxy " "settings", error=True
            )
            sys.exit(-1)
        else:
            log.console("Reconnecting", color_code=constants.YELLOW)
        num_tries += 1


def check_existing_modules(module_list, os_name, log):
    """
    Check if any of the pre-requisite modules exist
    :param os_name: Name of Operating System
    :param pip_list: list of required pip  modules to be installed
    :param module_list: list of required modules to be installed
    """
    if constants.Operating_system == "Linux":
        if "CentOS" in os_name or "Red Hat" in os_name:
            git_version = subprocess.run(
                "git --version | cut -d ' ' -f3", stdout=subprocess.PIPE, shell=True
            )
            dec_version = git_version.stdout.decode("ascii").strip()
            for package in module_list:
                if package == "git":
                    if not dec_version.startswith("2."):
                        return False
                else:
                    skipped_modules = ["git", "python3-apt"]
                    if package in skipped_modules:
                        continue
                    command = ["yum", "list", "installed", "|", "grep", "-w", package]
                    res = run(command, stdout=PIPE, stderr=PIPE)
                    if res.stdout.decode("ascii") == "":
                        return False
            return True
        else:
            try:
                ret = subprocess.run(
                    "sudo apt-get update", shell=True, stdout=subprocess.PIPE
                )
                if ret.returncode:
                    log.console(
                        "Failed to update apt list. Exiting installation.", error=True
                    )
                    sys.exit(-1)
                for package in module_list:
                    reqs = subprocess.check_output(
                        ["apt", "-qq", "list", package],
                        stderr=subprocess.DEVNULL,
                    )
                    installed_packages = [
                        r.decode().split("==")[0] for r in reqs.split()
                    ]
                    installed_packages = [i.split("/")[0] for i in installed_packages]
                    if "[installed]" not in installed_packages:
                        return False
                    if installed_packages[0] not in module_list:
                        return False
                return True
            except Exception as e:
                log.console(
                    "Failed to update apt list. {} Exiting installation.".format(e),
                    error=True,
                )
                sys.exit(-1)

    elif constants.Operating_system == "Windows":
        if "Windows" in os_name:
            git_version = subprocess.run(
                "git --version",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
            )
        if git_version.returncode:
            return False
        else:
            dec_version1 = git_version.stdout.decode("ascii").strip()
            dec_version = dec_version1.strip("git version")
            for package in module_list:
                if package == "git":
                    if not dec_version.startswith("2."):
                        return False
                elif package == "curl":
                    res = subprocess.run("curl -V", shell=True, stdout=subprocess.PIPE)
                    if res.returncode != 0:
                        return False
                elif package == "pip":
                    res = subprocess.run(
                        "pip -V",
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    if res.returncode != 0:
                        log.console(
                            "Issue with python/pip version or Path setup."
                            "Exiting installation  {}".format(res.stderr),
                            color_code=constants.RED,
                        )
                        log.console(
                            "Check installed python verison and Environment Variable",
                            color_code=constants.YELLOW,
                        )
                        sys.exit(-1)


def check_pip_installed_modules(pip_list, log):
    """
    Check if any of the pip pre-requisite modules exist
    :param pip_list: list of required pip  modules to be installed
    """
    for module in pip_list:
        command = ["pip3", "show", module]
        ret = subprocess.run(command, stdout=PIPE, stderr=PIPE)
        dec_ret = ret.stdout.decode("ascii").strip("\n")
        if dec_ret == "":
            return False
    return True


def pre_requisites(log, os_name):
    """
    Install the pre-requisite packages
    :param os_name: Name of Operating System
    """
    log.console("Checking for prerequisites", color_code=constants.CYAN)
    pip_list = [
        "click",
        "requests",
        "termcolor",
        "wget",
        "setuptools",
        "PyYAML",
        "prettytable",
        "psutil",
        "py-cpuinfo",
        "colorama",
    ]
    if constants.Operating_system == "Linux":
        module_list = [
            "python3-pip",
            "git",
            "curl",
            "usbutils",
            "pciutils",
            "python3-apt",
        ]
    elif constants.Operating_system == "Windows":
        module_list = ["pip", "git", "curl"]
    module_exists = check_existing_modules(module_list, os_name, log)
    if not module_exists:
        log.console(
            "Installing prerequisites. This may take some " "time...".center(50, "-"),
            color_code=constants.CYAN,
        )
        if constants.Operating_system == "Linux":
            if "CentOS" in os_name or "Red Hat" in os_name:
                ret = subprocess.run(
                    "sudo yum install -y "
                    "python3-pip curl usbutils pciutils",
                    shell=True,
                )
                ret = subprocess.run(
                    "sudo yum install -y gcc python3-devel", shell=True
                )
                git_install = install_git(log)
            else:
                ret = subprocess.run(
                    "sudo apt-get update && sudo apt-get"
                    " install -y python3-pip git curl usbutils pciutils python3-apt",
                    shell=True,
                )
            if ret.returncode:
                log.console(
                    "Failed to install prerequisites:" " {}".format(ret.stderr),
                    error=True,
                )
                sys.exit(-1)
        elif constants.Operating_system == "Windows":
            git_version = subprocess.run(
                "git --version",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
            )
            if git_version.returncode:
                install_git(log)
            elif git_version.returncode == 0:
                dec_version1 = git_version.stdout.decode("ascii").strip()
                dec_version = dec_version1.strip("git version")
                if not dec_version.startswith("2."):
                    install_git(log)
    pip_module_exists = check_pip_installed_modules(pip_list, log)
    if not pip_module_exists:
        for module in pip_list:
            if constants.Operating_system == "Linux":
                command = ["sudo", "-E", "pip3", "install", module]
                ret = run(command, stdout=PIPE, stderr=PIPE)
            elif constants.Operating_system == "Windows":
                command = ["pip", "install", module]
                ret = subprocess.run(command, stdout=PIPE, stderr=PIPE)
            if ret.returncode:
                log.console(
                    "Failed to install {}. " "{}".format(module, ret.stderr), error=True
                )
                sys.exit(-1)
        log.console(
            "Succesfuly installed prerequisites".center(50, "-"),
            color_code=constants.GREEN,
        )
    log.console("All dependencies met", color_code=constants.GREEN)


def prompt_reinstall(log, component):
    """
    Prompt reinstall if the component is installed

    :param component: Component to be checked
    :returns: User input True or False
    """
    result = False
    num_prompts = 1
    while True:
        msg = (
            "{} is already installed. Type YES to "
            "reinstall or NO to skip installation.\n".format(component)
        )
        try:
            option = inputimeout(constants.BICYAN.format(msg), timeout=30)
            try:
                if option.lower() == "yes" or option.lower() == "y":
                    result = True
                    log.info("Selected {} for {}".format(option, component))
                    break
                elif option.lower() == "no" or option.lower() == "n":
                    result = False
                    log.info("Selected {} for {}".format(option, component))
                    break
                elif num_prompts >= 10:
                    log.console(
                        "Skipping re-installation for {}".format(component),
                        color_code=constants.CYAN,
                    )
                    result = False
                    break
                else:
                    log.console(
                        "Invalid option. Valid " "options are YES or NO.\n", error=True
                    )
                num_prompts += 1
            except:
                log.error("Failed to re-prompt. Exiting installation")
                sys.exit(-1)
        except KeyboardInterrupt:
            log.console(
                "Installation aborted by user. Exiting installation"
                " for {}".format(component),
                error=True,
            )
            break
        except:
            log.console(
                "Skipping re-installation for {}".format(component),
                color_code=constants.CYAN,
            )
            result = False
            break
    return result


def unzip_modules(component_list, log):
    esb_modules_list = OrderedDict()
    try:
        for module_id, value in component_list.items():
            if not is_image(value):
                abs_src_path = os.path.abspath(value["path"])
                zip_location = os.path.join(abs_src_path, module_id)
                if not is_helm(value):
                    module = value["label"]
                else:
                    module = value["label"] + "-" + value["tag"]
                tar_file = zip_location + ".tgz"
                zip_file = zip_location + ".zip"
                module_path = os.path.join(abs_src_path, module)
                if not len(component_valid) or (
                    component_valid[module] == None or not os.path.exists(module_path)
                ):
                    if os.path.exists(zip_file):
                        with ZipFile(zip_file, "r") as zipObj:
                            # Extract all the contents of zip file
                            log.console("Unzipping the module {}...".format(module))
                            for info in zipObj.infolist():
                                extract_file(zipObj, info, module_path)
                    elif os.path.exists(tar_file):
                        with tarfile.open(tar_file, "r:gz") as tar:
                            log.console("Unzipping Helm chart {}...".format(module))
                            tar.extractall(module_path)

                if value.get("esb_install"):
                    esb_modules_list.update({module_id: value})
                if is_helm(value):
                    esb_modules_list.update({module_id: value})
            else:
                esb_modules_list.update({module_id: value})
    except Exception as e:
        log.console("Failed to unzip modules. {}".format(e))
    return esb_modules_list


def update_xml_json(component_id, component_name, file_name, log):
    output_dir_path = create_output_dir(manifest_file)
    install_status_log_path = os.path.join(output_dir_path, install_status_log)
    try:
        component_list = {}
        try:
            with open(install_status_log_path, "r") as file:
                component_list = json.load(file)
            del component_list[component_name]
            with open(install_status_log_path, "w") as file:
                json.dump(component_list, file)
                log.info("Successfully updated json file for {}".format(component_name))
        except Exception as e:
            log.console(
                "Failed to update json file due to " "error {}".format(e), error=True
            )
        # try:
        #     if(os.path.exists(file_name)):
        #         tree = ET.parse(file_name)
        #         root = tree.getroot()
        #         for child in root:
        #             if child.tag == "project":
        #                 if component_id == child.attrib.get('id'):
        #                     rem_child = child
        #                     root.remove(rem_child)
        #                     tree.write(file_name)
        #                     log.info("Removed the xml entry of the "
        #                              "component id {}".format(component_id))
        #                     break
        # except Exception as e:
        #     log.console("Failed to update xml file due to "
        #                 "error {}".format(e), error=True)
    except Exception as e:
        log.console(
            "Failed to update uninstalled component due to" " error {}".format(e),
            error=True,
        )


def copy_export_deps(deps_list, dest, log):
    for dep in deps_list:
        try:
            if os.path.exists(dep):
                if os.path.isfile(dep):
                    shutil.copy(dep, dest)
                else:
                    log.console("Failed to add export dependencies", error=True)
                    sys.exit(-1)
        except:
            log.console("Failed to add export dependencies.")
            sys.exit(-1)


def upgrade_cleanup(log, install_path, conf_path, package, error=False):
    """
    Clean up for upgrade function

    :param install_path: ESB CLI path under log directory
    :param error: upgrade status
    """
    temp_xml_path = os.path.join(conf_path, manifest_file)
    log.info("Cleanup for Upgrade function")
    try:
        if error:
            if os.path.exists(conf_path):
                shutil.rmtree(conf_path)
            if os.path.exists(package):
                log.info("Removing {}".format(package))
                if constants.Operating_system == "Linux":
                    command = ["sudo", "rm", "-rf", package]
                    ret = run(command, stdout=PIPE, stderr=PIPE)
                elif constants.Operating_system == "Windows":
                    shutil.rmtree(package)
            if os.path.exists(install_path):
                log.info("Removing {}".format(install_path))
                if constants.Operating_system == "Linux":
                    command = ["sudo", "rm", "-rf", install_path]
                    ret = run(command, stdout=PIPE, stderr=PIPE)
                elif constants.Operating_system == "Windows":
                    shutil.rmtree(install_path)
        else:
            if os.path.exists(conf_path):
                os.remove(manifest_file)
                file_names = os.listdir(conf_path)
                for file_name in file_names:
                    shutil.move(
                        os.path.join(conf_path, file_name),
                        os.path.join(os.getcwd(), file_name),
                    )
                shutil.rmtree(conf_path)
            if os.path.exists(install_path):
                log.info("Removing {}".format(install_path))
                if constants.Operating_system == "Linux":
                    command = ["sudo", "rm", "-rf", install_path]
                    ret = run(command, stdout=PIPE, stderr=PIPE)
                elif constants.Operating_system == "Windows":
                    shutil.rmtree(install_path)
        log.info("Clean up complete")
    except Exception as e:
        log.console("Failed to clean installation directory. {}".format(e), error=True)


def clean_esb_common(log, output_dir_path):
    if constants.Operating_system == "Linux":
        command = ["sudo", "find", "/usr/local/", "-type", "d", "-iname", "esb_common"]
        common_path = run(command, stdout=PIPE, stderr=PIPE)
        del_common_path = common_path.stdout.decode("ascii").strip("\n")
        command = [
            "sudo",
            "find",
            "/usr/local/",
            "-type",
            "d",
            "-iname",
            "lanternrock-*",
        ]
        lr_path = run(command, stdout=PIPE, stderr=PIPE)
        del_lr_path = lr_path.stdout.decode("ascii").strip("\n")
        command = ["sudo", "find", "/opt/intel/", "-name", "lanternrocksdk-*"]
        opt_lr_path = run(command, stdout=PIPE, stderr=PIPE)
        del_opt_lr_path = opt_lr_path.stdout.decode("ascii").strip("\n")
    elif constants.Operating_system == "Windows":
        del_common_path = os.path.join(
            sitepackage_location, "Lib", "site-packages", "esb_common"
        )
    try:
        if del_common_path:
            log.info("Cleaning common directories")
            if constants.Operating_system == "Linux":
                command = ["sudo", "rm", "-rf", del_common_path]
                ret = run(command, stdout=PIPE, stderr=PIPE)
                if ret.returncode:
                    log.error("Failed to clean common directories")
                command = [
                    "sudo",
                    "-E",
                    "python3",
                    "-m",
                    "pip",
                    "uninstall",
                    "-y",
                    "esb-common",
                ]
                ret = run(command, stdout=PIPE, stderr=PIPE)
                if ret.returncode:
                    log.error("Failed to clean esb_common-egg directories")
                command = [
                    "sudo",
                    "-E",
                    "python3",
                    "-m",
                    "pip",
                    "uninstall",
                    "-y",
                    "lanternrock",
                ]
                ret = run(command, stdout=PIPE, stderr=PIPE)
                if ret.returncode:
                    log.error("Failed to clean LanternRock directories")
            elif constants.Operating_system == "Windows":
                command = ["python", "-m", "pip", "uninstall", "-y", "esb-common"]
                ret = run(command, stdout=PIPE, stderr=PIPE)
                if ret.returncode:
                    log.error("Failed to clean esb_common-egg directories")
                shutil.rmtree(del_common_path)
        if del_lr_path:
            log.info("Cleaning Lanternrock SDK")
            command = ["sudo", "rm", "-rf", del_lr_path]
            ret = run(command, stdout=PIPE, stderr=PIPE)
            if ret.returncode:
                log.error("Failed to clean Lanternrock egg folders")
        if del_opt_lr_path:
            command = ["sudo", "rm", "-rf", del_opt_lr_path]
            ret = run(command, stdout=PIPE, stderr=PIPE)
            if ret.returncode:
                log.error("Failed to clean Lanternrock SDK")

        if os.path.exists(output_dir_path):
            if constants.Operating_system == "Linux":
                command = ["sudo", "rm", "-rf", output_dir_path]
                ret = run(command, stdout=PIPE, stderr=PIPE)
                if ret.returncode:
                    log.error("Failed to clean log directories")
            elif constants.Operating_system == "Windows":
                for i in os.listdir(output_dir_path):
                    if i == "output.log":
                        continue
                    if os.path.isfile(os.path.join(output_dir_path, i)):
                        os.remove(os.path.join(output_dir_path, i))
                    else:
                        shutil.rmtree(os.path.join(output_dir_path, i))
    except Exception as e:
        log.error("Failed to clean log directories")
        log.console("Failed to clean log directories {}".format(e))


def reinstall_check(update, upgrade, log):
    """
    Check if it is reinstallation of package
    :param update: update command
    """
    output_dir_path = create_output_dir(manifest_file)
    install_status_json_path = os.path.join(output_dir_path, install_status_log)
    try:
        if constants.Operating_system == "Linux":
            common_path = subprocess.run(
                "sudo find /usr/local/ -type d -iname " "'esb_common' ",
                stdout=subprocess.PIPE,
                shell=True,
            )
            common_dir = common_path.stdout.decode("ascii").strip("\n")
            if (
                not (update or upgrade)
                and common_dir
                and os.path.exists(install_status_json_path)
                and os.stat(install_status_json_path).st_size != 0
            ):
                send_telemetry_data(({"type": "reinstall"}), log)
        elif constants.Operating_system == "Windows":
            common_dir = os.path.join(
                sitepackage_location, "Lib", "site-packages", "esb_common"
            )
            if (
                not (update or upgrade)
                and os.path.isdir(common_dir)
                and os.path.exists(install_status_json_path)
                and os.stat(install_status_json_path).st_size != 0
            ):
                send_telemetry_data(({"type": "reinstall"}), log)
    except:
        log.error("Failed to set reinstall status")


def reboot_msg(statuses):
    """
    Print Reboot message after installation is complete
    :param statuses: list of install statuses of modules
    """
    try:
        dec_statuses = []
        reg_form = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
        for status in statuses:
            dec_statuses.append(reg_form.sub("", status))
        if not "FAILED" in dec_statuses:
            print(
                constants.YELLOW.format(
                    "Recommended to reboot system" " after installation".center(53, "*")
                )
            )
    except:
        print(constants.YELLOW.format("Missing reboot message"))


def docker_progress_bar(line, bar, progress_data):
    """
    Create progress bar for pulling docker image
    :param line: docker status line
    :param bar: level of new bar
    :param progress_data: progress data
    """
    line_text = "{}: {}".format(line.get("id", ""), line.get("status", ""))
    if line.get("progressDetail"):
        progress_data[line["id"]] = line["progressDetail"]
        bar.total = sum(p["total"] for p in progress_data.values())
        bar.update(sum(p["current"] for p in progress_data.values()) - bar.n)
    bar.set_description_str(line_text)

def docker_final_update(bar, progress_data):
    """
    Update Final progress bar for pulling docker image
    :param bar: level of new bar
    :param progress_data: progress data
    """
    bar.total = sum(p["total"] for p in progress_data.values())
    bar.update(bar.total - bar.n)

def intel_registry_pull(image, tag, product_key, log):
    """
    Pull docker image from Intel Registry
    :param image: Name of the docker image
    :param tag: Tag of the docker image
    :param product_key: Product Key associated with the images
    """
    global success_container_names
    global success_container_ids
    status = False
    data = api.validate_docker_image(image, tag, product_key, log)
    if not data or data["registryType"] != "intelprivate":
        # Image not found in Intel Registry, or is Intel Public Registry.
        status = non_intel_registry_pull(image, tag, log)
    else:
        base_image_status = None
        if (
            "baseImage" in data
            and data["baseImage"] != None
            and data["baseImage"] != "null"
            and data["baseImage"].strip() != ""
        ):
            # If image has non-redistributable base image, then pull base layers and then pull Intel layers
            base_img, base_img_digest = data["baseImage"].split("@")
            base_image_status = api.fetch_base_image(base_img, base_img_digest, log)
        if base_image_status or base_image_status == None:
            status = api.fetch_image(
                data["id"],
                data["image"],
                data["tag"],
                product_key,
                log,
            )
        else:
            status = False
        success_container_ids = [data["id"]]
        success_pulled_image = image + ":" + tag
        success_container_names = [success_pulled_image]
        if status and telemetry_data.get("type") == "docker-pull":
            send_telemetry_data(({"successContainerIds": success_container_ids}), log)
        if status and is_LR_installed(log) and LR_data.get("type") == "docker-pull":
            successful_pulled_image = image + ":" + tag
            send_LR_data({"image_name": success_container_names}, log)

    return status


def non_intel_registry_pull(image, tag, log):
    """
    Pull docker image from Non-Intel Registry.
    :param image: Name of the docker image
    :param tag: Tag of the docker image
    """
    log.console("Image not available in Intel Registry.")
    log.console("Downloading {}:{} from public registry.".format(image, tag))

    try:
        log.console(
            "Pulling Image from {}:{}".format(image, tag), color_code=constants.GREEN
        )
        client = docker.from_env()
        with tqdm(
            total=1,
            desc="Downloading",
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
            position=0,
            ascii=False,
        ) as download_bar:
            with tqdm(
                total=1,
                desc="Extracting",
                unit="B",
                unit_scale=True,
                unit_divisor=1024,
                position=1,
                ascii=False,
            ) as extract_bar:
                download_progress = {}
                extract_progress = {}
                for line in client.api.pull(image, tag=tag, stream=True, decode=True):
                    if line["status"] == "Downloading":
                        docker_progress_bar(line, download_bar, download_progress)
                    elif line["status"] == "Extracting":
                        docker_progress_bar(line, extract_bar, extract_progress)

                if download_progress:
                    docker_final_update(download_bar,download_progress)
                if extract_progress:
                    docker_final_update(extract_bar,extract_progress)

        log.console("Status: Image saved for {}:{}".format(image, tag))
        return image_load_status(image, tag, log)
    except Exception as e:
        msg = "Failed to pull image {}:{}. {}"
        print_msg = "Failed to pull image {}:{}"
        log.console(msg.format(image, tag, e), print_msg.format(image, tag), error=True)
        return False


def image_load_status(image, tag, log):
    """
    Verifies if docker image available in device.
    :param image: Name of the docker image
    :param tag: Tag of the docker image
    """
    digest = None
    if "sha256" in tag:
        digest = tag
    if constants.Operating_system == "Linux":
        if not digest:
            cmd = "sudo docker images -q {}:{}".format(image, tag)
        else:
            cmd = "sudo docker images -q {}@{}".format(image, digest)
    elif constants.Operating_system == "Windows":
        if not digest:
            cmd = "docker images -q {}:{}".format(image, tag)
        else:
            cmd = "docker images -q {}@{}".format(image, digest)
    p = subprocess.run(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = p.stdout.decode("utf-8")
    if output:
        return True
    return False


def docker_installed():
    """
    Verifies if docker is installed in the device.
    """
    if constants.Operating_system == "Linux":
        cmd = "sudo docker --version"
    elif constants.Operating_system == "Windows":
        cmd = "docker --version"
    p = subprocess.run(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    docker_version = p.stdout.decode("ascii").strip()
    if docker_version:
        return True
    return False


def is_image(val):
    if val.get("type") == "image":
        return True
    return False


def is_helm(val):
    if val.get("type") == "helm":
        return True
    return False


def get_docker_credentials(log):
    """
    Get Docker credentials from ~/.docker/config.json file
    """
    try:
        docker_config = str(Path.home()) + "/.docker/config.json"
        if Path(docker_config).is_file():
            with open(docker_config) as json_file:
                data = json.load(json_file)
                if "auths" in data:
                    repo_creds = data["auths"]
                    if "https://index.docker.io/v1/" in repo_creds:
                        auth = repo_creds["https://index.docker.io/v1/"]
                        if "auth" in auth:
                            encoded_cred = auth["auth"]
                            decoded_cred = base64.b64decode(encoded_cred).decode(
                                "utf-8"
                            )
                            user, passwd = decoded_cred.split(":")
                            return {"username": user, "password": passwd}
                        else:
                            return {}
                    else:
                        return {}
                else:
                    return {}
        else:
            return {}
    except Exception as e:
        log.console("Unable to get docker credentials.", error=True)
    return {}


def get_layer_dir(log):
    """
    Create layer directory if not exist
    """
    layer_dir = str(Path.home()) + layers_dir
    try:
        if constants.Operating_system == "Linux":
            if not os.path.isdir(layer_dir):
                subprocess.run(["sudo", "mkdir", "-p", layer_dir])
            subprocess.run(["sudo", "chown", os.environ["USER"], layer_dir])
        elif constants.Operating_system == "Windows":
            Path(layer_dir).mkdir(parents=True, exist_ok=True)
        return layer_dir
    except Exception as e:
        log.console(
            "Unable to create {} directory: {}".format(layer_dir, e), error=True
        )
        sys.exit(-1)


def validate_hash(filepath, hash, log):
    """
    Validate the file with provided hash
    :param filepath: Path where the layer is located
    :param hash: Hash to validate the file against
    """
    try:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
            computed_hash = sha256_hash.hexdigest()
    except Exception as e:
        log.console("Cannot compute hash on file {}".format(filepath), error=True)

    return hash == computed_hash


def remove_docker_image(image, log):
    """
    Remove the docker images
    :param image: Name of the image
    """
    if constants.Operating_system == "Linux":
        command = run(
            (
                [
                    "sudo",
                    "docker",
                    "images",
                    "-a",
                    "--format",
                    "{{.Repository}},{{.Tag}},{{.ID}}",
                ]
            ),
            stdout=PIPE,
            stdin=PIPE,
        )
    elif constants.Operating_system == "Windows":
        command = run(
            (
                [
                    "docker",
                    "images",
                    "-a",
                    "--format",
                    "{{.Repository}},{{.Tag}},{{.ID}}",
                ]
            ),
            stdout=PIPE,
            stdin=PIPE,
        )
    image_list = command.stdout.decode("utf-8").splitlines()

    sv_reader = csv.reader(image_list, delimiter=",")
    for row in sv_reader:
        image_name = row[0] + ":" + row[1]
        if image_name == image:
            image_id = row[2]
            if constants.Operating_system == "Linux":
                command = f"sudo docker rmi -f {image_id}"
            elif constants.Operating_system == "Windows":
                command = f"docker rmi -f {image_id}"
            status = run(command.split(), stdout=PIPE, stderr=PIPE)
            if status.returncode:
                log.console(
                    ((status.stdout + status.stderr).decode("utf-8")), error=True
                )
                return False
            else:
                return True

    # Image not found. So return True
    return True


def remove_helm_keys(chart_name, log):
    """
    Remove Helm chart Secrets from Kubernetes Cluster

    Args:
        chart_name (String): Name and ID of the chart
        log (obj): Log Object

    Returns:
        Bool: Status
    """
    # Delete the secret if it actually exists
    try:
        config.load_kube_config()
        v1 = client.CoreV1Api()
        namespace = "default"
        secret_name = "esh-" + chart_name
        secret_name = secret_name.lower()
        api_response = v1.list_namespaced_secret(namespace)
    except Exception as e:
        log.error("Exception when calling CoreV1Api load Kube Config {}".format(e))
        return True

    try:
        if not api_response:
            return True
        for data in api_response.items:
            if data.metadata.name == secret_name:
                log.info(
                    "Deleting old secret keys for Helm chart {}".format(chart_name)
                )
                api_response = v1.delete_namespaced_secret(secret_name, namespace)
                if api_response:
                    log.console(
                        "Deleted old secret keys for Helm chart {}".format(chart_name),
                        color_code=constants.GREEN,
                    )
                    return True
        log.console(
            "Helm chart secret keys for {} not found in the Kubernetes Cluster".format(
                chart_name
            )
        )
        return True
    except ApiException as e:
        log.console(
            "Exception when calling CoreV1Api. {}".format(e),
            error=True,
        )

    return False


def update_k8s_secret_store(chart_name, chart_tag, chart_id, product_key, log):
    """
    Delete Previous Secrets and add new Secrets for Helm Chart

    Args:
        chart_name (String): Helm Chart Name
        chart_tag (String): Helm Chart Tag
        chart_id (String): Helm Chart GUID
        product_key (String): Product Key Value
        log (obj): Log Object

    Returns:
        Bool: Status
    """
    # Initialize K8s Client
    validation_status, helm_data = api.get_helm_robot_account(
        chart_id, product_key, log
    )

    if validation_status:

        try:
            config.load_kube_config()
            v1 = client.CoreV1Api()
            namespace = "default"
            secret_name = "esh-" + chart_name + "-" + chart_tag
            secret_name = secret_name.lower()
            api_response = v1.list_namespaced_secret(namespace)

        except Exception as e:
            log.console(
                "Exception when calling Kubernetes CoreV1Api. {}".format(e),
                error=True,
            )
            return False
        # Delete the secret if it actually exists.
        if api_response:
            for data in api_response.items:
                if data.metadata.name == secret_name:
                    log.info(
                        "Deleting old secret keys for Helm chart {}-{}".format(
                            chart_name, chart_tag
                        )
                    )
                    try:
                        api_response = v1.delete_namespaced_secret(
                            secret_name, namespace
                        )
                        if api_response:
                            log.info(
                                "Deleted old secret keys for Helm Chart {}-{}".format(
                                    chart_name, chart_tag
                                )
                            )
                    except ApiException as e:
                        log.console(
                            "Exception when calling CoreV1Api to delete old Helm Chart secret {}-{}".format(
                                chart_name, chart_tag
                            ),
                            color_code=constants.RED,
                        )

        # Get one registry credential for all the private docker images available in Helm chart.
        username, password = (
            base64.b64decode(helm_data["token"]).decode("utf-8").split(":", 1)
        )
        registry = helm_data["registry"]
        docker_creds = get_credentials(registry, username, password)

        docker_creds_encoded = base64.b64encode(
            json.dumps(docker_creds).encode()
        ).decode()
        # Add new secret with the credentials.
        log.info(
            "Adding new secret keys for Helm chart {}-{}".format(chart_name, chart_tag)
        )
        namespace = "default"
        body = {
            "api_version": "v1",
            "data": {".dockerconfigjson": docker_creds_encoded},
            "kind": "Secret",
            "metadata": {"name": secret_name, "namespace": namespace},
            "type": "kubernetes.io/dockerconfigjson",
        }

        try:
            api_response = v1.create_namespaced_secret(namespace, body)
            if api_response:
                log.console(
                    "Added new secret keys for Helm chart {}-{}".format(
                        chart_name, chart_tag
                    ),
                    color_code=constants.GREEN,
                )
                return True
        except ApiException as e:
            log.console(
                "Exception when calling CoreV1Api list_namespaced_secret. {}".format(e),
                error=True,
            )
            return False
    else:
        return False


def get_credentials(registry_name, username, password):
    creds = {
        "auths": {
            "{}".format(registry_name): {"username": username, "password": password}
        }
    }
    return creds


def install_lanternrock(src, manifest, log):
    """
    Installs Lanternrock analytics SDK

    :param src: esb-common dict
    :param manifest: manifest file edgesoftware_configuration.xml
    :log (obj): Logger Object
    """

    global LR_INSTALLED
    log.console("Installing Lanternrock SDK", color_code=constants.GREEN)
    common_id = get_recipe_details(manifest, common=True)["common_id"]
    try:
        cwd = os.getcwd()
        abs_src_path = os.path.abspath(src["path"])
        module_path = os.path.join(abs_src_path, "esb_common")

        lr_install_path = "/opt/intel/"
        if not os.path.exists(lr_install_path):
            subprocess.run(["sudo", "mkdir", "-p", lr_install_path])
        subprocess.run(["sudo", "chown", os.environ["USER"], lr_install_path])
        tarfile_path = os.path.join(module_path, "lanternrocksdk-linux-3.0.90.tar.gz")
        if os.path.exists(tarfile_path):
            with tarfile.open(tarfile_path, "r:gz") as tar:
                log.info("Unzipping LanternRock SDK within {}".format(lr_install_path))
                tar.extractall(lr_install_path)

        unzipped_lr_path = os.path.join(lr_install_path, "lanternrocksdk-linux-3.0.90")
        lr_tar_gz = os.path.basename(tarfile_path)
        lr_tar = os.path.splitext(lr_tar_gz)[0]
        lr_version = os.path.splitext(lr_tar)[0]
        log.info("Lanternrock SDK being installed: {}".format(lr_version))
        # NOTE: Following lines are to support LR SDK 3.0.14 which doesn't have the
        # requirement of specific libstdc++.so
        # dest_ias3_so_path = os.path.join(
        #    unzipped_lr_path, "python/lanternrock/linux/libintel-ias3.so"
        # )
        # src_ias3_so_path = os.path.join(
        #    unzipped_lr_path, "native/lib/static-legacy/libintel-ias3.so"
        # )
        # shutil.copy(src_ias3_so_path, dest_ias3_so_path)

        # NOTE: LR SDK 3.0.90 requires libstdc++.so from the LR package for Ubuntu 18, CentOS & RHEL

        import_LR_helper(log)
        os.chdir(os.path.join(unzipped_lr_path, "python/"))
        ret = subprocess.run(
            "sudo python3 setup.py install 2>/dev/null",
            shell=True,
            stdout=subprocess.PIPE,
        )
        if ret.returncode:
            msg = "Failed to install Lanternrock SDK" " {}".format(ret.stderr)
            print(constants.RED.format(msg))
            log.error("Failed to run setup.py for lanternrock. {}".format(ret.stderr))
    except Exception as e:
        msg = "Failed to install 'Lanternrock SDK'. {}".format(e)
        log.console(msg, error=True)
        return False
    finally:
        os.chdir(cwd)
    log.console("Successfully installed Lanternrock SDK.", color_code=constants.GREEN)
    command = ["sudo", "find", "/usr/local/", "-type", "d", "-iname", "lanternrock-*"]
    lr_path = run(command, stdout=PIPE, stderr=PIPE)
    lr_egg_path = lr_path.stdout.decode("ascii").strip("\n")
    if lr_egg_path not in sys.path:
        sys.path.append(lr_egg_path)
    LR_INSTALLED = True
    return True


def import_LR_helper(log):
    """
    Sets appropriate libstdc++.so version from LR SDK folder.
    Logic is equivalent to setting LD_PRELOAD from terminal.
    """
    global LR_INSTALLED
    lr_install_path = "/opt/intel/lanternrocksdk-linux-3.0.90"
    if os.path.exists(lr_install_path):
        cwd = os.getcwd()
        libstd_path = os.path.join(lr_install_path, "native/lib/libstdc++/libstdc++.so")
        if libstd_path:
            import ctypes

            ctypes.cdll.LoadLibrary(libstd_path)
        else:
            log.error("Failed to setup relevant libstdc++ version for LanternRock")
            return False
        os.chdir(cwd)
        LR_INSTALLED = True


def is_LR_installed(log):
    """
    Checks if LanternRock SDK is already installed in a system or not.
    """
    if constants.Operating_system == "Linux":
        ret = os.system("pip3 show lanternrock >/dev/null 2>&1")
        if ret == 0:
            return True
        return False


def save_image(log, name, tag, id):
    """
    Save Docker image to a tarfile
    Max Supported Docker Image to save ~ 30 GB

    Args:
        log (obj): Logger Object
        name (String): Name of the Image
        tag (String): Tag of the Image
        id (String): ID of the module
    """
    try:
        cli = docker.from_env(timeout=99999)
        log.info("Saving Image file {}:{} to target system".format(name, tag))

        image = cli.images.get("{}:{}".format(name, tag))
        gen = image.save(named=True)
        with open("{}.tar".format(id), "wb") as f:
            for chunk in tqdm(
                gen,
                leave=True,
                miniters=1,
                desc="Saving Image {}:{} ".format(name, tag),
            ):
                f.write(chunk)

    except Exception as e:
        log.error("Exception in saving image {}:{} to file. {}".format(name, tag, e))


def load_image(log, name, tag, image_path):
    """
    Load Docker image from a tarfile

    Args:
        log (obj): Logger Object
        name (String): Name of the Image
        tag (String): Tag of the Image
        image_path (String): Image path Location
    """
    try:
        cli = docker.from_env(timeout=99999)
        log.info("Loading Image file {}:{} to target system".format(name, tag))
        with open(
            "{}.tar".format(image_path),
            "rb",
        ) as file:
            images = cli.images.load(file)
        if images:
            # Retagging the image incase there exist an image already of same ID
            if cli.api.tag(images[0].tags[0], name, tag=tag, force=True):
                log.info("Loaded Image file {}:{} to target system".format(name, tag))
            else:
                log.error(
                    "Unable to load Image file {}:{} to target system".format(name, tag)
                )
    except Exception as e:
        log.error(
            "Exception in loading image file {}:{} to target system. {}".format(
                name, tag, e
            )
        )
    return image_load_status(name, tag, log)

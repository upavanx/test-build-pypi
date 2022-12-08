import importlib.util
import os
import requests
import subprocess
import sys
import oyaml as yaml
import time
import json
import shutil
import tempfile
import signal
import yaml

from subprocess import run, PIPE, check_output, Popen, DEVNULL, STDOUT
from collections import OrderedDict
from distutils.dir_util import copy_tree
from distutils.version import LooseVersion
from edgesoftware.common import logger
from edgesoftware.common import service_layer_api as api
from edgesoftware.common import utils
from edgesoftware.common import constants
from json.decoder import JSONDecodeError
from prettytable import PrettyTable

install_status_json = "install_status.json"
output_log = "output.log"
docker_pull_log = "docker.log"
helm_download_log = "helm.log"
log = None
manifest_file = "edgesoftware_configuration.xml"
temp_conf_file = ""
system_info = utils.sys_info(log)
OS_Version = system_info["os_name"]


def signal_handling(signum, frame):
    print("Operation aborted by user. Exiting")
    sys.exit(-1)


if constants.Operating_system == "Windows":
    signal.signal(signal.SIGTERM, signal_handling)
elif constants.Operating_system == "Linux":
    signal.signal(signal.SIGTSTP, signal_handling)


def get_install_status(component_list):
    """
    Get the component status from install_status log file

    :param component_list: list of components
    :returns: A dictionary with component name and status
    """
    output_dir_path = utils.create_output_dir(manifest_file)
    install_status_json_path = os.path.join(output_dir_path, install_status_json)
    components = {}
    component_status = {}
    try:
        with open(install_status_json_path, "r") as file:
            components = json.load(file)
        for component, val in components.items():
            if component in component_list:
                if val["status"] == "FAILED":
                    status = constants.RED.format(val["status"])
                else:
                    status = constants.GREEN.format(val["status"])
                component_status[component] = status
        return component_status
    except Exception as e:
        log.error("Failed to get install status due to error {}".format(e))


def verify_installation_status(component_list, upgrade=False):
    """
    Verify Installation
    :param component_list: list of components
    """
    components = {}
    table = PrettyTable()
    if upgrade and os.path.exists(temp_conf_file):
        output_dir_path = utils.create_output_dir(temp_conf_file)
    else:
        output_dir_path = utils.create_output_dir(manifest_file)
    install_status_json_path = os.path.join(output_dir_path, install_status_json)
    try:
        with open(install_status_json_path, "r") as file:
            components = json.load(file)
        component_name = []
        component_id = []
        component_status = []
        for component in component_list:
            component_name.append(component.get("label"))
            if utils.is_image(component):
                component_id.append(component.get("comp_id"))
                status = (
                    constants.GREEN.format("SUCCESS")
                    if utils.image_load_status(
                        component.get("label"), component.get("tag"), log
                    )
                    else constants.RED.format("FAILED")
                )
                component_status.append(status)
            elif utils.is_helm(component):
                component_id.append(component.get("comp_id"))
                helm_chart = "{}-{}".format(
                    component.get("label"), component.get("tag")
                )
                status = (
                    constants.GREEN.format("SUCCESS")
                    if (
                        helm_chart in components
                        and components[helm_chart]["status"] == "SUCCESS"
                    )
                    else constants.RED.format("FAILED")
                )
                component_status.append(status)
            else:
                component_id.append(components[component.get("label")]["id"])
                status = (
                    constants.GREEN.format("SUCCESS")
                    if (
                        component.get("label") in components
                        and components[component.get("label")]["status"] == "SUCCESS"
                    )
                    else constants.RED.format("FAILED")
                )
                component_status.append(status)
        utils.format_component_name(component_name)
        utils.reboot_msg(component_status)
        table.add_column("Id", component_id)
        table.add_column("Module", component_name)
        table.add_column("Status", component_status)
        print(table)
    except Exception as e:
        log.error("Failed to verify installation status due to error {}".format(e))


def verify_uninstall_status(uninstall_dict):
    """
    Print uninstall status
    :param uninstall_dict: Dictionary with component details
    """
    components = uninstall_dict
    table = PrettyTable()
    try:
        component_name = []
        component_id = []
        component_status = []
        for component, val in components.items():
            component_name.append(component)
            component_id.append(val["id"])
            if val["status"] == "FAILED":
                status = constants.RED.format(val["status"])
            elif val["status"] == "NOT SUPPORTED":
                status = constants.YELLOW.format(val["status"])
            else:
                status = constants.GREEN.format(val["status"])
            component_status.append(status)
        utils.format_component_name(component_name)
        table.add_column("Id", component_id)
        table.add_column("Module", component_name)
        table.add_column("Status", component_status)
        print(table)
    except Exception as e:
        log.error("Failed to verify uninstall status")


def update_log(
    component, state, component_dict, id="custom", type="native", upgrade=False
):
    """
    Update log file with installation status

    :param component: Recipe component
    :param state: state of the component
    :param component_dict: dictionary to be updated with component details
    :param id: id associated with components
    """
    if upgrade and os.path.exists(temp_conf_file):
        output_dir_path = utils.create_output_dir(temp_conf_file)
    else:
        output_dir_path = utils.create_output_dir(manifest_file)

    install_status_json_path = os.path.join(output_dir_path, install_status_json)

    component_list = {}
    try:
        if (
            os.path.exists(install_status_json_path)
            and os.stat(install_status_json_path).st_size != 0
        ):
            with open(install_status_json_path, "r") as file:
                component_list = json.load(file)
            log.info(
                "Updating status in log file for {} as {}".format(component, state)
            )
            for key, value in component_list.items():
                if key == component:
                    if value["status"] != state:
                        value["status"] = state
        component_val = {}
        component_val["status"] = state
        component_val["id"] = id
        component_val["type"] = type
        component_list[component] = component_val
        component_dict.update(component_list)

        if upgrade and os.path.exists(temp_conf_file):
            output_dir_path = utils.create_output_dir(temp_conf_file)
        else:
            output_dir_path = utils.create_output_dir(manifest_file)

        install_status_json_path = os.path.join(output_dir_path, install_status_json)
        with open(install_status_json_path, "w") as file:
            json.dump(component_dict, file)
        log.info("Successfully updated status in log file for {}".format(component))
    except Exception as e:
        log.error("Failed to update log due to error {}".format(e))


def get_component_list(manifest, path, xml=None, product_key=None, download=False):
    # Clone components
    components_dict = {}
    component_list = {}
    recipe_id = None
    os_id = None

    if not path:
        recipe_id = utils.get_recipe_details(manifest)["id"]
        os_id = utils.get_recipe_details(manifest)["osId"]

    component_list_download = []

    if manifest:
        component_list = utils.get_component_list(manifest)
        components_dict["esb_modules"] = component_list

    if xml:
        component_list = utils.get_component_list(xmlstring=xml)
        components_dict["esb_modules"] = component_list
    for comp_id, val in component_list.items():
        component_list_download.append(val["label"])

    if download and not path:
        log.info(
            "Modules to be downloaded by package are {}".format(component_list_download)
        )
        log.console("Downloading modules...", color_code=constants.CYAN)
        utils.download_component(log, product_key, component_list, recipe_id, os_id)
        log.console("Downloading modules completed...", color_code=constants.GREEN)

    if path:
        try:
            with open(path) as f:
                data = yaml.load(f, Loader=yaml.FullLoader)
                if "esb_modules" in data:
                    component_list = data.get("esb_modules")
                    components_dict["esb_modules"] = component_list
                if "custom_modules" in data:
                    component_list = data.get("custom_modules")
                    components_dict["custom_modules"] = OrderedDict(component_list)
        except yaml.YAMLError as e:
            log.console("Failed to read custom YAML file {}".format(e), error=True)
            sys.exit(-1)
        except Exception as e:
            log.console("Failed to read custom YAML file {}".format(e), error=True)
            sys.exit(-1)
    return components_dict


def download_modules(log, product_key, manifest, path):
    """
    Run the installation scripts

    :param product_key: Product Key associated with the user
    :param manifest: Repo manifest file
    :param path: YAML file with package details
    """
    # FIXME(mkumari): Remove the hardcoded file name
    try:
        downloaded_modules = []
        output_dir_path = utils.create_output_dir(manifest)
        component_list = get_component_list(
            manifest, path, xml=None, product_key=product_key, download=True
        )
        esb_modules_list = utils.unzip_modules(component_list["esb_modules"], log)
        esb_common = utils.get_recipe_details(manifest, common=True)["common_id"]
        if not utils.is_LR_installed(log):
            utils.install_lanternrock(
                component_list["esb_modules"][esb_common], manifest, log
            )

        (
            success_ids,
            failed_ids,
            success_helm_ids,
            failed_helm_ids,
        ) = api.get_download_status()
        if "type" in utils.LR_data and utils.LR_data["type"] == "download":
            utils.send_LR_data(
                {
                    "success_ids": success_ids,
                    "failed_ids": failed_ids,
                    "success_helm_ids": success_helm_ids,
                    "failed_helm_ids": failed_helm_ids,
                    "success_container_ids": [],
                    "failed_container_ids": [],
                },
                log,
            )
            utils.send_telemetry_data(
                (
                    {
                        "success_ids": success_ids,
                        "failed_ids": failed_ids,
                        "successHelmIds": success_helm_ids,
                        "failedHelmIds": failed_helm_ids,
                    }
                ),
                log,
            )
        if "esb_modules" in component_list:
            for comp_id, val in component_list.get("esb_modules").items():
                downloaded_modules.append(val["label"])
        component_list["esb_modules"] = esb_modules_list

    except Exception as e:
        log.console("Failed to download modules: {}".format(e), error=True)
    sys.exit(-1)


def run_installation(log, product_key, manifest, path, xml, upgrade):
    """
    Run the installation scripts

    :param product_key: Product Key associated with the user
    :param manifest: Repo manifest file
    :param path: YAML file with package details
    :param xml: XML string
    """
    log.console("Starting installation", color_code=constants.CYAN)
    # FIXME(mkumari): Remove the hardcoded file name
    file_manifest = "edgesoftware_configuration.xml"
    if upgrade and os.path.exists(temp_conf_file):
        output_dir_path = utils.create_output_dir(temp_conf_file)
        manifest = temp_conf_file
    else:
        output_dir_path = utils.create_output_dir(file_manifest)
        manifest = file_manifest

    state = "FAILED"
    component_list = get_component_list(manifest, path, xml, product_key, True)
    if "esb_modules" in component_list:
        if xml is None:
            esb_common = utils.get_recipe_details(manifest, common=True)["common_id"]
        if xml is None and esb_common in component_list.get("esb_modules"):
            try:
                ret = utils.install_common(
                    component_list["esb_modules"][esb_common], manifest, log
                )
                if not utils.is_LR_installed(log):
                    utils.install_lanternrock(
                        component_list["esb_modules"][esb_common], manifest, log
                    )
                if not ret:
                    if upgrade:
                        log.console("Failed to upgrade", error=True)
                    sys.exit(-1)
                del component_list["esb_modules"][esb_common]
            except Exception as e:
                log.console(
                    "Failed to install 'esb_common'. {}"
                    " Exiting installation.".format(e),
                    error=True,
                )
                sys.exit(-1)
        esb_modules_list = utils.unzip_modules(component_list["esb_modules"], log)
        component_list["esb_modules"] = esb_modules_list
    to_install = []
    if "esb_modules" in component_list:
        for comp_id, val in component_list.get("esb_modules").items():
            if utils.is_image(val):
                to_install.append(
                    {
                        "label": val["label"],
                        "type": val.get("type"),
                        "comp_id": comp_id,
                        "tag": val.get("tag"),
                    }
                )
            elif utils.is_helm(val):
                to_install.append(
                    {
                        "label": val["label"],
                        "type": val.get("type"),
                        "comp_id": comp_id,
                        "tag": val.get("tag"),
                    }
                )

            else:
                to_install.append({"label": val["label"], "comp_id": comp_id})

    if "custom_modules" in component_list:
        to_install.extend(
            list(
                {"label": module}
                for module in component_list.get("custom_modules").keys()
            )
        )

    log.console(
        "Modules to be installed by package"
        " are {}".format(list(module.get("label") for module in to_install)),
        color_code=constants.CYAN,
    )

    if upgrade:
        log.console(
            " Uninstalling previously installed Package ".center(50, "-"),
            color_code=constants.YELLOW,
        )
        uninstall_ingredient(False, True, False, upgrade=True)
        log.console(
            "Starting modules installation".center(50, "-"), color_code=constants.YELLOW
        )
        log.console(
            " WARNING: DO NOT INTERRUPT ".center(50, "*"), color_code=constants.YELLOW
        )

        # Re-installing esb_common as during upgrade we do a blanket uninstallation
        ordered_dict = OrderedDict()
        ordered_dict = utils.get_component_list(manifest)
        esb_common = utils.get_recipe_details(manifest, common=True)["common_id"]
        if esb_common in ordered_dict:
            utils.install_common(ordered_dict[esb_common], manifest, log)
        # Reininstallation of LR SDK as it is uninstalled along with esb_common
        if constants.Operating_system == "Linux":
            utils.install_lanternrock(ordered_dict[esb_common], manifest, log)

    success_ids = []
    failed_ids = []
    success_helm_ids = []
    failed_helm_ids = []
    success_container_ids = []
    failed_container_ids = []
    component_update = {}

    for modules, modules_dict in component_list.items():
        for component_id, value in modules_dict.items():
            component = value["label"]
            if utils.is_image(value):
                try:
                    ret = False
                    module_type = "image"
                    startTime = time.time()

                    if path and os.path.isfile(
                        "{}.tar".format(os.path.join(value["path"], component_id))
                    ):
                        log.console(
                            "Loading Image {}".format(value["label"]),
                            color_code=constants.CYAN,
                        )
                        image_path = os.path.join(value["path"], component_id)
                        ret = utils.load_image(
                            log, value["label"], value["tag"], image_path
                        )
                    else:
                        log.console(
                            "Pulling Image {}".format(value["label"]),
                            color_code=constants.CYAN,
                        )
                        ret = utils.intel_registry_pull(
                            value["label"], value["tag"], product_key, log
                        )
                    endTime = time.time()

                    if ret == True:
                        state = "SUCCESS"
                        log.console(
                            "Successfully installed {} "
                            "took {}".format(
                                component,
                                utils.print_time(endTime - startTime),
                            ),
                            color_code=constants.GREEN,
                        )
                        update_log(
                            value["label"] + ":" + value["tag"],
                            state,
                            component_update,
                            component_id,
                            module_type,
                            upgrade,
                        )
                        success_container_ids.append(component_id)
                    else:
                        state = "FAILED"
                        log.console(
                            "Failed to install {} took {}".format(
                                component,
                                utils.print_time(endTime - startTime),
                            ),
                            error=True,
                        )
                        update_log(
                            value["label"] + ":" + value["tag"],
                            state,
                            component_update,
                            component_id,
                            module_type,
                            upgrade,
                        )
                        failed_container_ids.append(component_id)
                except Exception as e:
                    state = "FAILED"
                    log.console(
                        "Failed to download Image {} due to error "
                        "{}".format(value["label"], e),
                        error=True,
                    )
                    update_log(
                        value["label"] + ":" + value["tag"],
                        state,
                        component_update,
                        component_id,
                        module_type,
                        upgrade,
                    )
                    failed_container_ids.append(component_id)

            elif utils.is_helm(value):
                try:
                    ret = None
                    helm_list = []
                    module_type = "helm"
                    helm_list.append(
                        {
                            "label": value["label"],
                            "comp_id": component_id,
                            "tag": value["tag"],
                            "path": value["path"],
                        }
                    )

                    ret = update_helm_keys(helm_list, product_key, True)
                    if ret == True or ret == None:
                        state = "SUCCESS"
                        update_log(
                            value["label"] + "-" + value["tag"],
                            state,
                            component_update,
                            component_id,
                            module_type,
                            upgrade,
                        )
                        success_helm_ids.append(component_id)

                    else:
                        state = "FAILED"
                        update_log(
                            value["label"] + "-" + value["tag"],
                            state,
                            component_update,
                            component_id,
                            module_type,
                            upgrade,
                        )
                        failed_helm_ids.append(component_id)
                except Exception as e:
                    state = "FAILED"
                    log.console(
                        "Failed to update keys {}-{} due to error "
                        "{}".format(value["label"], value["tag"], e),
                        error=True,
                    )
                    update_log(
                        value["label"] + "-" + value["tag"],
                        state,
                        component_update,
                        component_id,
                        module_type,
                        upgrade,
                    )
                    failed_helm_ids.append(component_id)
            else:
                try:
                    src_path = None
                    module_type = "native"
                    custom = False
                    if modules == "custom_modules":
                        custom = True
                        abs_src_path = os.path.abspath(value)
                        src_path = os.path.join(abs_src_path, "esb_install.py")
                    else:
                        abs_src_path = os.path.abspath(value["path"])
                        zip_location = os.path.join(abs_src_path, component)
                        if constants.Operating_system == "Linux":
                            so_file = "esb_install" + ".so"
                        elif constants.Operating_system == "Windows":
                            so_file = "esb_install" + ".pyd"
                        install_file = "esb_install" + ".py"
                        src_path = os.path.join(zip_location, so_file)
                        if not os.path.exists(src_path):
                            src_path = os.path.join(zip_location, install_file)
                    install = False
                    if src_path and os.path.exists(src_path):
                        output_dir = os.path.join(output_dir_path, component)
                        # Importing the ingredient SO files and initiating the
                        # install process
                        try:
                            if custom:
                                install = True
                            else:
                                so_location = os.path.join(value["path"], component_id)
                                spec = importlib.util.spec_from_file_location(
                                    "esb_install", src_path
                                )
                                module_name = importlib.util.module_from_spec(spec)
                                spec.loader.exec_module(module_name)
                                log.info(
                                    "Imported module for {} is {}".format(
                                        component, module_name
                                    )
                                )

                                if utils.check_installed(log, component):
                                    installed = module_name.verify_install(
                                        zip_location, output_dir
                                    )
                                    if installed:
                                        if utils.prompt_reinstall(log, component):
                                            install = True
                                    else:
                                        install = True
                                else:
                                    install = True
                            ret = False
                            if install:
                                log.console(
                                    "Installing {}".format(component),
                                    color_code=constants.CYAN,
                                )
                                startTime = time.time()
                                if custom:
                                    if constants.Operating_system == "Linux":
                                        status = subprocess.run(["python3", src_path])
                                    elif constants.Operating_system == "Windows":
                                        status = subprocess.run(["python", src_path])
                                    if not status.returncode:
                                        ret = True
                                else:
                                    ret = module_name.main_install(
                                        zip_location, output_dir
                                    )
                                    if ret:
                                        success_ids.append(component_id)
                                    else:
                                        failed_ids.append(component_id)
                                endTime = time.time()
                                if ret == 2:
                                    log.console(
                                        "Skipping install for {}".format(component),
                                        color_code=constants.CYAN,
                                    )
                                    continue
                                elif ret == True:
                                    state = "SUCCESS"
                                    log.console(
                                        "Successfully installed {} "
                                        "took {}".format(
                                            component,
                                            utils.print_time(endTime - startTime),
                                        ),
                                        color_code=constants.GREEN,
                                    )
                                else:
                                    state = "FAILED"
                                    log.console(
                                        "Failed to install {} took {}".format(
                                            component,
                                            utils.print_time(endTime - startTime),
                                        ),
                                        error=True,
                                    )
                                if not custom:
                                    update_log(
                                        component,
                                        state,
                                        component_update,
                                        component_id,
                                        module_type,
                                        upgrade,
                                    )
                                else:
                                    update_log(component, state, component_update)
                        except Exception as e:
                            state = "FAILED"
                            failed_ids.append(component_id)
                            log.console(
                                "Failed to install {}. {}".format(component, e),
                                error=True,
                            )
                            if not custom:
                                update_log(
                                    component,
                                    state,
                                    component_update,
                                    component_id,
                                    module_type,
                                    upgrade,
                                )
                            else:
                                update_log(component, state, component_update)
                    else:
                        state = "FAILED"
                        failed_ids.append(component_id)
                        msg = (
                            "Failed to find installation file for {} at {}. "
                            "Check file location and re-enter the path to"
                            " start installation."
                        )
                        print_msg = "Failed to install {} due to missing file"
                        log.console(
                            msg.format(component, src_path),
                            print_msg.format(component),
                            error=True,
                        )
                        if not custom:
                            update_log(
                                component,
                                state,
                                component_update,
                                component_id,
                                module_type,
                                upgrade,
                            )
                        else:
                            update_log(component, state, component_update)
                except Exception as e:
                    log.console("Failed to install {}".format(e), error=True)

    # api.update_ingredient_count(success_ids, failed_ids, log)
    utils.send_LR_data(
        (
            {
                "success_ids": success_ids,
                "failed_ids": failed_ids,
                "success_helm_ids": success_helm_ids,
                "failed_helm_ids": failed_helm_ids,
                "success_container_ids": success_container_ids,
                "failed_container_ids": failed_container_ids,
            }
        ),
        log,
    )
    utils.send_telemetry_data(
        (
            {
                "success_ids": success_ids,
                "failed_ids": failed_ids,
                "successHelmIds": success_helm_ids,
                "failedHelmIds": failed_helm_ids,
                "successContainerIds": success_container_ids,
                "failedContainerIds": failed_container_ids,
            }
        ),
        log,
    )
    log.console("Installation of package complete", color_code=constants.GREEN)

    return list(to_install)


def setup_start(
    product_key,
    manifest=None,
    path=None,
    xml=None,
    update=False,
    upgrade=False,
    download=False,
):
    """
    Starting setup

    :param product_key: Product Key associated with the user
    :param manifest: manifest.xml file
    :param path: Path of a YAML file with component list
    :param xml: XML string
    """
    # FIXME(mkumari): Remove the hardcoded file name
    if upgrade and os.path.exists(temp_conf_file):
        output_dir_path = utils.create_output_dir(temp_conf_file)
    else:
        output_dir_path = utils.create_output_dir(manifest_file)
    output_log_path = os.path.join(output_dir_path, output_log)
    recipe_id = utils.get_recipe_details(manifest_file)["id"]
    print(constants.CYAN.format("Starting the setup..."))

    try:
        install_status_json_path = os.path.join(output_dir_path, install_status_json)
        if not os.path.exists(install_status_json_path):
            with open(install_status_json_path, "w"):
                pass
        # command = ['touch', install_status_json_path]
        # ret = run(command, stdout=PIPE, stderr=PIPE)
    except Exception as e:
        print(
            constants.RED.format("Failed to create install_status_json. {}".format(e))
        )
        sys.exit(-1)

    global log
    if not log:
        log = logger.Logger(output_log_path)

    log.console(
        "ESB CLI version: {}\nTarget OS: {}".format(
            constants.VERSION, constants.BUILD_OS
        ),
        color_code=constants.CYAN,
    )
    utils.reinstall_check(update, upgrade, log)
    system_info = utils.sys_info(log)
    os_name = system_info["os_name"]
    utils.python_version(log)
    utils.checkInternetConnection(log)
    if update and product_key is not None:
        if not utils.validate_product_key(log, product_key, recipe_id, update):
            sys.exit(-1)

    elif not path and product_key is not None:
        if not utils.validate_product_key(
            log, product_key, recipe_id, update, upgrade, download
        ):
            sys.exit(-1)
    recipe_version = utils.get_recipe_details(manifest_file)["label"]
    utils.identify_geolocation(log)
    if not download:
        # Skip prerequisite check during download
        utils.pre_requisites(log, os_name)
    utils.print_system_info(system_info, log)
    utils.check_enough_memory(system_info, recipe_id, log)
    utils.send_telemetry_data(({"product_key": product_key}), log)
    utils.send_LR_data({"product_key": product_key}, log)
    if "recipe_id" not in utils.LR_data:
        utils.send_telemetry_data(({"recipe_id": recipe_id}), log)
        utils.send_LR_data({"recipe_id": recipe_id}, log)
    if download:
        utils.send_telemetry_data(({"type": "download"}), log)
        utils.send_LR_data({"type": "download"}, log)
        download_modules(log, product_key, manifest, path)
    component_list = run_installation(log, product_key, manifest, path, xml, upgrade)
    if not upgrade:
        verify_installation_status(component_list)
    return component_list


def list_packages(default=False, json_out=False, version=False, local=False):
    """
    List installed packages in a recipe

    :param default: If True, lists all the default packages in the recipe
    :param json_out: Return the output in json format
    :param version: If True, lists all the supported recipes
    :param local: If True, lists all the supported modules(in JSON format) present in XML
    """
    # FIXME(mkumari): Remove the hardcoded file name
    output_dir_path = utils.create_output_dir(manifest_file)
    global log
    output_log_path = os.path.join(output_dir_path, output_log)
    log = logger.Logger(output_log_path)
    install_status_json_path = os.path.join(output_dir_path, install_status_json)
    recipe_version = utils.get_recipe_details(manifest_file)["id"]
    os_id = utils.get_recipe_details(manifest_file)["osId"]

    if default:
        resp = api.get_components_list(recipe_version, os_id, log)
        if json_out:
            print(resp)
            return resp
        log.console(
            "Modules in the recommended configuration for " "{}".format(recipe_version),
            color_code=constants.CYAN,
        )
        if resp:
            component_names = []
            component_ids = []
            component_versions = []
            table = PrettyTable()
            for ingredient in resp["ingredients"]:
                component_names.append(ingredient["label"])
                component_ids.append(ingredient["id"])
                component_versions.append(ingredient["version"])
            table.add_column("ID", component_ids)
            table.add_column("Module", component_names)
            table.add_column("Version", component_versions)
            print(table)
        return

    if version:
        package_type = utils.get_recipe_details(manifest_file)["packageId"]
        resp = api.get_upgrade_list(package_type, os_id, log)
        if json_out:
            print(resp)
            return resp
        log.console(
            "Packages recommended for " "'{}'".format(package_type),
            color_code=constants.CYAN,
        )
        if resp:
            component_names = []
            component_ids = []
            component_versions = []
            table = PrettyTable()
            for ingredient in resp:
                component_names.append(ingredient["label"])
                component_ids.append(ingredient["id"])
                component_versions.append(ingredient["version"])
            table.add_column("ID", component_ids)
            table.add_column("Package", component_names)
            table.add_column("Version", component_versions)
            print(table)
        return

    if local:
        component_list = get_component_list(manifest_file, None, None, None, None)
        recipe_name = utils.get_recipe_details(manifest_file)["label"]
        recipe_version = utils.get_recipe_details(manifest_file)["version"]

        if "esb_modules" in component_list:
            esb_common = utils.get_recipe_details(manifest_file, common=True)[
                "common_id"
            ]
            if esb_common in component_list.get("esb_modules"):
                del component_list["esb_modules"][esb_common]

        to_install = {"recipe_name": recipe_name, "recipe_version": recipe_version}
        to_install.update({"component_list": []})
        if "esb_modules" in component_list:
            for comp_id, val in component_list.get("esb_modules").items():
                to_install["component_list"].append(
                    {val["label"].replace("_", " "): {"status": None, "id": comp_id}}
                )
        log.console(
            "Modules to be installed by package"
            " are {}".format(json.dumps(to_install, indent=2)),
            color_code=constants.CYAN,
        )

        return json.dumps(to_install)

    if not os.path.exists(install_status_json_path):
        log.console("No packages or modules found.", color_code=constants.YELLOW)
        return

    try:
        table = PrettyTable()
        component_name = []
        component_status = []
        component_id = []
        component_list = {}

        recipe_name = utils.get_recipe_details(manifest_file)["label"]
        recipe_version = utils.get_recipe_details(manifest_file)["version"]
        component_list = {"recipe_name": recipe_name, "recipe_version": recipe_version}
        with open(install_status_json_path, "r") as file:
            try:
                component_list.update({"component_list": []})
                component_list["component_list"].append(json.load(file))
            except JSONDecodeError:
                pass
        if json_out:
            print(json.dumps(component_list))
            return json.dumps(component_list)

        for val in component_list["component_list"]:
            for module, module_val in val.items():
                if module_val["status"] == "FAILED":
                    component_status.append(constants.RED.format(module_val["status"]))
                else:
                    component_status.append(
                        constants.GREEN.format(module_val["status"])
                    )
                component_id.append(module_val["id"])
                component_name.append(module)

        utils.format_component_name(component_name)
        table.add_column("ID", component_id)
        table.add_column("Module", component_name)
        table.add_column("Status", component_status)
        print(table)
    except Exception as e:
        msg = "Failed to read {}. {}"
        log.console(
            msg.format(install_status_json_path, e), msg.format(" ", e), error=True
        )
        sys.exit(-1)


def update(package):
    """
    Updates a module in a package

    :package: List of packages to update
    """
    # FIXME(mkumari): Remove the hardcoded file name
    is_product_key = True
    product_key = None
    is_product_key = check_product_key(manifest_file=manifest_file)
    if os.path.exists(manifest_file) and is_product_key is True:
        print(
            constants.BICYAN.format(
                "Please enter the "
                "Product Key. The Product Key is contained in the email you "
                "received from Intel confirming your download: "
            ),
            end=" ",
        )
        product_key = input()
    output_dir_path = utils.create_output_dir(manifest_file)
    output_log_path = os.path.join(output_dir_path, output_log)
    global log
    if not log:
        log = logger.Logger(output_log_path)

    recipe_version = utils.get_recipe_details(manifest_file)["id"]
    log.console(
        "Updating {} modules of package {}".format(list(package), recipe_version),
        color_code=constants.CYAN,
    )
    utils.send_telemetry_data(({"type": "update"}), log)
    utils.send_LR_data({"type": "update"}, log)

    resp = api.get_update_components(list(package), recipe_version, product_key, log)
    if resp:
        try:
            setup_start(product_key, xml=resp, update=True)
        except Exception as e:
            log.console("Failed to update module {}. {}".format(package, e), error=True)
        try:
            components = utils.get_component_list(xmlstring=resp)
            utils.update_xml(manifest_file, resp, log)
        except Exception as e:
            log.console(
                "Error updating the {} XML file due to error {}".format(
                    manifest_file, e
                ),
                error=True,
            )
            sys.exit(-1)
    else:
        log.console("Failed to update module", error=True)
        sys.exit(-1)


def print_log(components_id, all_components=False):
    """
    Prints the logs.

    :param components: Name of the components
    :param all_components: Specify True to print logs for all components
    """

    def print_installer_log(log_file):
        if os.path.exists(log_file):
            with open(log_file) as fd:
                print(constants.CYAN.format("Start of installer log".center(80, "=")))
                print(fd.read())
                print(constants.CYAN.format("End of installer log".center(80, "=")))
        else:
            print(constants.CYAN.format("No log found"))

    # FIXME(mkumari): Remove the hardcoded file name
    output_dir_path = utils.create_output_dir(manifest_file)
    output_log_path = os.path.join(output_dir_path, output_log)
    if not components_id and not all_components:
        print_installer_log(output_log_path)
        return
    global log
    log = logger.Logger(output_log_path)

    component_list = {}
    component_dict = utils.get_component_list(manifest_file)
    if components_id:
        for component_id, val in component_dict.items():
            component = val["label"]
            if component_id in components_id:
                component_list[component] = component_id
    if all_components:
        for component_id, val in component_dict.items():
            component = val["label"]
            component_list[component] = component_id
        if "esb_common" in list(component_list.keys()):
            del component_list["esb_common"]
        print_installer_log(output_log_path)
    for component in list(component_list.keys()):
        log_path = os.path.join(output_dir_path, component, "install.log")
        if os.path.exists(log_path):
            with open(log_path) as fd:
                print(
                    constants.CYAN.format(
                        "Start of log for module {}".center(80, "=").format(
                            component.replace("_", " ")
                        )
                    )
                )
                print(fd.read())
                print(
                    constants.CYAN.format(
                        "End of log for module {}".center(80, "=").format(
                            component.replace("_", " ")
                        )
                    )
                )
        else:
            log.console("No log found for module " "{}".format(component), error=True)


def export_package(package_name=None, user_yaml=None):
    """
    Package the recipe
    :param package_name: Name of the package
    :param manifest_file: xml file to read components
    """
    manifest_file = "edgesoftware_configuration.xml"
    configuration_yaml = "edgesoftware_configuration.yaml"
    user_config_file = "config_install.yml"
    config_file = "config.ini"
    resource_files = []

    output_dir_path = utils.create_output_dir(manifest_file)
    output_log_path = os.path.join(output_dir_path, output_log)
    global log
    if not log:
        log = logger.Logger(output_log_path)

    if os.path.exists(configuration_yaml):
        os.remove(configuration_yaml)
    component_list = get_component_list(manifest_file, user_yaml, download=False)
    if package_name == None:
        package_name = utils.get_recipe_details(manifest_file)["label"]

    support_files = [
        sys.argv[0],
        manifest_file,
        configuration_yaml,
        user_config_file,
        config_file,
    ]

    resource_files = download_package_artifacts(manifest_file, None, None, False, True)
    if resource_files:
        support_files = support_files + resource_files

    try:
        temp_dir = tempfile.mkdtemp()
        esb_modules_dir = os.path.join(temp_dir, package_name, "esb_modules")
        custom_modules_dir = os.path.join(temp_dir, package_name, "custom_modules")
        package_module_dir = os.path.join(temp_dir, package_name)
        os.makedirs(esb_modules_dir)
        os.makedirs(custom_modules_dir)

    except Exception as e:
        log.console("Failed to create package. {}".format(e), error=True)
        sys.exit(-1)

    modules_to_zip = {"esb_modules": OrderedDict({}), "custom_modules": OrderedDict({})}
    try:
        for modules, modules_dict in component_list.items():
            for component_id, value in modules_dict.items():
                try:
                    docker_file_name = ""
                    if utils.is_image(value):
                        utils.save_image(
                            log, value["label"], value["tag"], component_id
                        )
                        docker_file_name = "{}.tar".format(component_id)
                    component = value["label"]
                    src_path = ""
                    src_path_helm = ""
                    custom = False
                    if modules == "custom_modules":
                        custom = True
                        abs_src_path = os.path.abspath(value)
                        src_path = os.path.join(abs_src_path)
                    else:
                        if not utils.is_image(value):
                            abs_src_path = os.path.abspath(value["path"])
                            zip_location = os.path.join(abs_src_path, component_id)
                            src_path = zip_location + ".zip"
                            src_path_helm = zip_location + ".tgz"
                    if (
                        os.path.exists(src_path)
                        or os.path.exists(src_path_helm)
                        or utils.is_image(value)
                    ):

                        if custom:
                            custom_component = os.path.join(
                                custom_modules_dir, component
                            )
                            if os.path.isfile(src_path):
                                shutil.copy(src_path, custom_modules_dir)
                            elif os.path.isfile(src_path_helm):
                                shutil.copy(src_path_helm, custom_modules_dir)
                            elif utils.is_image(value):
                                if os.path.isfile(docker_file_name):
                                    shutil.copy(docker_file_name, custom_modules_dir)
                                    os.remove(docker_file_name)
                            elif os.path.isdir(src_path_helm):
                                copy_tree(src_path, custom_modules_dir)
                            elif os.path.isdir(src_path):
                                copy_tree(src_path, custom_modules_dir)
                            else:
                                log.console(
                                    "Failed to add custom module: {}".format(
                                        custom_component
                                    ),
                                    error=True,
                                )
                                sys.exit(-1)

                            if not utils.is_image(value):
                                path = os.path.join(modules, value.split("/")[-1])
                                modules_to_zip[modules].update({component: path})

                        else:
                            if os.path.isfile(src_path):
                                shutil.copy(src_path, esb_modules_dir)
                            elif os.path.isdir(src_path):
                                copy_tree(src_path, esb_modules_dir)
                            elif os.path.isfile(src_path_helm):
                                shutil.copy(src_path_helm, esb_modules_dir)
                            elif utils.is_image(value):
                                if os.path.isfile(docker_file_name):
                                    shutil.copy(docker_file_name, esb_modules_dir)
                                    os.remove(docker_file_name)
                            elif os.path.isdir(src_path_helm):
                                copy_tree(src_path_helm, esb_modules_dir)
                            else:
                                log.console(
                                    "Failed to add esb module: {}".format(component_id),
                                    error=True,
                                )
                                sys.exit(-1)
                            value["path"] = modules
                            if "esb_install" in value:
                                modules_to_zip[modules].update(
                                    {
                                        component_id: {
                                            "path": value["path"],
                                            "label": component,
                                            "esb_install": value["esb_install"],
                                        }
                                    }
                                )
                            elif utils.is_helm(value):
                                modules_to_zip[modules].update(
                                    {
                                        component_id: {
                                            "path": value["path"],
                                            "label": component,
                                            "tag": value["tag"],
                                            "type": "helm",
                                        }
                                    }
                                )
                            elif utils.is_image(value):
                                modules_to_zip[modules].update(
                                    {
                                        component_id: {
                                            "path": value["path"],
                                            "label": component,
                                            "tag": value["tag"],
                                            "type": "image",
                                        }
                                    }
                                )
                            else:
                                modules_to_zip[modules].update(
                                    {
                                        component_id: {
                                            "path": value["path"],
                                            "label": component,
                                        }
                                    }
                                )
                except Exception as e:
                    log.console("Failed to create package. {}".format(e), error=True)
                    sys.exit(-1)

        try:
            with open(configuration_yaml, "w") as yaml_file:
                yaml.dump(modules_to_zip, yaml_file)

            file_list = []
            for package, module_dirs, module_file in os.walk(package_module_dir):
                for module_dir in module_dirs:
                    if len(os.listdir(os.path.join(package, module_dir))) == 0:
                        shutil.rmtree(os.path.join(package, module_dir))
                if module_file:
                    file_list.append(module_file)
            if len(file_list) == 0:
                try:
                    if os.path.exists(temp_dir) and os.path.exists(configuration_yaml):
                        shutil.rmtree(temp_dir)
                        os.remove(configuration_yaml)
                except Exception as e:
                    log.console(
                        "Failed to remove temporary files. {}".format(e), error=True
                    )
                log.console("No modules found to export.", color_code=constants.YELLOW)
                sys.exit(-1)

            utils.copy_export_deps(support_files, package_module_dir, log)
            shutil.make_archive(package_name, "zip", temp_dir)

            if os.path.exists(temp_dir) and os.path.exists(configuration_yaml):
                shutil.rmtree(temp_dir)
                os.remove(configuration_yaml)
            else:
                log.console("Failed to remove temp files")
            log.console(
                "Successfully created {}.zip".format(package_name),
                color_code=constants.GREEN,
            )
        except shutil.Error as e:
            msg = "Failed to create archive. {}"
            print_msg = "Failed to create archive."
            log.console(msg.format(e), print_msg, error=True)
            sys.exit(-1)
        except Exception as e:
            msg = "Failed to create package. {}"
            print_msg = "Failed to create package."
            log.console(msg.format(e), print_msg, error=True)
            sys.exit(-1)

    except KeyboardInterrupt:
        log.console("Export aborted by user.Exiting" " export operation", error=True)
        zip_file = package_name + ".zip"
        if os.path.exists(zip_file):
            os.remove(zip_file)
        if os.path.exists(docker_file_name):
            os.remove(docker_file_name)
        if os.path.exists(temp_dir) and os.path.exists(configuration_yaml):
            shutil.rmtree(temp_dir)
            os.remove(configuration_yaml)
        sys.exit(-1)
    except Exception as e:
        msg = "Failed to create package. {}"
        print_msg = "Failed to create package."
        log.console(msg.format(e), print_msg, error=True)
        sys.exit(-1)


def uninstall_ingredient(ingredient_id, all_modules, file, upgrade=False):

    output_dir_path = utils.create_output_dir(manifest_file)
    output_log_path = os.path.join(output_dir_path, output_log)
    install_status_json_path = os.path.join(output_dir_path, install_status_json)
    global log
    log = logger.Logger(output_log_path)
    recipe_name = utils.get_recipe_details(manifest_file)["label"]
    recipe_version = utils.get_recipe_details(manifest_file)["version"]
    recipe_id = utils.get_recipe_details(manifest_file)["id"]
    if not upgrade:
        utils.send_LR_data({"type": "uninstall", "recipe_id": recipe_id}, log)
        utils.send_telemetry_data(({"type": "uninstall", "recipe_id": recipe_id}), log)

    if file:
        install_path = "_".join(["esb", "modules"])
    else:
        install_path = "_".join([recipe_name, recipe_version])
    if not os.path.exists(install_status_json_path):
        log.console("No Modules to uninstall", color_code=constants.YELLOW)
        sys.exit(-1)
    try:
        components = {}
        with open(install_status_json_path, "r") as file:
            components_list = json.load(file)
        reverse_list = list(components_list.keys())
        reverse_list.reverse()
        component_list = {}
        for component in reverse_list:
            component_list[component] = components_list[component]

        if not all_modules:
            id_list = []
            for value in component_list.values():
                id_list.append(value["id"])
            for id in ingredient_id:
                if id not in id_list:
                    log.console("component id {} not installed.".format(id), error=True)
        for name, value in component_list.items():
            component_val = {}
            ingredient_path = os.path.join(install_path, name)
            if all_modules or value["id"] in ingredient_id:
                if utils.is_image(value):
                    component_val["id"] = value["id"]
                    component_val["type"] = "image"
                    components[name] = component_val
                if utils.is_helm(value):
                    component_val["id"] = value["id"]
                    component_val["type"] = "helm"
                    components[name] = component_val
                else:
                    component_val["id"] = value["id"]
                    component_val["path"] = ingredient_path
                    components[name] = component_val

        if len(components):
            log.console(
                "Components to be uninstalled are :{}".format(list(components.keys())),
                color_code=constants.CYAN,
            )
        else:
            log.console("No modules to uninstall", color_code=constants.YELLOW)
            if all_modules:
                utils.clean_esb_common(log, output_dir_path)
            sys.exit(-1)

        success_ids = []
        failed_ids = []
        success_helm_ids = []
        failed_helm_ids = []
        success_container_ids = []
        failed_container_ids = []
        uninstall_status = {}

        def status_update(component, component_id, status="FAILED"):
            uninstall_status.update({component: {"id": component_id, "status": status}})

        for component, value in components.items():
            try:
                if utils.is_image(value):
                    startTime = time.time()
                    ret = 0  # initializing with uninstall FAIL status
                    try:
                        ret = utils.remove_docker_image(component, log)
                    except Exception as e:
                        status = "FAILED"
                        log.error("Failed to uninstall module " " {}".format(e))
                        log.console("Failed to uninstall module", error=True)
                        status_update(component, value["id"], status)
                        continue
                    endTime = time.time()
                    if ret == 1:
                        success_container_ids.append(value["id"])
                        status = "SUCCESS"
                        log.console(
                            "Successfully uninstalled {} "
                            "took {}".format(
                                component, utils.print_time(endTime - startTime)
                            ),
                            color_code=constants.GREEN,
                        )
                        utils.update_xml_json(
                            value["id"], component, manifest_file, log
                        )
                        status_update(component, value["id"], status)
                    else:
                        status = "FAILED"
                        failed_container_ids.append(value["id"])
                        log.console(
                            "Failed to uninstall {} took {}".format(
                                component, utils.print_time(endTime - startTime)
                            ),
                            error=True,
                        )
                        status_update(component, value["id"])

                elif utils.is_helm(value):
                    startTime = time.time()
                    ret = False  # initializing with uninstall FAIL status
                    ret = utils.remove_helm_keys(component, log)
                    endTime = time.time()
                    if ret:
                        success_helm_ids.append(value["id"])
                        status = "SUCCESS"
                        log.console(
                            "Successfully uninstalled {} "
                            "took {}".format(
                                component, utils.print_time(endTime - startTime)
                            ),
                            color_code=constants.GREEN,
                        )
                        utils.update_xml_json(
                            value["id"], component, manifest_file, log
                        )
                        status_update(component, value["id"], status)
                    else:
                        status = "FAILED"
                        failed_helm_ids.append(value["id"])
                        log.console(
                            "Failed to uninstall {} took {}".format(
                                component, utils.print_time(endTime - startTime)
                            ),
                            error=True,
                        )
                        status_update(component, value["id"])

                elif not utils.is_image(value) and not utils.is_helm(value):
                    if constants.Operating_system == "Windows":
                        so_file = "esb_install" + ".pyd"
                    elif constants.Operating_system == "Linux":
                        so_file = "esb_install" + ".so"
                    install_file = "esb_install" + ".py"
                    abs_src_path = os.path.abspath(value["path"])
                    src_path = os.path.join(abs_src_path, so_file)
                    if not os.path.exists(src_path):
                        src_path = os.path.join(abs_src_path, install_file)
                    output_dir = os.path.join(output_dir_path, component)
                    if src_path and os.path.exists(src_path):
                        try:
                            spec = importlib.util.spec_from_file_location(
                                "esb_install", src_path
                            )
                            module_name = importlib.util.module_from_spec(spec)
                            spec.loader.exec_module(module_name)

                            log.console(
                                "Uninstalling {}".format(component),
                                color_code=constants.CYAN,
                            )
                            startTime = time.time()
                            ret = 0  # initializing with uninstall FAIL status
                            try:
                                if all_modules:
                                    ret = module_name.main_uninstall(
                                        abs_src_path, output_dir, False
                                    )
                                else:
                                    # In case individual uninstallation is not supported
                                    ret = module_name.main_uninstall(
                                        abs_src_path, output_dir, True
                                    )
                            except Exception as e:
                                status = "NOT SUPPORTED"
                                log.error(
                                    "Module does not support uninstall" " {}".format(e)
                                )
                                log.console(
                                    "Module does not support uninstall", error=True
                                )
                                status_update(component, value["id"], status)
                                continue
                            endTime = time.time()
                            if ret == 1:
                                success_ids.append(value["id"])
                                status = "SUCCESS"
                                log.console(
                                    "Successfully uninstalled {} "
                                    "took {}".format(
                                        component, utils.print_time(endTime - startTime)
                                    ),
                                    color_code=constants.GREEN,
                                )
                                utils.update_xml_json(
                                    value["id"], component, manifest_file, log
                                )
                                status_update(component, value["id"], status)
                            elif ret == 2:
                                status = "NOT SUPPORTED"
                                log.console(
                                    "Individual uninstall of the module is"
                                    " not supported",
                                    error=True,
                                )
                                status_update(component, value["id"], status)
                            else:
                                failed_ids.append(value["id"])
                                log.console(
                                    "Failed to uninstall {} took {}".format(
                                        component, utils.print_time(endTime - startTime)
                                    ),
                                    error=True,
                                )
                                status_update(component, value["id"])
                        except Exception as e:
                            msg = "Failed to uninstall {}. {}"
                            print_msg = "Failed to uninstall {}"
                            log.console(
                                msg.format(component, e),
                                print_msg.format(component),
                                error=True,
                            )
                            status_update(component, value["id"])
                    else:
                        if utils.is_image(value):
                            failed_container_ids.append(value["id"])
                        elif utils.is_helm(value):
                            failed_helm_ids.append(value["id"])
                        else:
                            failed_ids.append(value["id"])
                        msg = (
                            "Failed to find installation file for {} at {}. "
                            "Please check file location"
                        )
                        print_msg = "Failed to uninstall {} due to missing file"
                        log.console(
                            msg.format(component, src_path),
                            print_msg.format(component),
                            error=True,
                        )
                        status_update(component, value["id"])
            except Exception as e:
                msg = "Failed to uninstall {}"
                print_msg = "Failed to uninstall"
                log.console(msg.format(e), print_msg, error=True)

        if not upgrade:
            utils.send_LR_data(
                {
                    "success_ids": success_ids,
                    "failed_ids": failed_ids,
                    "success_helm_ids": success_helm_ids,
                    "failed_helm_ids": failed_helm_ids,
                    "success_container_ids": success_container_ids,
                    "failed_container_ids": failed_container_ids,
                },
                log,
            )
            utils.send_telemetry_data(
                (
                    {
                        "success_ids": success_ids,
                        "failed_ids": failed_ids,
                        "successHelmIds": success_helm_ids,
                        "failedHelmIds": failed_helm_ids,
                        "successContainerIds": success_container_ids,
                        "failedContainerIds": failed_container_ids,
                    }
                ),
                log,
            )
        if all_modules:
            utils.clean_esb_common(log, output_dir_path)

        log.console("Uninstall Finished", color_code=constants.GREEN)
        verify_uninstall_status(uninstall_status)

    except KeyboardInterrupt as e:
        log.console(
            "Uninstallation aborted by user. Exiting uninstallation", error=True
        )
        sys.exit(-1)
    except JSONDecodeError as e:
        log.info(
            "Failed to load file:{} with error {}".format(install_status_json_path, e)
        )
        log.console("No modules to uninstall", color_code=constants.YELLOW)
        if all_modules:
            utils.clean_esb_common(log, output_dir_path)
        log.console("Uninstall Finished", color_code=constants.GREEN)
    except Exception as e:
        msg = "Error during uninstallation {}"
        print_msg = "Error during uninstallation"
        log.console(msg.format(e), print_msg, error=True)


def upgrade(package):
    """
    Upgrade selected package
    :param package: id of the package
    """
    installed_path = ""
    temp_dir = tempfile.mkdtemp()
    global temp_conf_file
    temp_conf_file = os.path.join(temp_dir, manifest_file)
    product_key = None
    is_product_key = True
    # Flag to check the Product key requirement for the upgrade requested version of the package
    is_product_key_upgraded = True
    version = ""
    data = {}
    download_package_artifacts(
        manifest_file=manifest_file, recipe_id=package, src_dir=temp_dir
    )
    try:
        if os.path.exists(manifest_file):
            is_product_key = check_product_key(manifest_file=manifest_file)
            is_product_key_upgraded = check_product_key(recipe=package)

            # If the upgrade requested version has a product key but current version does not.
            if is_product_key is False and is_product_key_upgraded is True:
                print(
                    constants.YELLOW.format(
                        "This version of the package requires a product key. "
                        "Please visit Intel® Edge Software Hub and download the product key."
                    ),
                    end="\n",
                )

            if is_product_key_upgraded is True:
                print(
                    constants.BICYAN.format(
                        "Please enter the "
                        "Product Key. The Product Key is contained in the email you "
                        "received from Intel confirming your download: "
                    ),
                    end=" ",
                )
                product_key = input()
                if not product_key:
                    print(
                        constants.YELLOW.format(
                            "Please enter product key." " Exiting upgrade."
                        )
                    )
                    sys.exit(-1)
            details = utils.get_recipe_details(manifest_file)
            package_id = details.get("packageId")
            os_id = details.get("osId")
            label = details.get("label")
            version = details.get("version")
            package_name = "_".join([label, version])
            if constants.Operating_system == "Windows":
                installed_path = os.path.join("/log/esb-cli", package_name)
            elif constants.Operating_system == "Linux":
                installed_path = os.path.join("/var/log/esb-cli", package_name)
            install_json = os.path.join(installed_path, "install_status.json")
        else:
            print(constants.RED.format("Failed to find manifest file"))
            sys.exit(-1)

        data.update(
            {
                "recipeId": package,
                "packageId": package_id,
                "productKey": product_key,
                "osId": os_id,
                "order": "installation",
            }
        )
        resp = api.get_upgrade_package(data)
        if resp:
            s = ""
            with open(temp_conf_file, "w") as f:
                for item in resp.decode("ascii"):
                    s += item
                    if item == ">":
                        f.write(s)
                        f.write("\n")
                        s = ""
        else:
            print(
                constants.RED.format(
                    "Failed to fetch upgrade details." " Exiting Upgrade"
                )
            )
            sys.exit(-1)

        details = utils.get_recipe_details(temp_conf_file)
        new_version = details.get("version")

        if os.path.exists(install_json) and os.path.getsize(install_json):
            if LooseVersion(new_version) == LooseVersion(version):
                print(
                    constants.YELLOW.format(
                        "The selected package version is" " already installed"
                    )
                )
                sys.exit(-1)
            elif LooseVersion(new_version) < LooseVersion(version):
                print(constants.GREEN.format("You are on the latest version"))
                sys.exit(-1)
            else:
                print(constants.CYAN.format("Upgrading to {}".format(package)))
        else:
            print(
                constants.YELLOW.format(
                    "No package installed to run" " upgrade. Exiting upgrade"
                )
            )
            sys.exit(-1)
    except Exception as e:
        print(constants.RED.format("Upgrade failed. Exiting Upgrade.{}".format(e)))
        sys.exit(-1)

    try:
        output_dir_path = utils.create_output_dir(temp_conf_file)
        output_log_path = os.path.join(output_dir_path, output_log)
        tmp_details = utils.get_recipe_details(temp_conf_file)
        tmp_label = tmp_details.get("label")
        tmp_version = tmp_details.get("version")
        tmp_id = tmp_details.get("id")
        tmp_package_name = "_".join([tmp_label, tmp_version])

        global log
        log.clean()
        log = logger.Logger(output_log_path)

        print(
            constants.YELLOW.format(
                "WARNING: Upgrade in progress." " Do not interrupt".center(52, "*")
            )
        )

        utils.send_LR_data({"type": "upgrade", "recipe_id": tmp_id}, log)
        utils.send_telemetry_data(({"type": "upgrade", "recipe_id": tmp_id}), log)
        component_list = setup_start(product_key, temp_conf_file, upgrade=True)
        if component_list:
            utils.upgrade_cleanup(log, installed_path, temp_dir, package_name)
            verify_installation_status(component_list, upgrade=True)
            log.console("Finished upgrade", color_code=constants.GREEN)
        else:
            utils.upgrade_cleanup(
                log, output_dir_path, temp_dir, tmp_package_name, error=True
            )
            log.console("Failed to upgrade", error=True)

    except KeyboardInterrupt as e:
        log.console("Upgrade interrupted by user. Exiting Upgrade", error=True)
        utils.upgrade_cleanup(
            log, output_dir_path, temp_dir, tmp_package_name, error=True
        )
        sys.exit(-1)
    except Exception as e:
        log.console("Upgrade failed. Exiting Upgrade {}".format(e), error=True)
        utils.upgrade_cleanup(
            log, output_dir_path, temp_dir, tmp_package_name, error=True
        )
        sys.exit(-1)


def pull(image, tag, product_key=None, compose_log=None):
    """
    Pull Docker Image

    :param product_key: Product Key associated with the user
    :param image_name: Docker Image to download
    """
    global log
    if not compose_log:
        try:
            output_dir_path = utils.create_output_dir()
            if constants.Operating_system == "Linux":
                subprocess.run(["sudo", "chown", os.environ["USER"], output_dir_path])
            output_log_path = os.path.join(output_dir_path, docker_pull_log)
            if not log:
                log = logger.Logger(output_log_path)
        except Exception as e:
            print("Failed to create log file. {}".format(e))
            sys.exit(-1)
    else:
        log = compose_log

    if not utils.LR_data.get("type") and utils.is_LR_installed(log):
        utils.send_LR_data({"product_key": product_key, "type": "docker-pull"}, log)
    utils.send_telemetry_data(
        ({"product_key": product_key, "type": "docker-pull"}), log
    )

    startTime = time.time()
    log.console("Pulling Image {}:{}".format(image, tag))
    ret = utils.intel_registry_pull(image, tag, product_key, log)
    endTime = time.time()
    if ret == True:
        state = "SUCCESS"
        log.console(
            "Successfully installed {} "
            "took {}".format(
                image,
                utils.print_time(endTime - startTime),
            ),
            color_code=constants.GREEN,
        )
    else:
        state = "FAILED"
        log.console(
            "Failed to install {} took {}".format(
                image,
                utils.print_time(endTime - startTime),
            ),
            error=True,
        )


def pull_docker_compose(compose_file, product_key=None):
    """
    Get image names from docker compose file

    :param compose_file: Path to docker compose file to parse
    :param product_key: Product Key associated with the user
    """
    try:
        output_dir_path = utils.create_output_dir()
        output_log_path = os.path.join(output_dir_path, docker_pull_log)
        if constants.Operating_system == "Linux":
            subprocess.run(["sudo", "chown", os.environ["USER"], output_dir_path])
        global log
        if not log:
            log = logger.Logger(output_log_path)
    except Exception as e:
        print("Failed to create log file. {}".format(e))
        sys.exit(-1)

    """
    If the docker compose file available, it will parse the file,
    and read the value beside image tag.
    """
    if os.path.exists(compose_file):
        path = os.path.abspath(os.getcwd()) + "/" + compose_file
        getImages = []
        try:
            with open(path, "r") as f:
                docker_compose = yaml.safe_load(f)
            for item in docker_compose.items():
                if item[0] == "services":
                    services = item[1]
                    for i in services:
                        if "image" in services[i]:
                            image = services[i]["image"].split(":")
                            if len(image) == 1:
                                name = image[0]
                                tag = "latest"
                            else:
                                name, tag = image
                            getImages.append([name, tag])

        except yaml.YAMLError as exc:
            msg = "Failed to parse file {}: {}"
            print_msg = "Failed to parse file {}"
            log.console(
                msg.format(compose_file, exc),
                print_msg.format(compose_file),
                error=True,
            )

        except Exception as e:
            log.console(
                "Failed to read images from {}: {}".format(compose_file, e), error=True
            )

        # Pull each image availabe in docker compose file
        for image in getImages:
            name = image[0]
            tag = image[1]
            pull(name, tag, product_key, log)
    else:
        log.console("{} not available".format(compose_file), error=True)
    return


def check_product_key(
    manifest_file=None,
    image=None,
    tag=None,
    recipe=None,
    helm_chart_name=None,
    helm_chart_tag=None,
):
    """
    Get if Product key is needed by the Package or Image

    :param manifest_file: XML file to read components
    :param image : Image Name of the Image
    :param tag : Tag of the Image
    :param recipe : Recipe GUID
    :param helm_chart_name : Name of the Helm Chart
    :param helm_chart_tag : Tag of the Helm chart
    """
    recipe_id = None
    try:
        if manifest_file:
            output_dir_path = utils.create_output_dir(manifest_file)
            output_log_path = os.path.join(output_dir_path, output_log)

        elif helm_chart_name:
            output_dir_path = utils.create_output_dir()
            output_log_path = os.path.join(output_dir_path, helm_download_log)
        else:
            output_dir_path = utils.create_output_dir()
            output_log_path = os.path.join(output_dir_path, docker_pull_log)
        if constants.Operating_system == "Linux":
            subprocess.run(["sudo", "chown", os.environ["USER"], output_dir_path])
        global log
        if not log:
            log = logger.Logger(output_log_path)

    except Exception as e:
        print("Failed to create log file. {}".format(e))
        sys.exit(-1)
    if manifest_file and recipe is None:
        recipe_id = utils.get_recipe_details(manifest_file)["id"]
    if recipe:
        recipe_id = recipe
    return api.check_product_key(
        log,
        recipe_id=recipe_id,
        image=image,
        tag=tag,
        helm_chart_name=helm_chart_name,
        helm_chart_tag=helm_chart_tag,
    )


def get_config_xml(configuration_id):
    """
    Gets configuration xml file from service layer via api.get_config_xml()

    :param configuration_id: Unique ID for package which user gets from ESH-UI
    """

    xml_overwritten = False
    resp = api.get_config_xml(configuration_id)
    fetched_xml_file = "edgesoftware_configuration.xml"
    if resp and os.path.exists(fetched_xml_file):
        xml_overwritten = True
    # This part formats downloaded XML file line by line
    if resp:
        line = ""
        with open(fetched_xml_file, "w") as f:
            for char in resp.decode("ascii"):
                line += char
                if char == ">":
                    f.write(line)
                    f.write("\n")
                    line = ""
    else:
        print(
            constants.RED.format(
                "Failed to fetch Manifest XML file "
                "edgesoftware_configuration.xml. Exiting."
            )
        )
        sys.exit(-1)
    try:
        output_dir_path = utils.create_output_dir(fetched_xml_file)
        output_log_path = os.path.join(output_dir_path, output_log)
        if constants.Operating_system == "Linux":
            subprocess.run(["sudo", "chown", os.environ["USER"], output_dir_path])
        global log
        if not log:
            log = logger.Logger(output_log_path)

    except Exception as e:
        log.error("Failed to create log file. {}".format(e))
        sys.exit(-1)

    utils.send_LR_data({"configuration_id": configuration_id}, log)
    utils.send_telemetry_data(({"configuration_id": configuration_id}), log)
    log.info(
        "User config found. Manifest XML file "
        "edgesoftware_configuration.xml fetched succesfully."
    )
    return fetched_xml_file, xml_overwritten


def download_helm_chart(name, tag, helm_chart_id, helm_chart_type, product_key=None):
    """
    Download Helm Chart

    Args:
        name (string): Helm chart Name.
        tag (string): Helm chart Tag.
        helm_chart_id (string): Helm id.
        helm_chart_type (string): Helm Chart Registry Type
        product_key (string, optional): Product key for the chart. Defaults to None.
    """
    global log
    try:
        output_dir_path = utils.create_output_dir()
        if constants.Operating_system == "Linux":
            subprocess.run(["sudo", "chown", os.environ["USER"], output_dir_path])
        output_log_path = os.path.join(output_dir_path, helm_download_log)
        if not log:
            log = logger.Logger(output_log_path)
    except Exception as e:
        print("Failed to create log file. {}".format(e))
        sys.exit(-1)

    if not utils.LR_data.get("type"):
        utils.send_LR_data({"type": "helm-pull", "product_key": product_key}, log)
    utils.send_telemetry_data(({"type": "helm-pull", "product_key": product_key}), log)
    api.fetch_helm(
        log, product_key, name, tag, helm_chart_id, None, helm_chart_type, unzip=True
    )
    success_helm_chart_names, success_helm_ids = api.get_helm_pull_status()
    if utils.is_LR_installed(log) and utils.LR_data.get("type") == "helm-pull":
        utils.send_LR_data({"helm_chart": success_helm_chart_names}, log)
    utils.send_telemetry_data(({"successHelmIds": success_helm_ids}), log)


def get_helm_charts(manifest):
    """
    Gets helm charts list from manifest file.

    Args:
        manifest (String): Location of XML file

    Returns:
        [list]: List of helm charts
    """
    # send a ordered array of all helm charts
    helm_list = []
    component_list = get_component_list(manifest, None, None, None, None)
    if "esb_modules" in component_list:
        for comp_id, val in component_list.get("esb_modules").items():
            if utils.is_helm(val):
                helm_list.append(
                    {
                        "label": val["label"],
                        "comp_id": comp_id,
                        "tag": val.get("tag"),
                        "path": val["path"],
                    }
                )

    return helm_list


def update_helm_keys(helm_list, product_key, is_manifest):
    """
    Updates Helm chart keys. Invoked from edgesoftware helm -u  install command

    Args:
        helm_list (list): list of helm charts
        product_key (string): Product Key Value
        is_manifest (bool, optional): Manifest File. Defaults to False.

    Returns:
        Bool/None: True/False/None
    """
    global log
    try:
        if not log:
            if not is_manifest:
                output_dir_path = utils.create_output_dir()
                if constants.Operating_system == "Linux":
                    subprocess.run(
                        ["sudo", "chown", os.environ["USER"], output_dir_path]
                    )
                output_log_path = os.path.join(output_dir_path, helm_download_log)
                log = logger.Logger(output_log_path)
            else:
                output_dir_path = utils.create_output_dir(manifest_file)
                output_log_path = os.path.join(output_dir_path, output_log)
                log = logger.Logger(output_log_path)
    except Exception as e:
        print("Failed to create log file. {}".format(e))
        sys.exit(-1)

    for helm_chart in helm_list:

        if is_manifest:
            helm_chart_path = os.path.join(
                helm_chart["path"], helm_chart["label"] + "-" + helm_chart["tag"]
            )
            if not os.path.isdir(helm_chart_path):
                log.console(
                    "Failed to update Helm chart secret keys {}-{}.\nHelm chart directory not found at {}.".format(
                        helm_chart["label"], helm_chart["tag"], helm_chart_path
                    ),
                    color_code=constants.RED,
                )
                if isinstance(is_manifest, bool):
                    return False
                continue

        log.console(
            "Updating secret keys for Helm chart {}-{}".format(
                helm_chart["label"], helm_chart["tag"]
            ),
            color_code=constants.CYAN,
        )
        startTime = time.time()
        ret = None
        # Since it is called form XML, we don't know the credentials requirement

        if is_manifest:
            # Gets the status for all the helm charts in the XML.
            _, is_helm_credentials = api.get_helm_registry_credentials(
                helm_chart["label"], helm_chart["tag"], log
            )

            if is_helm_credentials:
                ret = utils.update_k8s_secret_store(
                    helm_chart["label"],
                    helm_chart["tag"],
                    helm_chart["comp_id"],
                    product_key,
                    log,
                )

            elif is_helm_credentials is None:
                ret = False

        else:
            ret = utils.update_k8s_secret_store(
                helm_chart["label"],
                helm_chart["tag"],
                helm_chart["comp_id"],
                product_key,
                log,
            )

        endTime = time.time()

        if ret is None:
            log.info(
                "Helm chart {}-{} does not need secret keys.".format(
                    helm_chart["label"], helm_chart["tag"]
                )
            )
        elif ret:
            log.console(
                "Successfully updated secret keys for Helm chart {}-{} took {}".format(
                    helm_chart["label"],
                    helm_chart["tag"],
                    utils.print_time(endTime - startTime),
                ),
                color_code=constants.GREEN,
            )

        else:
            log.console(
                "Failed to update secret keys for Helm chart {}-{} took {}".format(
                    helm_chart["label"],
                    helm_chart["tag"],
                    utils.print_time(endTime - startTime),
                ),
                error=True,
            )
        if len(helm_list) == 1:
            return ret


def download_package_artifacts(
    manifest_file, recipe_id=None, src_dir=None, remove_previous=False, export=False
):
    """
    Downloads Package Artifacts

    Args:
        manifest_file (string): Manifest File Location
        recipe_id (string, optional): Package GUID. Defaults to None.
        src_dir (string, optional): Temporary Directory. Defaults to None.
        remove_previous (BOOL, optional): Remove Previous Files. Defaults to False.
        export (BOOL, optional): If called from export. Defaults to False.
    """
    try:
        if manifest_file:
            output_dir_path = utils.create_output_dir(manifest_file)
            output_log_path = os.path.join(output_dir_path, output_log)
        if constants.Operating_system == "Linux":
            subprocess.run(["sudo", "chown", os.environ["USER"], output_dir_path])
        global log
        if not log:
            log = logger.Logger(output_log_path)

    except Exception as e:
        print("Failed to create log file. {}".format(e))
        sys.exit(-1)
    if manifest_file and recipe_id is None and src_dir is None:
        recipe_id = utils.get_recipe_details(manifest_file)["id"]

    file_list = api.download_package_artifacts(
        log, recipe_id, src_dir, remove_previous, export
    )
    if export:
        return file_list

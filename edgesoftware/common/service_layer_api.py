from requests.auth import HTTPBasicAuth
from edgesoftware.common import utils
from edgesoftware.common import constants
from configparser import ConfigParser
from multiprocessing.pool import ThreadPool
import json
import shutil
import gzip
import hashlib
import requests
import os
import sys
import docker
import tarfile

import urllib3
import base64
from tqdm import tqdm

urllib3.disable_warnings()


# FIXME(mkumari): Remove the hardcoded URL

# BASE_URL = "http://servicelayeresb.apps1-bg-int.icloud.intel.com/"
BASE_URL = "https://edgesoftwarehub.intel.com/"

success_ids = []
failed_ids = []
success_helm_ids = []
failed_helm_ids = []
success_helm_chart_names = []


def get_service_layer_url():
    parser = ConfigParser()
    url = None
    if os.path.exists("config.ini"):
        parser.read("config.ini")
        url = parser.get("default", "service_layer_url")
    url = url if url else BASE_URL
    return url


def get_modules_list(recipe_id, os_id, country_code, log):
    base_url = get_service_layer_url()
    url = "".join(
        [
            base_url,
            "recipe/supportedModules/{}?order=display&osId={}&countryCode={}".format(
                recipe_id, os_id, country_code
            ),
        ]
    )
    resp = None
    try:
        modules_list = requests.get(url)
        if modules_list.status_code == constants.HTTP_STATUS.get("OK"):
            resp = modules_list.json()
        else:
            log.error("Failed to retrieve the supported modules from URL.")
    except requests.ConnectionError as e:
        log.console(
            "Failed to connect. Please check the Internet connection"
            " and proxy settings and retry. {}".format(e),
            error=True,
        )
    return resp


def get_components_list(recipe_id, os_id, log):
    base_url = get_service_layer_url()
    url = "".join(
        [base_url, "recipe/{}?order=display&osId={}".format(recipe_id, os_id)]
    )
    resp = None
    try:
        components_list = requests.get(url)
        if components_list.status_code == constants.HTTP_STATUS.get("OK"):
            resp = components_list.json()
        else:
            msg = "Failed to get the list of modules. {} {}".format(
                components_list.status_code, components_list.reason
            )
            log.console(msg, error=True)
    except requests.ConnectionError as e:
        log.console(
            "Failed to connect. Please check the Internet connection"
            " and proxy settings and retry. {}".format(e),
            error=True,
        )
    return resp


def get_supported_recipes(recipe_name, log):
    base_url = get_service_layer_url()
    url = "".join([base_url, "recipe/getAllVersionByName", recipe_name])
    resp = None
    try:
        recipes_list = requests.get(url)
        if recipes_list.status_code == constants.HTTP_STATUS.get("OK"):
            resp = recipes_list.json()
        else:
            msg = "Failed to get the list of packages. {} {}".format(
                recipes_list.status_code, recipes_list.reason
            )
            log.console(msg, error=True)
    except requests.ConnectionError as e:
        log.console(
            "Failed to connect. Please check the Internet connection"
            " and proxy settings and retry. {}".format(e),
            error=True,
        )
    return resp


def get_update_components(components_id_list, recipe_id, product_key, log):
    base_url = get_service_layer_url()
    data = {
        "components": components_id_list,
        "recipeId": recipe_id,
        "productKey": product_key,
    }
    url = "".join([base_url, "ingredient/update_ingredient/"])
    try:
        components_list = requests.post(url, json=data)
        if components_list.status_code == constants.HTTP_STATUS.get("OK"):
            return components_list.content
        else:
            msg = "Failed to get the list of modules. {}.".format(
                components_list.json()["message"]
            )
            err_msg = "Failed to get the list of modules. {} {} {}.".format(
                components_list.status_code,
                components_list.reason,
                components_list.json()["message"],
            )
            log.console(msg, error=True)
            log.error(err_msg)
    except requests.ConnectionError as e:
        log.console(
            "Failed to connect. Please check the Internet connection"
            " and proxy settings and retry. {}".format(e),
            error=True,
        )
    return None


def get_upgrade_package(data):
    base_url = get_service_layer_url()
    url = "".join([base_url, "recipe/upgrade/"])
    try:
        package_details = requests.post(url, json=data)
        if package_details.status_code == constants.HTTP_STATUS.get("OK"):
            return package_details.content
        else:
            print(
                constants.RED.format(
                    "Failed to get the upgrade details. {} {}".format(
                        package_details.status_code, package_details.reason
                    )
                )
            )
    except requests.ConnectionError as e:
        print(
            "Failed to connect. Please check the Internet connection"
            " and proxy settings and retry. {}".format(e)
        )


def get_upgrade_list(package_type, os_id, log):
    base_url = get_service_layer_url()
    url = "".join(
        [base_url, "recipe/getAllByIrcId/{}?osId={}".format(package_type, os_id)]
    )
    resp = None
    try:
        components_list = requests.get(url)
        if components_list.status_code == constants.HTTP_STATUS.get("OK"):
            resp = components_list.json()
        else:
            msg = "Failed to get the list of packages. {} {}".format(
                components_list.status_code, components_list.reason
            )
            log.console(msg, error=True)
    except requests.ConnectionError as e:
        log.console(
            "Failed to connect. Please check the Internet connection"
            " and proxy settings and retry. {}".format(e),
            error=True,
        )
    return resp


def validate_product_key(log, product_key, recipe_id):
    """
    Validate product key for package
    :param product_key: Customer obtained product key
    :param recipe_id: ID of the Package
    """
    try:
        log.console("Validating package product key", color_code=constants.CYAN)
        base_url = get_service_layer_url()
        data = {"recipeId": recipe_id, "productKey": product_key}
        url = "".join([base_url, "recipe/validateProductKey"])
        resp = requests.post(url, json=data)
        if resp.status_code == constants.HTTP_STATUS.get("UNAUTHORIZED"):
            return False
        elif resp.status_code == constants.HTTP_STATUS.get("OK"):
            return True
        else:
            log.console(
                "Failed to validate Product Key. {} {}".format(
                    resp.status_code, resp.reason
                ),
                error=True,
            )
            return False
    except requests.ConnectionError as e:
        log.console(
            "Failed to connect. Please check the Internet connection"
            " and proxy settings and retry. {}".format(e),
            error=True,
        )
        sys.exit(-1)


def get_download_status():
    return success_ids, failed_ids, success_helm_ids, failed_helm_ids


def fetch_helm(
    log, prod_key, name, tag, helm_chart_id, src_dir, registry_type=None, unzip=False
):
    """
    Fetch Helm charts from Service Layer

    Args:
        log (obj): Logger Object
        prod_key (string): Product Key Value
        name (string): Name of the Helm chart
        tag (string):  Helm chart Tag
        helm_chart_id (string):  Helm chart id.
        unzip (bool, optional): If the Helm chart is to be Extracted. Defaults to False.
    """
    base_url = get_service_layer_url()
    valid = True
    global success_helm_ids
    global failed_helm_ids
    global success_helm_chart_names
    if registry_type is None:
        registry_type, _ = get_helm_registry_credentials(name, tag, log)

    data = {"id": helm_chart_id, "productKey": prod_key}
    url = "".join([base_url, "helmChart/download"])
    helm_chart_name = name + "-" + tag
    if src_dir:
        tar_path = os.path.join(src_dir, helm_chart_id + ".tgz")
    else:
        tar_path = os.path.join(helm_chart_id + ".tgz")
    download = False
    num_tries = 0
    utils.component_valid[helm_chart_name] = None
    if os.path.exists(tar_path):
        if registry_type == "intelprivate":
            log.console(
                "Helm chart package {} already exists. "
                "Validating it...".format(helm_chart_name),
                color_code=constants.CYAN,
            )
            ret = hashlib.md5(open(tar_path, "rb").read()).hexdigest()
            valid = validate_helm_chart(helm_chart_id, ret, log)
        else:
            log.console(
                "Helm chart package {} already exists. ".format(helm_chart_name),
                color_code=constants.CYAN,
            )

        utils.component_valid[helm_chart_name] = valid
        if not valid:
            log.console(
                "Validation failed, re-downloading Helm chart package {}".format(
                    helm_chart_name
                ),
                error=True,
            )
            download = True
        else:
            log.console("Skipping download...", color_code=constants.CYAN)
    else:
        download = True
    if download:
        while num_tries < 3:
            try:
                if unzip:
                    log.console(
                        "Downloading Helm chart package {}-{} ".format(name, tag)
                    )

                log.info(
                    "Sending request to download Helm chart package {}-{} id : {} ".format(
                        name, tag, helm_chart_id
                    )
                )
                resp = requests.post(url, json=data, stream=True)
                if resp.status_code == constants.HTTP_STATUS.get("OK"):
                    size_bytes = int(resp.headers.get("content-length", 0))
                    block_size = 1024
                    p_bar = tqdm(total=size_bytes, unit="iB", unit_scale=True)
                    with open(tar_path, "wb") as fd:
                        for stream_data in resp.iter_content(block_size):
                            p_bar.update(len(stream_data))
                            fd.write(stream_data)
                    p_bar.close()
                    if registry_type == "intelprivate":
                        ret = hashlib.md5(open(tar_path, "rb").read()).hexdigest()
                        valid = validate_helm_chart(helm_chart_id, ret, log)
                    utils.component_valid[helm_chart_name] = valid
                    if not valid:
                        log.console(
                            "Validation failed, deleting Helm chart package {}".format(
                                helm_chart_name
                            ),
                            error=True,
                        )
                        os.remove(tar_path)
                    else:
                        success_helm_ids.append(helm_chart_id)
                        log.console(
                            "Successfully downloaded Helm Chart package {}".format(
                                helm_chart_name
                            ),
                            color_code=constants.GREEN,
                        )
                        break
                elif resp.status_code < constants.HTTP_STATUS.get("SERVER_ERR"):
                    failed_helm_ids.append(helm_chart_id)
                    log.console(
                        "Failed to download the Helm chart package {}. {} {}".format(
                            helm_chart_name, resp.status_code, resp.reason
                        ),
                        error=True,
                    )
                    break
                else:
                    failed_helm_ids.append(helm_chart_id)
                    log.console(
                        "Failed to download the Helm chart package {}. {} {}".format(
                            helm_chart_name, resp.status_code, resp.reason
                        ),
                        error=True,
                    )
            except requests.ConnectionError as e:
                log.console(
                    "Failed to connect. Please check the Internet "
                    "connection and proxy settings and retry. {}".format(e),
                    error=True,
                )
            if num_tries == 2:
                log.console(
                    "Failed to connect. Please check the Internet "
                    "connection and proxy settings. Exiting download.",
                    error=True,
                )
            else:
                log.console("Retrying Helm chart download", color_code=constants.YELLOW)
            num_tries += 1

    if unzip:
        file_path = tar_path.replace("{}.tgz".format(helm_chart_id), helm_chart_name)
        if not len(utils.component_valid) or (
            utils.component_valid[helm_chart_name] is None
            or not os.path.exists(file_path)
        ):
            try:
                if os.path.exists(tar_path):
                    with tarfile.open(tar_path, "r:gz") as tar:
                        # Extract all the contents of tar file
                        log.console(
                            "Unzipping Helm chart {}...".format(helm_chart_name)
                        )
                        tar.extractall(helm_chart_name)
                        success_helm_chart_names = [helm_chart_name]
                        success_helm_ids = [helm_chart_id]

            except Exception as e:
                log.console("Failed to unzip Helm chart. {}".format(e))


def get_helm_pull_status():
    return success_helm_chart_names, success_helm_ids


def fetch_ingredient(
    prod_key, ingredient_name, recipe_id, os_id, ingredient_id, src_dir, log
):
    base_url = get_service_layer_url()
    data = {
        "component": ingredient_id,
        "recipeId": recipe_id,
        "osId": os_id,
        "productKey": prod_key,
    }
    url = "".join([base_url, "ingredient/download"])
    zip_path = os.path.join(src_dir, ingredient_id + ".zip")
    download = False
    num_tries = 0
    utils.component_valid[ingredient_name] = None
    if os.path.exists(zip_path):
        log.console(
            "ZIP file for module {} already exists. "
            "Validating it...".format(ingredient_id),
            color_code=constants.CYAN,
        )
        ret = hashlib.md5(open(zip_path, "rb").read()).hexdigest()
        valid = validate_ingredient(ingredient_id, ret, log)
        utils.component_valid[ingredient_name] = valid
        if not valid:
            log.console(
                "Validation failed, re-downloading module {}".format(ingredient_id),
                error=True,
            )
            download = True
        else:
            log.console("Skipping download...", color_code=constants.CYAN)
    else:
        download = True
    if download:
        while num_tries < 3:
            try:
                log.info("Sending request to download module {}".format(ingredient_id))
                resp = requests.post(url, json=data, stream=True)
                if resp.status_code == constants.HTTP_STATUS.get("OK"):
                    size_bytes = int(resp.headers.get("content-length", 0))
                    block_size = 1024
                    p_bar = tqdm(total=size_bytes, unit="iB", unit_scale=True)
                    with open(zip_path, "wb") as fd:
                        for stream_data in resp.iter_content(block_size):
                            p_bar.update(len(stream_data))
                            fd.write(stream_data)
                    p_bar.close()
                    ret = hashlib.md5(open(zip_path, "rb").read()).hexdigest()
                    valid = validate_ingredient(ingredient_id, ret, log)
                    if not valid:
                        log.console(
                            "Validation failed, deleting module {}".format(
                                ingredient_id
                            ),
                            error=True,
                        )
                        os.remove(zip_path)
                    else:
                        success_ids.append(ingredient_id)
                        log.console(
                            "Successfully downloaded module {}".format(ingredient_name),
                            color_code=constants.GREEN,
                        )
                        break
                elif resp.status_code < 500:
                    failed_ids.append(ingredient_id)
                    log.console(
                        "Failed to download the module {}. {} {}".format(
                            ingredient_name, resp.status_code, resp.reason
                        ),
                        error=True,
                    )
                    break
                else:
                    failed_ids.append(ingredient_id)
                    log.console(
                        "Failed to download the module {}. {} {}".format(
                            ingredient_name, resp.status_code, resp.reason
                        ),
                        error=True,
                    )
            except requests.ConnectionError as e:
                log.console(
                    "Failed to connect. Please check the Internet "
                    "connection and proxy settings and retry. {}".format(e),
                    error=True,
                )
            if num_tries == 2:
                failed_ids.append(ingredient_id)
                log.console(
                    "Failed to connect. Please check the Internet "
                    "connection and proxy settings. Exiting download.",
                    error=True,
                )
            else:
                log.console("Retrying module download", color_code=constants.YELLOW)
            num_tries += 1


def validate_ingredient(ingredient_id, ingredient_hash, log):
    base_url = get_service_layer_url()
    data = {"id": ingredient_id, "value": ingredient_hash}
    url = "".join([base_url, "ingredient/validate"])
    try:
        log.info(
            "Sending request to validate module {} with hash value {}".format(
                ingredient_id, ingredient_hash
            )
        )
        resp = requests.post(url, json=data)
        if resp.status_code == constants.HTTP_STATUS.get("OK"):
            log.console(
                "Module validation passed for {}".format(ingredient_id),
                color_code=constants.GREEN,
            )
            return True
        else:
            msg = "Module validation failed for {}. {} {}".format(
                ingredient_id, resp.status_code, resp.reason
            )
            log.console(msg, error=True)
    except requests.ConnectionError as e:
        log.console(
            "Failed to connect. Please check the Internet connection"
            " and proxy settings and retry. {}".format(e),
            error=True,
        )
        raise e


def validate_helm_chart(helm_chart_id, helm_chart_hash, log):
    """
    Validate helm Chart MD5 Hash

    Args:
        helm_chart_id (String): Helm Chart ID
        helm_chart_hash (String): Helm Chart MD5 Hash
        log (obj): Logger Object

    Returns:
        Bool: Status
    """
    base_url = get_service_layer_url()
    data = {"id": helm_chart_id, "value": helm_chart_hash}
    url = "".join([base_url, "helmChart/validate"])
    try:
        log.info(
            "Sending request to validate Helm chart {} with hash value {}".format(
                helm_chart_id, helm_chart_hash
            )
        )
        resp = requests.post(url, json=data)
        if resp.status_code == constants.HTTP_STATUS.get("OK"):
            log.console(
                "Helm chart validation passed for {}".format(helm_chart_id),
                color_code=constants.GREEN,
            )
            return True
        else:
            msg = "Helm chart validation failed for {}. {} {}".format(
                helm_chart_id, resp.status_code, resp.reason
            )
            log.console(msg, error=True)
            return False
    except requests.ConnectionError as e:
        log.console(
            "Failed to connect. Please check the Internet connection"
            " and proxy settings and retry. {}".format(e),
            error=True,
        )
        return False


def update_ingredient_count(success_ids, failed_ids, log):
    base_url = get_service_layer_url()
    data = {
        "successfullInstallationIds": success_ids,
        "failedInstallationIds": failed_ids,
    }
    url = "".join([base_url, "ingredient/update_installation_count"])
    try:
        log.info("Sending installation status {}".format(data))
        resp = requests.post(url, json=data)
        if resp.status_code == constants.HTTP_STATUS.get("OK"):
            log.info("Installation status was successfully sent.")
        else:
            log.error(
                "Failed to update installation status. {} {}".format(
                    resp.status_code, resp.reason
                )
            )
    except requests.ConnectionError as e:
        log.console(
            "Failed to connect. Please check the Internet connection"
            " and proxy settings and retry. {}".format(e),
            error=True,
        )


def send_telemetry_data(telemetry_data, log):
    base_url = get_service_layer_url()
    data = telemetry_data
    url = "".join([base_url, "analytics"])
    try:
        log.info("Sending installation report")
        resp = requests.post(url, json=data)
        if resp.status_code == constants.HTTP_STATUS.get("OK"):
            log.info("Installation report was successfully sent.")
        else:
            log.error(
                "Failed to send installation report. {} {}".format(
                    resp.status_code, resp.reason
                )
            )
    except requests.ConnectionError as e:
        log.error(
            "Failed to connect. Please check the Internet connection"
            " and proxy settings and retry. {}".format(e)
        )


def validate_docker_image_productkey(imageId, product_key, log):
    """
    Validate product key
    :param imageId: UUID of the Image
    :param product_key: product_key of the user
    """
    try:
        base_url = get_service_layer_url()
        data = {"imageId": imageId, "productKey": product_key}
        url = "".join([base_url, "docker/validate/productkey"])
        resp = requests.post(url, json=data)
        if resp.status_code == constants.HTTP_STATUS.get("OK"):
            return True, resp.json()["token"]
        else:
            log.console(
                "Failed to validate Product Key. {} {}".format(
                    resp.status_code, resp.reason
                ),
                error=True,
            )
            return False
    except requests.ConnectionError as e:
        log.console(
            "Failed to connect. Please check the Internet connection"
            " and proxy settings and retry. {}".format(e),
            error=True,
        )
        sys.exit(-1)


def validate_docker_image(image, tag, product_key, log):
    """
    Validate docker image and its availability in Intel Reg.
    :param image: Docker image name
    :param tag: Docker image tag
    :param product_key: product_key of the user
    """
    try:
        base_url = get_service_layer_url()
        log.console("Checking Intel registry for {}:{}".format(image, tag))
        url = "".join([base_url, "docker/image?name={}&tag={}".format(image, tag)])
        resp = requests.get(url)
        if resp.status_code == constants.HTTP_STATUS.get("OK"):
            if str(resp.text):
                return resp.json()[0]
            else:
                return False
        else:
            return False
    except requests.ConnectionError as e:
        log.console(
            "Failed to connect. Please check the Internet connection"
            " and proxy settings and retry. {}".format(e),
            error=True,
        )
        sys.exit(-1)


def fetch_base_image(base_img, base_img_digest, log):
    """
    Fetch Base Image Layer
    :param registry: Registry to pull the docker image
    :param auth_url: Registry Authentication URL
    :param registry_service: Registry service of docker registry
    :param repository: Repo to download the image
    :param digest: image identified with the digest
    """
    try:
        log.console(
            "Pulling Base Image from {}@{}".format(base_img, base_img_digest),
            color_code=constants.GREEN,
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
                for line in client.api.pull(
                    base_img, tag=base_img_digest, stream=True, decode=True
                ):
                    if "status" in line:
                        if line["status"] == "Downloading":
                            utils.docker_progress_bar(
                                line, download_bar, download_progress
                            )
                        elif line["status"] == "Extracting":
                            utils.docker_progress_bar(
                                line, extract_bar, extract_progress
                            )

                if download_progress:
                    utils.docker_final_update(download_bar,download_progress)
                if extract_progress:
                    utils.docker_final_update(extract_bar,extract_progress)

        log.console(
            "Status: Base Image saved for {}@{}".format(base_img, base_img_digest)
        )
        return utils.image_load_status(base_img, base_img_digest, log)
    except Exception as e:
        log.console(
            "Failed to download base layer. {}".format(e),
            error=True,
        )
        return False


def get_robot_account(imageId, product_key, log):
    try:
        base_url = get_service_layer_url()
        data = {"imageId": imageId, "productKey": product_key}
        url = "".join([base_url, "docker/robot"])
        resp = requests.post(url, json=data)
        if resp.status_code == constants.HTTP_STATUS.get("OK"):
            return True, resp.json()
        else:
            log.console(
                "Failed to validate Product Key. {} {}".format(
                    resp.status_code, resp.reason
                ),
                error=True,
            )
            return False, ""
    except requests.ConnectionError as e:
        log.console(
            "Failed to connect. Please check the Internet connection"
            " and proxy settings and retry. {}".format(e),
            error=True,
        )


def get_helm_robot_account(helmId, product_key, log):
    """
    Get helm robot account

    Args:
        helmId (String): Id of Helm Chart
        product_key (String): Product Key Value
        log (obj): Logger Object

    Returns:
        [type]: Robot Account Details
    """
    try:
        base_url = get_service_layer_url()
        data = {"id": helmId, "productKey": product_key}
        url = "".join([base_url, "helmChart/getRobotAccount"])
        resp = requests.post(url, json=data)
        if resp.status_code == constants.HTTP_STATUS.get("OK"):
            return True, resp.json()
        else:
            log.console(
                "Failed to validate Product Key. {} {}".format(
                    resp.status_code, resp.reason
                ),
                error=True,
            )
            return False, ""
    except requests.ConnectionError as e:
        log.console(
            "Failed to connect. Please check the Internet connection"
            " and proxy settings and retry. {}".format(e),
            error=True,
        )


def fetch_image(imageId, image, tag, product_key, log):
    """
    Fetch Docker Image from Intel registry
    :param registry: Registry to pull the docker image
    :param registry_service: Registry service of docker registry
    :param repository: Repo to download the image
    :param imageId: Docker Image ID
    :param image: Docker image name
    :param tag: Docker image tag
    :param product_key: Product Key required to pull image
    :param directory: Directory to pull the layers
    """

    validation_status, data = get_robot_account(imageId, product_key, log)

    if validation_status:
        try:
            log.console(
                "Pulling from Intel Registry {}:{}".format(image, tag),
                color_code=constants.GREEN,
            )
            client = docker.from_env()

            image_name = data["registry"] + "/" + data["repository"] + "/" + image
            auth_config = {}
            # Decode the token into username and password
            auth_config["username"], auth_config["password"] = (
                base64.b64decode(data["token"]).decode("utf-8").split(":", 1)
            )

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
                    for line in client.api.pull(
                        image_name,
                        tag=tag,
                        stream=True,
                        auth_config=auth_config,
                        decode=True,
                    ):
                        if "status" in line:
                            if line["status"] == "Downloading":
                                utils.docker_progress_bar(
                                    line, download_bar, download_progress
                                )
                            elif line["status"] == "Extracting":
                                utils.docker_progress_bar(
                                    line, extract_bar, extract_progress
                                )
                    if download_progress:
                        utils.docker_final_update(download_bar,download_progress)
                    if extract_progress:
                        utils.docker_final_update(extract_bar,extract_progress)

            log.console("Status: Image saved for {}:{}".format(image, tag))

            full_image_name = image_name + ":" + tag
            new_image_name = image + ":" + tag
            client.api.tag(full_image_name, new_image_name, tag=tag, force=True)
            client.api.remove_image(full_image_name)
            return utils.image_load_status(image, tag, log)
        except Exception as e:
            msg = "Failed to download docker image. {}"
            print_msg = "Failed to download docker image"
            log.console(msg.format(e), print_msg, error=True)
    else:
        return False


def check_product_key(
    log, recipe_id=None, image=None, tag=None, helm_chart_name=None, helm_chart_tag=None
):
    """
    Checks if product key is needed for the Package

    Args:
        log (obj):  log object
        recipe_id (string, optional): Recipe ID of the Package. Defaults to None.
        image (string, optional): Image Name of the Image. Defaults to None.
        tag (string, optional): Tag of the Image. Defaults to None.
        helm_chart (string, optional): Helm chart name. Defaults to None.

    Returns:
        Bool: True / False
        Multiple Return : Helm chart details
    """
    base_url = get_service_layer_url()
    resp = True
    helm_chart_id = None
    helm_chart_type = None
    is_helm_credentials = False

    if image is None and helm_chart_name is None:
        url = "".join([base_url, "recipe/{}".format(recipe_id)])

    elif helm_chart_name is not None:
        url = "".join(
            [
                base_url,
                "helmChart/chart?name={}&tag={}".format(
                    helm_chart_name, helm_chart_tag
                ),
            ]
        )

    else:
        url = "".join([base_url, "docker/image?name={}&tag={}".format(image, tag)])
    try:
        status = requests.get(url)
        if status.status_code == constants.HTTP_STATUS.get("OK"):
            if recipe_id:
                resp = status.json()["productKey"]
            elif helm_chart_name:
                resp = status.json()["productKey"]
                helm_chart_id = status.json()["id"]
                helm_chart_type = status.json()["registryType"]
                is_helm_credentials = status.json()["updateCredentials"]
            else:
                resp = status.json()[0]["productKey"]
        else:
            log.console(
                "Failed to check Product Key requirement. {} {}".format(
                    status.status_code, status.reason
                ),
                error=True,
            )
            if helm_chart_name:
                return None, helm_chart_id, helm_chart_type, is_helm_credentials
            sys.exit(-1)
    except requests.ConnectionError as e:
        log.console(
            "Failed to connect. Please check the Internet "
            "connection and proxy settings and retry. {}".format(e),
            error=True,
        )
        sys.exit(-1)

    except ValueError as e:
        # For Public Images, SL will not have Value for product key
        if image is not None:
            resp = False
            log.info(
                "Public Image - {}:{}. Product Key Status not found. {}".format(
                    image, tag, e
                )
            )

        elif helm_chart_name is not None:
            log.console(
                "Server Response Incomplete. {}".format(e),
                error=True,
            )
            return None, helm_chart_id, helm_chart_type, is_helm_credentials

        else:
            log.error("Exception : Product Key Status not found. {}".format(e))

    except (KeyError, IndexError) as e:
        if helm_chart_name is not None:
            log.console(
                "Server Response Incomplete. {}".format(e),
                error=True,
            )
            return None, helm_chart_id, helm_chart_type, is_helm_credentials

        log.error("Exception : Product Key Status not found. {}".format(e))

    log.info("Product key requirement status is {}".format(resp))

    if helm_chart_name:
        log.info(
            "Helm chart id for {} chart {}-{} is {}".format(
                helm_chart_type, helm_chart_name, helm_chart_tag, helm_chart_id
            )
        )
        return resp, helm_chart_id, helm_chart_type, is_helm_credentials
    return resp


def get_config_xml(configuration_id):
    """
    Gets configuration XML from service layer

    :param configuration_id: Unique ID for package which user gets from ESH-UI
    """

    base_url = get_service_layer_url()
    url = "".join([base_url, "downloadedconfiguration/{}".format(configuration_id)])
    try:
        xml_file = requests.get(url)
        if xml_file.status_code == constants.HTTP_STATUS.get("OK"):
            return xml_file.content
        else:
            print(
                constants.RED.format(
                    "Failed to fetch the Manifest XML file edgesoftware_configuration.xml. "
                    "{} {}. Exiting. ".format(xml_file.status_code, xml_file.reason)
                )
            )
            sys.exit(-1)
    except requests.ConnectionError as e:
        print(
            "Failed to connect. Please check the Internet connection"
            " and proxy settings and retry. {}".format(e)
        )
    except requests.exceptions.RequestException as e:
        print("Failed to connect. " " {}".format(e))


def get_helm_registry_credentials(helm_chart_name, helm_chart_tag, log):
    """
    Gets Helm chart Registry Type

    Args:
        helm_chart_name (String): Helm Chart Name
        helm_chart_tag (String): Helm Chart Tag
        log (obj): Logger Object

    Returns:
        helm_chart_type, Bool: Chart Type, Credentials Status
    """
    try:
        base_url = get_service_layer_url()
        url = "".join(
            [
                base_url,
                "helmChart/chart?name={}&tag={}".format(
                    helm_chart_name, helm_chart_tag
                ),
            ]
        )
        status = requests.get(url)
        if status.status_code == constants.HTTP_STATUS.get("OK"):
            helm_chart_type = status.json()["registryType"]
            is_creds = status.json()["updateCredentials"]
            return helm_chart_type, is_creds
        else:
            log.console(
                "Failed to get Helm chart registry Type. {} {}".format(
                    status.status_code, status.reason
                ),
                error=True,
            )
            return None, None
    except requests.ConnectionError as e:
        log.console(
            "Failed to connect. Please check the Internet connection"
            " and proxy settings and retry. {}".format(e),
            error=True,
        )


def get_recipe_details(recipe_id, log):
    """
    Get package and module details from SL

    :Returns: package and module details
    """
    try:
        base_url = get_service_layer_url()
        url = "".join([base_url, "recipe/{}".format(recipe_id)])
        resp = None
        recipe_details = requests.get(url)
        if recipe_details.status_code == constants.HTTP_STATUS.get("OK"):
            resp = recipe_details.json()
        else:
            log.error("Failed to retrieve the package and module details from URL.")
    except requests.ConnectionError as e:
        log.console(
            "Failed to connect. Please check the Internet connection"
            " and proxy settings and retry. {}".format(e),
            error=True,
        )
    return resp


def download_package_artifacts(
    log, recipe_id, temp_file=None, remove_previous=False, export=False
):
    """
    Download the Package Artifacts from Service Layer

    Args:
        log (obj): Logger Object
        recipe_id (String): Package GUID
        temp_file (String, optional): Temporary folder location. Defaults to None.
        remove_previous (BOOL, optional): Remove Previous Files. Defaults to False.
        export (BOOL, optional): If called from export.
    """
    try:
        base_url = get_service_layer_url()
        url = "".join([base_url, "recipe/otherfiles/{}".format(recipe_id)])
        resp = None
        if export:
            file_list = []
        recipe_details = requests.get(url)
        if recipe_details.status_code == constants.HTTP_STATUS.get("OK"):
            resp = recipe_details.json()
            if remove_previous and len(resp) == 0:
                log.console(
                    "No artifacts file(s) for the package exist.",
                    color_code=constants.CYAN,
                )
            # Array of files, check if the file is present in the dir if not then download
            is_message = True
            for artifact in resp:
                file_name = artifact["filename"]
                download_link = artifact["downloadLink"]
                if temp_file:
                    file_path = os.path.join(temp_file, file_name)
                else:
                    file_path = os.path.join(file_name)
                if not os.path.isfile(file_path) or remove_previous:
                    if is_message:
                        log.console(
                            "Downloading artifacts file(s).", color_code=constants.CYAN
                        )
                        is_message = False
                    artifact_file = requests.get(download_link, stream=True)
                    if artifact_file.status_code == constants.HTTP_STATUS.get("OK"):
                        with open(file_path, "wb") as fd:
                            fd.write(artifact_file.content)
                        if remove_previous:
                            log.console(
                                "Fetched artifacts file {} ".format(file_name),
                                color_code=constants.GREEN,
                            )
                        else:
                            log.info("Fetched artifacts file {}. ".format(file_name))
                    else:
                        log.console(
                            "Failed to fetch the artifacts file {}. {} {}".format(
                                file_name,
                                artifact_file.status_code,
                                artifact_file.reason,
                            ),
                            color_code=constants.RED,
                        )

                else:
                    log.info("Artifacts file {} already exists.".format(file_name))

                if os.path.isfile(file_path) and export:
                    file_list.append(file_name)
                    log.info("Artifacts file {} appended.".format(file_name))
        else:
            log.error(
                "Failed to retrieve the package artifacts details for {}.".format(
                    recipe_id
                )
            )

        if export:
            return file_list

    except requests.ConnectionError as e:
        log.console(
            "Failed to connect. Please check the Internet connection"
            " and proxy settings and retry. {}".format(e),
            error=True,
        )
        sys.exit(-1)
    except (KeyError, IndexError, ValueError) as e:
        log.error("Exception in artifacts API. {}".format(e))

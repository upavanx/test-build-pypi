import click
import os
import sys

from edgesoftware import functions
from edgesoftware.common import constants
from colorama import init

if constants.Operating_system == "Windows":
    init(convert=True, autoreset=True)


@click.group()
@click.version_option(constants.VERSION_TAG, "-v", "--version")
def main():
    """A CLI wrapper for management of Intel® Edge Software Hub packages."""


@click.argument("configuration_id", required=False)
@click.argument("package_name", required=False)
@click.option(
    "-f",
    "--yaml-file",
    help="YAML file path that contains the list of modules to "
    "install. Please specify the supported format which is "
    "<module_name>:<path_to_code> under 'custom_modules' tag",
)
@main.command()
def install(yaml_file, package_name, configuration_id):
    """Install modules of a package.

    \b
    PACKAGE_NAME is the name of the package.
    CONFIGURATION_ID is the Configuration ID of the selected package.
    """
    if len(sys.argv) == 3:
        print(
            constants.RED.format(
                "Package name or Configuration ID is missing. "
                "Please check install command usage. Run edgesoftware install --help "
            )
        )
        sys.exit(-1)
    if yaml_file == None and len(sys.argv) > 3 and sys.argv[2] and sys.argv[3]:
        configuration_id = sys.argv[3]

    xml_overwritten = False
    if configuration_id:
        manifest, xml_overwritten = functions.get_config_xml(configuration_id)
    else:
        manifest = None
    if os.path.exists("edgesoftware_configuration.xml"):
        manifest = "edgesoftware_configuration.xml"
    if yaml_file:
        if os.path.exists(yaml_file):
            # NOTE(mkumari): Setting manifest to None because we don't
            # want to sync repo when path to custom packages is provided
            manifest = None
        else:
            print(
                constants.RED.format(
                    "User defined configuration file {} "
                    "not found. Exiting installation.".format(yaml_file)
                )
            )
            sys.exit(-1)
    if not manifest and not yaml_file:
        print(
            constants.RED.format(
                "Manifest XML file "
                "edgesoftware_configuration.xml not found. "
                "Exiting installation."
            )
        )
        sys.exit(-1)

    product_key = None
    is_product_key = True

    if not yaml_file:
        functions.download_package_artifacts(manifest_file=manifest)
        is_product_key = functions.check_product_key(manifest_file=manifest)

    if manifest and not yaml_file and is_product_key is True:
        print(
            constants.BICYAN.format(
                "Please enter the "
                "Product Key. The Product Key is contained in the email you "
                "received from Intel confirming your download: "
            ),
            end=" ",
        )
        product_key = input()
    if xml_overwritten:
        print(
            constants.YELLOW.format(
                "WARNING: Overwriting Manifest XML file edgesoftware_configuration.xml "
                "in current working directory."
            )
        )
    functions.setup_start(product_key, manifest, yaml_file)


@click.option(
    "-a",
    "--artifacts",
    is_flag=True,
    help="Download Package Artifacts.",
)
@click.argument("configuration_id", required=False)
@click.argument("package_name", required=False)
@main.command()
def download(
    artifacts,
    package_name,
    configuration_id,
):
    """Download modules/artifacts of a package.

    \b
    PACKAGE_NAME is the name of the package.
    CONFIGURATION_ID is the Configuration ID of the selected package.
    """
    if artifacts:
        manifest_file = None
        if os.path.exists("edgesoftware_configuration.xml"):
            manifest_file = "edgesoftware_configuration.xml"
        if not manifest_file:
            print(
                constants.RED.format(
                    "Manifest XML file "
                    "edgesoftware_configuration.xml not found. "
                    "Exiting artifacts download operation."
                )
            )
            sys.exit(-1)

        functions.download_package_artifacts(
            manifest_file, recipe_id=None, src_dir=None, remove_previous=True
        )

        sys.exit(-1)

    if len(sys.argv) == 3:
        print(
            constants.RED.format(
                "Package name or Configuration ID is missing. "
                "Please check download command usage. Run edgesoftware download --help "
            )
        )
        sys.exit(-1)
    if len(sys.argv) > 3 and sys.argv[2] and sys.argv[3]:
        configuration_id = sys.argv[3]

    xml_overwritten = False
    if configuration_id:
        manifest, xml_overwritten = functions.get_config_xml(configuration_id)
    else:
        manifest = None
    yaml_file = None
    if os.path.exists("edgesoftware_configuration.xml"):
        manifest = "edgesoftware_configuration.xml"
    if not manifest:
        print(
            constants.RED.format(
                "Manifest XML file "
                "edgesoftware_configuration.xml not found. "
                "Exiting download operation."
            )
        )
        sys.exit(-1)
    product_key = None
    is_product_key = True

    functions.download_package_artifacts(manifest_file=manifest)
    is_product_key = functions.check_product_key(manifest_file=manifest)
    if manifest and is_product_key is True:
        print(
            constants.BICYAN.format(
                "Please enter the "
                "Product Key. The Product Key is contained in the email you "
                "received from Intel confirming your download: "
            ),
            end=" ",
        )
        product_key = input()
    if xml_overwritten:
        print(
            constants.YELLOW.format(
                "WARNING: Overwriting Manifest XML file edgesoftware_configuration.xml "
                "in current working directory."
            )
        )
    functions.setup_start(product_key, manifest, yaml_file, download=True)


@click.option(
    "-d", "--default", is_flag=True, help="Lists the default modules of a package."
)
@click.option("-j", "--json", is_flag=True, help="Return output in json format.")
@click.option("-v", "--version", is_flag=True, help="Lists available packages.")
@click.option(
    "-l", "--local", is_flag=True, hidden=True, help="Lists available modules."
)
@main.command()
def list(default, json, version, local):
    """List the modules of a package."""
    functions.list_packages(default, json, version, local)


@click.argument("module", nargs=-1, required=True)
@main.command()
def update(module):
    """Update the modules of a package."""
    functions.update(module)


@click.argument("module_id", nargs=-1)
@click.option(
    "-a", "--all-modules", is_flag=True, help="Print logs for all modules of a package."
)
@main.command()
def log(module_id, all_modules):
    """Show log of CLI events."""
    functions.print_log(module_id, all_modules)


@click.option("-n", "--name", help="Name of ZIP file created by export")
@click.option("-f", "--yaml-file", help="Path to custom YAML file to be exported")
@main.command()
def export(name=None, yaml_file=None):
    """
    Export modules installed as part of a package.

    Package modules, custom modules, edgesoftware_configuration.xml file,
    a custom YAML file and edgesoftware, the Python executable to a zip file
    """
    functions.export_package(name, yaml_file)


@click.argument("package_id", nargs=1, required=True)
@main.command()
def upgrade(package_id):
    """
    Upgrade a package.

    Run 'edgesoftware list -v' for available upgrades
    """
    functions.upgrade(package_id)


@click.argument("ingredient_id", nargs=-1)
@click.option(
    "-f", "--file", is_flag=True, help="uninstall from esb_module for export."
)
@click.option("-a", "--all-modules", is_flag=True, help="Uninstall all ingredients.")
@main.command()
def uninstall(ingredient_id, all_modules, file):
    """Uninstall the modules of a package."""
    if len(ingredient_id) == 0 and all_modules == False:
        print("Please check uninstall command usage. Run edgesoftware uninstall --help")
        sys.exit(-1)
    functions.uninstall_ingredient(ingredient_id, all_modules, file)


@click.option("-p", "--pull", help="Pull docker image. <Image Name:Tag>")
@click.argument("image_names", nargs=-1)
@click.option(
    "-f",
    "--yaml-file",
    "yaml_file",
    type=click.Path(exists=True),
    help="Docker Compose file path that contains the list of docker images to "
    "download.",
)
@main.command()
def docker(pull, image_names, yaml_file):
    """Pull docker images"""
    if pull and len(sys.argv) > 3:
        if len(sys.argv) > 4:
            print(
                constants.BICYAN.format("Pulling images : {} ".format(sys.argv[3:])),
                end="\n",
            )

        for image_name in sys.argv[3:]:
            image = image_name.split(":")
            if len(image) == 1:
                name = image[0]
                tag = "latest"
            else:
                name, tag = image

            product_key = None
            is_product_key = True

            is_product_key = functions.check_product_key(image=name, tag=tag)

            if is_product_key is True:
                product_key = input(
                    constants.BICYAN.format(
                        "Please enter the "
                        "Product Key. The Product Key is contained in the email you "
                        "received from Intel confirming your download: "
                    )
                )
            functions.pull(name, tag, product_key)

    elif yaml_file:
        print(
            constants.BICYAN.format(
                "Please enter the "
                "Product Key. The Product Key is contained in the email you "
                "received from Intel confirming your download: "
            ),
            end=" ",
        )
        product_key = input()
        functions.pull_docker_compose(yaml_file, product_key)
    else:
        print(
            constants.RED.format(
                "Please check docker command usage. Run edgesoftware docker --help "
            )
        )
        sys.exit(-1)


@click.option(
    "-p",
    "--pull",
    help="Download Helm chart. <Chart Name-Tag>",
)
@click.option(
    "-u",
    "--update-keys",
    help="Update Kubernetes secret keys",
    is_flag=True,
    default=False,
    is_eager=True,
)
@click.argument("value", required=False, nargs=-1)
@main.command()
def helm(pull, update_keys, value):
    """
    Download Helm charts or update Kubernetes secret keys.
    """
    product_key = None
    is_product_key = False
    helm_chart_id = None
    helm_chart_type = None
    is_helm_credentials = False

    manifest = None

    if pull and len(sys.argv) > 3:

        if len(sys.argv) > 4:
            print(
                constants.BICYAN.format(
                    "Pulling Helm charts : {} ".format(sys.argv[3:])
                ),
                end="\n",
            )

        for chart_name in sys.argv[3:]:
            helm_list = []
            helm_chart = chart_name.rsplit("-", 1)
            if len(helm_chart) == 1:
                name = helm_chart[0]
                tag = "latest"
            else:
                name, tag = helm_chart
            print(
                constants.BICYAN.format(
                    "Pulling Helm chart : {}-{} ".format(name, tag)
                ),
                end="\n",
            )
            (
                is_product_key,
                helm_chart_id,
                helm_chart_type,
                is_helm_credentials,
            ) = functions.check_product_key(helm_chart_name=name, helm_chart_tag=tag)

            if is_product_key is None:
                continue
            if is_product_key is True:
                print(
                    constants.BICYAN.format(
                        "Please enter the "
                        "Product Key. The Product Key is contained in the email you "
                        "received from Intel confirming your download: "
                    ),
                    end=" ",
                )
                product_key = input()
            functions.download_helm_chart(
                name, tag, helm_chart_id, helm_chart_type, product_key
            )
            if is_helm_credentials and os.path.isdir("{}-{}".format(name, tag)):
                helm_list.append(
                    {
                        "label": name,
                        "comp_id": helm_chart_id,
                        "tag": tag,
                    }
                )
                functions.update_helm_keys(helm_list, product_key, None)
        sys.exit(-1)

    elif update_keys:
        if value:
            if len(sys.argv) > 4:
                print(
                    constants.BICYAN.format(
                        "Updating Keys for Helm charts : {} ".format(sys.argv[3:])
                    ),
                    end="\n",
                )

            for chart_name in sys.argv[3:]:
                helm_chart = chart_name.rsplit("-", 1)
                if len(helm_chart) == 1:
                    name = helm_chart[0]
                    tag = "latest"
                else:
                    name, tag = helm_chart
                print(
                    constants.BICYAN.format(
                        "Updating Keys for Helm chart : {}-{} ".format(name, tag)
                    ),
                    end="\n",
                )
                if not os.path.isdir("{}-{}".format(name, tag)):
                    print(
                        constants.RED.format(
                            "Please download the helm chart {}-{} before updating secret keys.".format(
                                name, tag
                            )
                        )
                    )
                    continue

                (
                    is_product_key,
                    helm_chart_id,
                    helm_chart_type,
                    is_helm_credentials,
                ) = functions.check_product_key(
                    helm_chart_name=name, helm_chart_tag=tag
                )
                if is_product_key is None:
                    continue
                if is_product_key is True:
                    print(
                        constants.BICYAN.format(
                            "Please enter the "
                            "Product Key. The Product Key is contained in the email you "
                            "received from Intel confirming your download: "
                        ),
                        end=" ",
                    )
                    product_key = input()

                if is_helm_credentials:
                    helm_list = []
                    helm_list.append(
                        {
                            "label": name,
                            "comp_id": helm_chart_id,
                            "tag": tag,
                        }
                    )
                    functions.update_helm_keys(helm_list, product_key, None)
                else:
                    print(
                        constants.GREEN.format(
                            "Helm chart {}-{} does not need secret keys.".format(
                                name, tag
                            )
                        ),
                        end="\n",
                    )
            sys.exit(-1)

        elif os.path.exists("edgesoftware_configuration.xml"):
            manifest = "edgesoftware_configuration.xml"
            if not manifest:
                print(
                    constants.RED.format(
                        "Manifest XML file "
                        "edgesoftware_configuration.xml not found. "
                        "Exiting update secret keys operation."
                    )
                )
                sys.exit(-1)
            helm_list = functions.get_helm_charts(manifest)
            if not helm_list:
                print(
                    constants.RED.format(
                        "No helm chart found for updating secret keys."
                    ),
                    end="\n",
                )
                sys.exit(-1)

            product_key = None
            is_product_key = True
            is_product_key = functions.check_product_key(manifest_file=manifest)

            if manifest and is_product_key is True:
                print(
                    constants.BICYAN.format(
                        "Please enter the "
                        "Product Key. The Product Key is contained in the email you "
                        "received from Intel confirming your download: "
                    ),
                    end=" ",
                )
                product_key = input()
            if helm_list:
                functions.update_helm_keys(helm_list, product_key, manifest)
            sys.exit(-1)

    else:
        print(
            constants.RED.format(
                "Please check helm command usage. Run edgesoftware helm --help "
            )
        )


if __name__ == "__main__":
    main(prog_name="edgesoftware")

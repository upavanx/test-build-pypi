from setuptools import setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="edgesoftware",
    version="1.0.1",
    description="A CLI wrapper for management of Intel® Edge Software Hub packages.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Intel Corporation",
    author_email="sys_recipes@intel.com",
    packages=["edgesoftware", "edgesoftware.common"],
    license="Proprietary - Intel",
    install_requires=[
        "Click>=7.0",
        "requests>=2.27.1",
        "oyaml",
        "prettytable",
        "inputimeout",
        "psutil",
        "py-cpuinfo",
        "wget",
        "colorama",
        "docker",
        "defusedxml",
        "tqdm",
        "six",
        "termcolor",
        "pathlib2",
        "setuptools>=58.0.0",
        "PyYAML>=5.4.1",
        "scp",
        "paramiko",
        "ruamel.yaml",
        "pexpect",
        "docker",
        "inquirer",
        "kubernetes",
    ],
    entry_points={"console_scripts": ["edgesoftware = edgesoftware.edgesoftware:main"]},
    python_requires=">=3.6",
)


## Command Line Interface for Intel® Edgesoftware 

*edgesoftware* is a command line interface wrapper (CLI) that helps you manage [Intel® Edge Software Hub packages](https://software.intel.com/content/www/us/en/develop/topics/iot/edge-solutions.html). With these pretested and pre-validated packages you can create reliable, scalable AI applications for the edge.  



### Installation 

#### Requirements 

- Minimum Python* version: 3.6 

- To install the software package, you will need an XML configuration file (*edgesoftware_configuration.xml*) along with the CLI. There is a dedicated XML configuration file for each software package (for example, Edge Insights for Vision) which you can find on [Intel® Edge Software Hub](https://www.intel.in/content/www/in/en/edge-computing/edge-software-hub.html). 

  

#### System Requirements

The table below lists supported operating systems and Python versions required to run the installation.

| Supported Operating System                    | [Python* Version (64-bit)](https://www.python.org/) |
| :-------------------------------------------- | :-------------------------------------------------- |
| Ubuntu* 18.04 long-term support (LTS), 64-bit | 3.6                                                 |
| Ubuntu* 20.04 long-term support (LTS), 64-bit | 3.8                                                 |
| Ubuntu* 22.04 long-term support (LTS), 64-bit | 3.10                                                 |
| Red Hat* Enterprise Linux* 8, 64-bit          | 3.6                                                 |
| CentOS* 7, 64-bit                             | 3.6                                                 |

> **NOTE**: This package can be installed on other versions of Linux, but only the specific versions above are fully validated.



#### Install edgesoftware CLI 

##### Step 1: Install and update PIP to the highest version

To install pip in Ubuntu 18.04, Ubuntu 20.04 and Ubuntu 22.04

```shell
sudo apt install python3-pip
```

To install pip in CentOS 7 and RHEL 8:

```
sudo yum install python3-pip
```

Run the command below to upgrade pip to the latest version:

```
python3 -m pip install --upgrade pip
```

##### Step 2. Install the package

Run the command below: 

```shell
python3 -m pip install edgesoftware --user
```

##### Step 3. If needed, launch a new terminal and verify that package is installed

Run the command below:

```shell
edgesoftware -v
```

You will not see any error messages if installation finished successfully.



 ### Using the edgesoftware CLI

**Learn all of the commands available with *edgesoftware* CLI** 

Run the command below: 

```shell
edgesoftware
```

**Response:** 

> Usage: edgesoftware [OPTIONS] COMMAND [ARGS]... 

> A CLI wrapper for management of Intel® Edge Software Hub packages. 

> **Options:** 
>
> > | options       | description                |
> > | ------------- | -------------------------- |
> > | -v, --version | Show the version and exit. |
> > | --help        | Show this message and exit |
> >
> > 

> **Commands:** 
>
> > | commands  | description                                            |
> > | --------- | ------------------------------------------------------ |
> > | docker    | Pull docker images                                     |
> > | download  | Download modules/artifacts of a package.               |
> > | export    | Export modules installed as part of a package.         |
> > | helm      | Download Helm charts or update Kubernetes secret keys. |
> > | install   | Install modules of a package.                          |
> > | list      | List the modules of a package.                         |
> > | log       | Show log of CLI events.                                |
> > | uninstall | Uninstall the modules of a package.                    |
> > | update    | Update the modules of a package.                       |
> > | upgrade   | Upgrade a package.                                     |

 

#### Learn more about a command 

Run the command below:  

```shell
edgesoftware <command> --help
```

Example:  

```shell
edgesoftware list --help
```

Response: 

> Usage: edgesoftware list [OPTIONS] 

> List the modules of a package. 

> Options: 

> > | options       | description                            |
> > | ------------- | -------------------------------------- |
> > | -v, --version | Lists available packages.              |
> > | -j, --json    | Return output in json format.          |
> > | -d, --default | Lists the default modules of a package |
> > | --help        | Show this message and exit             |



### Troubleshooting

**Error: *edgesoftware* command may not respond after installation.**

To mitigate this issue, close the current terminal and open a new terminal. The command should work in the newer terminal.

**Error: *python3 -m pip install edgesoftware* may fail due to failed installation of cryptography package.**

To resolve this issue, upgrade pip to latest version using *python3 -m pip install --upgrade pip* and then retry the installation.

**Error: *edgesoftware install* command may fail first time giving error - missing esb_common.**

To resolve this issue, try edgesoftware install command once again. This time you should be able to install the modules.



### Additional Resources 

Refer to [Introduction to the Edge Software Hub CLI](https://www.intel.com/content/www/us/en/develop/documentation/edge-insights-vision-doc/get-started-guide-using-linux/intro-to-the-edge-software-cli.html) for more information on CLI commands. 



### License 

All *edgesoftware* wheels on PyPI are distributed under [LIMITED TOOLS LICENSE AGREEMENT](https://software.intel.com/content/dam/develop/external/us/en/documents/limited-tools-license-agreement.pdf).

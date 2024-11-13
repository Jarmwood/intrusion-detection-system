# IDS | Intrusion Detection System | Python + SciKit-learn + Scapy

Developed Intrusion Detection System (IDS) that monitors network traffic and alerts on suspicious or malicious activity using machine learning models like Isolation Forrest.

## Prerequisites
Download/install
* [PyCharm](https://www.jetbrains.com/pycharm/download/): Pycharm is a JetBrains is a feature rich IDE, specifically created with python in mind.
* [Anaconda(MiniConda)](https://docs.anaconda.com/miniconda/): Anaconda is an environment management system, Miniconda is a (free) miniature installation of Anaconda Distribution that includes only conda, Python, the packages they both depend on, and a small number of other useful packages.

## Installation
1. open the cloned down repository as a project
2. Open settings and navigate to:
   1. ```Settings -> Project -> Python Interpreter```
3. Click add interpreter -> add local interpreter
4. Choose conda tab -> use existing env -> ```intrusionDetectionSystem```

## common Conda commands
* To see all conda environments ```conda env list```.
* To switch to a different environment ```conda activate <env_name>```
  * Make sure to run ```conda deactivate``` before switching to a different environment
* To export current environment settings run ```conda env export -n <env_name> <path/to/file_name>```
* To delete environment run ```conda remove -n <env_name> --all```
* To update environment run ```conda env update -f env.yml --prune```
* In the event you break your local conda environment, you can 'roll back' to a previous revision point
  * First run ```conda list --revisions```
    * It will return a list of revisions with their associated revision number
    * Then, look at the second-to-last revision and take note it's number
  * To revert back run ```conda install --revision N```
    * here 'N' is the specified revision number
## Testing
unit tests using pytest
run ```pytest network_analyzer.py```

## Dependencies 
All the libraries and versions used are located in the env.yml file and requirements file but a brief overview is as follows:
- Python
- Pandas
- Scapy
- Scikit-learn
- Pytest

## Demo

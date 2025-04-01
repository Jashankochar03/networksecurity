from setuptools import find_packages,setup
from typing import List

def get_requirements()->List[str]:
    """
    This function will return list of requiremnents

    """
    requirement_list:List[str] = []
    try:
        with open('requirements.txt',"r") as file:
            #read lines from file
            lines = file.readlines()
            #process each line
            for line in lines:
                requirement = line.strip()
                # ignore empty line and -e.
                if requirement and requirement!='-e .':
                    requirement_list.append(requirement)
    except FileNotFoundError:
        print('requirement.txt file not found')

    return requirement_list

setup(
    name = "NetworkSecurity",
    version = "0.0.1",
    author = "Jashanpreet Singh",
    author_email = "jaskochar2003@gmail.com",
    packages = find_packages(),
    install_requires = get_requirements()
)

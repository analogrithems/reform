from setuptools import setup, find_packages
setup(
    name="reform",
    version="0.1.9",
    packages=find_packages(exclude=["docs", "tests"]),  # Required
    install_requires=["invoke", "pycryptodome", "pycryptodome", "pyee", "pathlib"],
    entry_points={"console_scripts": ["reform = reform:program.run"]},
)

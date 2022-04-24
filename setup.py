from setuptools import setup, find_packages

dependencies = open("requirements.txt").read().split("\n")

setup(name="secplugs-python-client",
      version="0.1",
      description="The python client for Secplugs REST API",
      url="https://github.com/SecPlugs/python-kit",
      author="TheStigAtSecPlugs",
      author_email="secplugs@secplugs.com",
      license="Apache 2.0",
      setup_requires=['wheel'],
      install_requires=dependencies,
      package_dir={'': 'src'},
      packages=[''],
      zip_safe=False)

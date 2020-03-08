from setuptools import setup

setup(
    name='gerrsh',
    version='0.1',
    scripts=['gerrsh'],
    author="Vadym Kochan",
    author_email="vadim4j@gmail.com",
    description="Command-line tool for review Gerrit changes",
    classifiers=[
        "Environment :: Console",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Topic :: Software Development :: Version Control :: Git",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
    ],
)

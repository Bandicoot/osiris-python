#!/usr/bin/env python

from setuptools import setup

setup(
    name="osiris_ids",
    version="0.1.0",
    author="Saj Goonatilleke",
    author_email="sg@redu.cx",

    description="Osiris IDS management client",
    long_description="""
Osiris is (or was) a distributed intrusion detection system (IDS)
maintained by the Shmoo Group.  This library, osiris_ids, can be used to
interact with the Osiris management daemon (osirismd) from your Python
applications.

Only a tiny subset of the osirismd network protocol has been implemented
here.
""",
    license="BSD",
    platforms=["Linux", "Unix"],

    classifiers=[
      "Development Status :: 1 - Alpha",
      "Intended Audience :: System Administrators",
      "License :: OSI Approved :: BSD License",
      "Operating System :: POSIX",
      "Programming Language :: Python",
      "Topic :: Security",
      "Topic :: System :: Systems Administration",
    ],

    py_modules=['osiris_ids',],
)

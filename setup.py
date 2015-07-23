from __future__ import division, absolute_import
from setuptools import setup, find_packages


setup(
    name='bastion-proxy',
    version='1.0.0',
    description='Bastion proxy to connect to other proxies via it.',
    url='https://github.com/nailgun/bastion-proxy',
    author='Nailgun',
    author_email='dbashkatov@gmail.com',
    license='MIT',
    packages=find_packages(),

    install_requires=[
        'Twisted >= 15.2, < 16.0',
    ],

    entry_points={
        'console_scripts': [
            'bastion-proxy = bastion_proxy:main',
        ],
    },
)

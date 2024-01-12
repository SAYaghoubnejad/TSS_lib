from setuptools import setup, find_packages

setup(
    name='pyfrost',
    version='0.1',
    packages=find_packages(exclude=['pyfrost/tests', 'pyfrost/example']),
    install_requires=[
        'web3==5.31.4',
        'ecpy==1.2.5',
        'numpy==1.26.2',
        'libp2p @ git+https://github.com/libp2p/py-libp2p.git@b38b36862f44421aec998e438b668cff265de75c#egg=libp2p',
        'Flask==3.0.0'
    ],
)

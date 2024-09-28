from setuptools import setup, find_packages

setup(
    name="safemx",
    version="0.1.5",
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'safemx=safemx.main:main',
        ],
    },
    install_requires=[
        'argparse',
        'colorama',
        'dnspython'
    ],
    description="A tool to check domain's SPF, DMARC, and DKIM records.",
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author="Marko Gordic",
    author_email="marko@gordic.rs",
    url="https://github.com/MarkoGordic/safemx",
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)

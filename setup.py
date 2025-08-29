from setuptools import setup, find_packages
import codecs
import os

# Read the long description from README
here = os.path.abspath(os.path.dirname(__file__))

with codecs.open(os.path.join(here, "README.md"), encoding="utf-8") as fh:
    long_description = "\n" + fh.read()

# Application version
VERSION = '1.0.0'
DESCRIPTION = 'Dark Vulnerability Scanner Pro - Advanced Web Vulnerability Scanning Tool'
LONG_DESCRIPTION = 'A comprehensive web vulnerability scanner with advanced GUI interface'

setup(
    name="dark-vulnerability-scanner",
    version=VERSION,
    author="Security Team",
    author_email="<your_email@example.com>",
    description=DESCRIPTION,
    long_description_content_type="text/markdown",
    long_description=long_description,
    packages=find_packages(),
    install_requires=[
        'requests>=2.28.0',
        'beautifulsoup4>=4.11.0',
        'tkinter>=0.1.0',  # Usually included with Python
        'urllib3>=1.26.0',
        'python-dateutil>=2.8.0',
        'cryptography>=3.4.0',
        'pyopenssl>=22.0.0',
        'idna>=3.0',
        'charset-normalizer>=2.0.0',
        'certifi>=2022.0.0',
        'pywin32>=300; platform_system=="Windows"',
        'pillow>=9.0.0'  # For better GUI support
    ],
    entry_points={
        'console_scripts': [
            'dark-scanner=dark_scanner.main:main',
        ],
    },
    keywords=['security', 'vulnerability', 'scanner', 'web', 'pentest'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'Topic :: Internet :: WWW/HTTP',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Operating System :: OS Independent',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: Unix',
        'Operating System :: MacOS'
    ],
    python_requires='>=3.7',
    include_package_data=True,
    package_data={
        'dark_scanner': [
            '*.txt',
            '*.md',
            'data/*.json',
            'data/*.txt',
            'icons/*.ico',
            'icons/*.png'
        ],
    },
    project_urls={
        'Documentation': 'https://github.com/yourusername/dark-scanner',
        'Source': 'https://github.com/yourusername/dark-scanner',
        'Tracker': 'https://github.com/yourusername/dark-scanner/issues',
    },
    options={
        'bdist_wheel': {
            'universal': True
        }
    }
)

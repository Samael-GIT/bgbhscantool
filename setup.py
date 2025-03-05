from setuptools import setup, find_packages

setup(
    name="bgbhscan",
    version="1.0.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        'requests>=2.31.0',
        'dnspython>=2.4.2',
        'beautifulsoup4>=4.12.2',
        'lxml>=4.9.3',
        'pyOpenSSL>=23.2.0',
        'cryptography>=41.0.5',
        'urllib3>=2.0.7',
        'xmltodict>=0.13.0',
        'defusedxml>=0.7.1',
        'colorama>=0.4.6',
        'tqdm>=4.66.1',
        'click>=8.1.7',
        'python-whois>=0.8.0',
        'netaddr>=0.9.0',
        'ipaddress>=1.0.23',
        'oauthlib>=3.2.2',
        'pyjwt>=2.8.0',
        'aiohttp>=3.9.0',
        'httpx>=0.25.1',
        'scrapy>=2.11.0',
        'selenium>=4.14.0',
        'playwright>=1.39.0',
        'wfuzz>=3.1.0',
        'paramiko>=3.3.1',
        
    ],
    entry_points={
        'console_scripts': [
            'bgbhscan=main:main',
        ],
    },
)




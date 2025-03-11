from setuptools import setup, find_packages
import platform

# Platform-specific dependencies
platform_deps = []
if platform.system() == "Windows":
    platform_deps = ["pywin32>=306"]
elif platform.system() == "Linux":
    platform_deps = ["python-iptables>=1.0.1"]

setup(
    name="personal-firewall",
    version="1.0.0",
    description="A cross-platform GUI-based personal firewall",
    author="Personal Firewall Team",
    author_email="",
    packages=find_packages(),
    install_requires=[
        "PyQt5>=5.15.0",
        "psutil>=5.9.0",
        "elevate>=0.1.3",
    ] + platform_deps,
    entry_points={
        "console_scripts": [
            "personal-firewall=personal_firewall:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: X11 Applications :: Qt",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: System :: Networking :: Firewalls",
        "Topic :: Utilities",
    ],
    python_requires=">=3.8",
)
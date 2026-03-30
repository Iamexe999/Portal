from setuptools import setup, find_packages

setup(
    name="portablizer",
    version="1.0.0",
    description="Convert any .exe installer into a portable, no-admin-required application",
    author="Portablizer",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "watchdog>=3.0.0",       # Filesystem watching (sandbox mode)
        "psutil>=5.9.0",         # Process utilities
    ],
    extras_require={
        "dev": ["pytest", "pytest-cov"],
    },
    entry_points={
        "console_scripts": [
            "portablizer=portablizer.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "portablizer": ["tools/bin/*"],
    },
)

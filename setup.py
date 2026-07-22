from setuptools import setup, find_packages

with open('README.md', 'r') as f:
    long_description = f.read()

setup(
    name="kfiosa",
    version="3.0.0",
    description="KFIOSA — AI-driven offensive-security TUI (wifite-style WiFi + BLE + OSINT + post-exploitation)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="KFIOSA",
    url="https://github.com/kfiosa/kfiosa",
    packages=find_packages(include=["core", "core.*"]),
    install_requires=[
        "python-dotenv>=1.0.0",
        "requests>=2.31.0",
        "bleak>=0.22.0",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.10",
)
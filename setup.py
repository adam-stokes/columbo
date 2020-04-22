from pathlib import Path

import setuptools

README = Path(__file__).parent.absolute() / "readme.md"
README = README.read_text(encoding="utf8")

setuptools.setup(
    name="columbo",
    version="0.0.3",
    author="Adam Stokes",
    author_email="adam.stokes@ubuntu.com",
    description="columbo, he smart yo",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/battlemidget/columbo",
    packages=["columbo", "columbo.commands"],
    package_data={"": ["*"]},
    entry_points={"console_scripts": ["columbo = columbo.commands.base:start",]},
    install_requires=[
        "click>=7.0,<8.0",
        "dict-deep==2.0.2",
        "loguru>=0.3.2,<1.99.30",
        "melddict>=1.0,<2.0",
        "pyyaml>=3.0,<6.0",
        "colorama==0.3.9",
        "pathos==0.2.5",
        "python-magic==0.4.15",
    ],
    zip_safe=False,
)

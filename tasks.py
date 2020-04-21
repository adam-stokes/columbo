import os

from invoke import task


@task
def clean(c):
    print("Cleaning project")
    c.run("rm -rf build dist columbo.egg-info __pycache__")


@task
def fix(c):
    c.run("isort -rc -m 3 .")
    c.run("black .")


@task
def test(c):
    c.run("pylint columbo tests")
    c.run("pytest")


@task
def bump_rev(c):
    c.run("punch --part patch")


@task
def dist(c):
    c.run("python3 setup.py bdist_wheel")


@task(pre=[clean, dist])
def install(c):
    c.run("pip install --upgrade dist/*whl --force")


@task(pre=[clean, fix, test, bump_rev, dist])
def upload(c):
    c.run("twine upload dist/*")

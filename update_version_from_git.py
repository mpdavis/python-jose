"""
Adapted from https://github.com/pygame/pygameweb/blob/master/pygameweb/builds/update_version_from_git.py

For updating the version from git.
__init__.py contains a __version__ field.
Update that.
If the user supplies "patch" as a CLi argument, we want to bump the existing patch version
If the user supplied the full version as a CLI argument, we want to use that version.
Otherwise,
If we are on master, we want to update the version as a pre-release.
git describe --tags
With these:
    __init__.py
        __version__= '0.0.2'
    git describe --tags
        0.0.1-22-g729a5ae
We want this:
    __init__.py
        __version__= '0.0.2.dev22.g729a5ae'
Get the branch/tag name with this.
    git symbolic-ref -q --short HEAD || git describe --tags --exact-match
"""

import io
import re
import subprocess
import sys
from pathlib import Path

from packaging.version import Version

_INIT_FILE = Path("jose/__init__.py")


def migrate_source_attribute(attr, to_this, target_file):
    """Updates __magic__ attributes in the source file"""
    new_file = []
    found = False
    lines = target_file.read_text().splitlines()

    for line in lines:
        if line.startswith(attr):
            found = True
            line = to_this
        new_file.append(line)

    if found:
        target_file.write_text("\n".join(new_file))


def migrate_version(new_version):
    """Updates __version__ in the init file"""
    print(f"migrate to version: {new_version}")
    migrate_source_attribute("__version__", to_this=f'__version__ = "{new_version}"\n', target_file=_INIT_FILE)


def is_master_branch():
    cmd = "git rev-parse --abbrev-ref HEAD"
    tag_branch = subprocess.check_output(cmd, shell=True)
    return tag_branch in [b"master\n"]


def get_git_version_info():
    cmd = "git describe --tags"
    ver_str = subprocess.check_output(cmd, shell=True)
    ver, commits_since, githash = ver_str.decode().strip().split("-")
    return Version(ver), int(commits_since), githash


def prerelease_version():
    """return what the prerelease version should be.
    https://packaging.python.org/tutorials/distributing-packages/#pre-release-versioning
    0.0.2.dev22
    """
    ver, commits_since, githash = get_git_version_info()
    initpy_ver = get_version()

    assert initpy_ver > ver, "the jose/__init__.py version should be newer than the last tagged release."
    return f"{initpy_ver.major}.{initpy_ver.minor}.{initpy_ver.micro}.dev{commits_since}"


def get_version():
    """Returns version from jose/__init__.py"""
    version_file = _INIT_FILE.read_text()
    version_match = re.search(r'^__version__ = [\'"]([^\'"]*)[\'"]', version_file, re.MULTILINE)
    if not version_match:
        raise RuntimeError("Unable to find version string.")
    initpy_ver = version_match.group(1)
    assert len(initpy_ver.split(".")) in [3, 4], "jose/__init__.py version should be like 0.0.2.dev"
    return Version(initpy_ver)


def increase_patch_version(old_version):
    """
    :param old_version: 2.0.1
    :return: 2.0.2.dev
    """
    return f"{old_version.major}.{old_version.minor}.{old_version.micro + 1}.dev"


def release_version_correct():
    """Makes sure the:
    - prerelease verion for master is correct.
    - release version is correct for tags.
    """
    print("update for a pre release version")
    assert is_master_branch(), "No non-master deployments yet"
    new_version = prerelease_version()
    print(f"updating version in __init__.py to {new_version}")
    assert len(new_version.split(".")) >= 4, "jose/__init__.py version should be like 0.0.2.dev"
    migrate_version(new_version)


if __name__ == "__main__":
    new_version = None
    if len(sys.argv) == 1:
        release_version_correct()
    elif len(sys.argv) == 2:
        for _, arg in enumerate(sys.argv):
            new_version = arg
        if new_version == "patch":
            new_version = increase_patch_version(get_version())

        migrate_version(new_version)
    else:
        print(
            "Invalid usage. Supply 0 or 1 arguments. "
            "Argument can be either a version '1.2.3' or 'patch' if you want to increase the patch-version (1.2.3 -> 1.2.4.dev)"
        )

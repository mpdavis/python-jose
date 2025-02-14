# Changelog #

## 3.4.0 -- 2025-02-14 ##

### News ###

* Remove support for Python 3.6 and 3.7
* Added support for Python 3.10 and 3.11

### Bug fixes and Improvements ###
* Updating `CryptographyAESKey::encrypt` to generate 96 bit IVs for GCM block
  cipher mode
* Fix for PEM key comparisons caused by line lengths and new lines
* Fix for CVE-2024-33664 - JWE limited to 250KiB
* Fix for CVE-2024-33663 - signing JWT with public key is now forbidden
* Replace usage of deprecated datetime.utcnow() with datetime.now(UTC) 

### Housekeeping ###

* Updated Github Actions Workflows
* Updated to use tox 4.x
* Revise codecov integration
* Fixed DeprecationWarnings

## 3.3.0 -- 2021-06-04 ##

### News ###

* Remove support for python 2.7 & 3.5
* Add support for Python 3.9
* Remove PyCrypto backend
* Fix deprecation warning from cryptography backend

### Housekeeping ###

* Switched from Travis CI to Github Actions
* Added iSort & Black
* Run CI Tests under Mac OS & Windows.
* Updated Syntax to use Python 3.6+
* Upgrade to latest pytest, remove used dev requirements.

## 3.2.0 -- 2020-07-29 ##

### News ###

* This will be the last release supporting Python 2.7, 3.5, and the PyCrypto
  backend.

### Bug fixes and Improvements ###

* Use hmac.compare_digest instead of our own constant_time_string_compare #163
* Fix `to_dict` output, which should always be JSON encodeable. #139 and #165
  (fixes #127 and #137)
* Require setuptools >= 39.2.0 #167 (fixes #161)
* Emit a warning when verifying with a private key #168 (fixes #53 and #142)
* Avoid loading python-ecdsa when using the cryptography backend, and pinned
  python-ecdsa dependency to <0.15 #178

### Housekeeping ###

* Fixed some typos #160, #162, and #164

## 3.1.0 -- 2019-12-10 ##

This is a greatly overdue release.

### Features ###

* Improve `JWT.decode()` #76 (fixes #75)
* Sort headers when serializing to allow for headless JWT #136 (fixes #80)
* Adjust dependency handling
  - Use PyCryptodome instead of PyCrypto #83
  - Update package dependencies #124 (fixes #158)
* Avoid using deprecated methods #85
* Support X509 certificates #107
* Isolate and flesh out cryptographic backends to enable independent operation #129 (fixes #114)
  - Remove pyca/cryptography backend's dependency on python-ecdsa #117
  - Remove pycrypto/dome backends' dependency on python-rsa #121
  - Make pyca/cryptography backend the preferred backend if multiple backends are present #122

### Bugfixes/Improvements ###

* Enable flake8 check in tox/TravisCI #77
* Fix `crytography` dependency typo #94
* Trigger tests using `python setup.py test` #97
* Properly raise an error if a claim is expected and not given #98
* Typo fixes #110
* Fix invalid RSA private key PKCS8 encoding by python-rsa backend #120 (fixes #119)
* Remove `future` dependency #134 (fixes #112)
* Fix incorrect use of `pytest.raises(message=...)` #141
* Typo fix #143
* Clarify sign docstring to allow for `dict` payload #150

### Housekeeping ###

* Streamline the code a bit and update classifiers #87
* Fix typo and rephrase `access_token` documentation #89
* Code linting now mostly honors flake8 #101
* Document using a `dict` for `jwt.encode` and `jwt.decode` #103
* Include docs and tests in source distributions #111
* Updating README descriptions of crypto backends #130
* Document versioning policy #131
* Add `CHANGELOG.rst` #132 (fixes #99)
* Simplify and extend `.travis.yml` #135
* Move `CHANGELOG.rst` to `CHANGELOG.md` and update it #159

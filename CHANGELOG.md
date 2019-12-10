# Changelog #

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

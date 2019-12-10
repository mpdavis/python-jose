---------
Changelog
---------

3.1.0 -- 2019-??-??
^^^^^^^^^^^^^^^^^^^

Major
"""""

* Require claim options added.
  `#98 <https://github.com/mpdavis/python-jose/pull/98>`_
* Isolate and flesh out cryptographic backends to enable independent operation.
  `#114 <https://github.com/mpdavis/python-jose/issues/114>`_
  `#129 <https://github.com/mpdavis/python-jose/pull/129>`_
* Remove pyca/cryptography backend's dependency on python-ecdsa.
  `#117 <https://github.com/mpdavis/python-jose/pull/117>`_
* Remove pycrypto/dome backends' dependency on python-rsa.
  `#121 <https://github.com/mpdavis/python-jose/pull/121>`_
* Make pyca/cryptography backend the preferred backend if multiple backends are present.
  `#122 <https://github.com/mpdavis/python-jose/pull/122>`_
* Allow for headless JWT by sorting headers when serializing.
  `#136 <https://github.com/mpdavis/python-jose/pull/136>`_

Bugfixes
""""""""

* Fix invalid RSA private key PKCS8 encoding by python-rsa backend.
  `#120 <https://github.com/mpdavis/python-jose/pull/120>`_

Housekeeping
""""""""""""

* Test each cryptographic backend independently in CI.
  `#114 <https://github.com/mpdavis/python-jose/issues/114>`_
  `#129 <https://github.com/mpdavis/python-jose/pull/129>`_
  `#135 <https://github.com/mpdavis/python-jose/pull/135>`_
* Add flake8 checks in CI.
* Add CPython 3.7 and PyPy 3.5 testing in CI.
* Remove package future as a dependency, not needed anymore.
* Fix warnings from py.test.

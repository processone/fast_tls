# Version 1.0.25

* Updating p1_utils to version 1.0.13.

# Version 1.0.24

* Updating p1_utils to version 6ff85e8.
* Add support for tls 1.1.1 and tls1.3

# Version 1.0.23

* Updating p1_utils to version 1.0.12.
* Add ability to get cipher user by connection

# Version 1.0.22

* Don't check mtime of certificates, and make cerificate update explicit
* Add ability to specify CA for accepting client certificates

# Version 1.0.21

* Updating p1_utils to version 1.0.11.
* Fix compilation with rebar3 

# Version 1.0.20

* Include uthash.h in hex package

# Version 1.0.19

* Fix couple memory leaks
* Switch hashmap to uthash library
* Use system allocator in openssl
* Update ciphers and option to safer defaults

# Version 1.0.18

* Do not report badly formed Client Hello as a TLS error
* Report meaningful error when SNI callback fails
* Add Server Name Indication support for server connections
* Libressl only offer pre 1.1 api even if it present version > 1.1
* Fix crash on Mac OS X High Sierra due to replacement of system OpenSSL with BoringSSL

# Version 1.0.17

* Fix case clause introduced after migration to NIF

# Version 1.0.16

* Updating p1_utils to version 1.0.10.
* Fix couple memory leaks
* Make ECDH work on openssl < 1.0.2
* Add SNI and ALPN support for client connections

# Version 1.0.15

* Fix Hex packaging

# Version 1.0.14

* Improve ECDH curve handling (thanks to user pitchum)
* Fix bug in handling protocol_options option

# Version 1.0.13

* Convert to use NIF (Paweł Chmielowski)

# Version 1.0.12

* depends on p1_utils-1.0.9

# Version 1.0.11

* coveralls:convert_file is not 4 arg function (Paweł Chmielowski)
* Resolve vars.config relative to SCRIPT (Paweł Chmielowski)
* Comment debug line (Paweł Chmielowski)
* Fix a couple typos in the README's macOS/OS X section (Alex Jordan)
* Small typo fix on readme (costpermille)
* Deprecate hash functions in favor of crypto:hash/2 (Peter Lemenkov)
* Fix certificate decoding to OTP format (Evgeniy Khramtsov)

# Version 1.0.10

* Add ability to use system installed deps instead fetching them from git (Paweł Chmielowski)

# Version 1.0.9

* Fix problem with compilation against libressl
* Make tests use localy build c library instead of system one

# Version 1.0.8

* Use p1_utils 1.0.6 (Christophe Romain)
* Make it possible to decode certificate to OTP format (Evgeniy Khramtsov)
* Make sure p1_sha isn't compiled to native code (Holger Weiss)

# Version 1.0.7

* Use p1_utils 1.0.5 (Mickaël Rémond)
* Do not log warning on sha1 nif reload attempt (Mickaël Rémond)

# Version 1.0.6

* Fix compilation on rebar3 (Paweł Chmielowski)

# Version 1.0.5

* OpenSSL 1.1.0 compliance (Paweł Chmielowski)
* Use p1_utils 1.0.4 (Mickaël Rémond)

# Version 1.0.4

* Better compliance with R17 and R18 (Paweł Chmielowski)

# Version 1.0.3

* Do not call internal erlang erl_exit function (Christophe Romain)

# Version 1.0.2

* Add support for cafile option (Evgeny Khramtsov)
* Better error checks (Michael Santos)

# Version 1.0.1

* Build improve, remove check on Erlang version for better build chain compliance (Mickaël Rémond)

# Version 1.0.0

* Release on Hex.pm (Mickaël Rémond)
* Project renamed to fast_tls to emphasize on performance (Mickaël
  Rémond)

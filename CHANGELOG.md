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

* Fix problem with compilation agains libressl
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

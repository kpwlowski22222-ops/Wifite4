"""core.osint.polish — no-key Polish OSINT subpackage.

Phase 2.4 (operator's revision): no Polish API that needs a key
is wired. This subpackage exposes:

* ``validators``  — PESEL / NIP / REGON9 / REGON14 / KRS / IBAN /
                    Phone_PL pure-Python checksum validators
                    (GDPR-safe local algorithms; no network).
* ``pesel_decode`` — PESEL -> {birthdate, sex, century} decoder.
* ``phone_prefix`` — UKE / static 50+ prefix -> carrier table.
* ``ceidg``        — CEIDG SOAP no-auth client (the only Polish
                     registry that works without a key).
* ``knf``          — KNF API XML parser (no auth, needs User-Agent).
* ``nameday``      — nameday.abalin.net (no key, JSON, CORS).
* ``postal_codes`` — pocztapolska GitHub CSV mirror (no key).
* ``captcha_wall`` — shared honest-degrade envelope builder for
                     captcha-walled endpoints.

All key-needing endpoints (GUS BIR1, TERYT, Allegro
client_credentials, Wykop Daisy tier, LinkedIn, NK.pl, KRD, ERIF,
InfoMonitor 3rd-party) honest-degrade via
``captcha_wall.honest_degrade`` with explicit ``error="<reason>_needs_*"``.
"""
from __future__ import annotations

__all__ = ["validators", "pesel_decode", "phone_prefix", "ceidg",
           "knf", "nameday", "postal_codes", "captcha_wall"]

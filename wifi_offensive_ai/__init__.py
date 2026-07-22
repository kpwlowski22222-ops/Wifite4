# wifi_offensive_ai — revived legacy re-export layer.
#
# The historical ``wifi_offensive_ai`` tree was deleted; only two loose
# blobs survived in the object store (``core/engine.py`` and
# ``modules/offensive_automations.py``). The tree is revived here as a
# thin shim — the heavy lifting (Kali integration, polymorphic evasion)
# lives in :mod:`core.modules` and is re-exported from this package for
# backwards compatibility with old import paths.

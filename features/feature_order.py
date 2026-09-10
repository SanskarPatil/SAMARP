"""Frozen feature order - the single authoritative artifact.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md section 6.4

Training and inference MUST import FEATURE_ORDER from this module. No
detector or model is allowed to construct its own feature ordering.

A silent reorder produces a model scoring against the wrong features. No
test outside tests/parity/ catches it, and no amount of debugging the
detector explains it.
"""

FEATURE_ORDER = (
    # --- DGA (section 10.3) ---
    # lm_bigram / lm_trigram come from a background model trained on the
    # benign Tranco-derived hostname corpus. The score is a FEATURE, not a
    # standalone verdict; it is what defeats wordlist-style DGAs that raw
    # entropy cannot separate.
    "length",
    "entropy",
    "digit_ratio",
    "vowel_ratio",
    "label_count",
    "lm_bigram",
    "lm_trigram",
    "nxdomain_rate",

    # --- DNS tunnel (sections 9.5, 10.4) ---
    # qtype distribution is a PS-named tunnelling discriminator and must be
    # exposed in the evidence drawer.
    "qtype_txt_ratio",
    "qtype_null_ratio",
    "qtype_cname_ratio",
    "qtype_entropy",

    # --- TLS/QUIC shape (section 10.6) ---
    # "Shape" means concrete traffic metadata, never a generic anomaly label.
    # These never inspect decrypted payload bytes.
    "packet_size_first_n",
    "packet_size_mean",
    "packet_size_p95",
    "iat_median",
    "iat_p95",
    "iat_cv",
    "upstream_packet_ratio",
    "downstream_packet_ratio",
)

# Frozen contract metadata. Asserted by tests/schema/.
FEATURE_ORDER_VERSION = 1
FEATURE_COUNT = len(FEATURE_ORDER)

assert len(set(FEATURE_ORDER)) == FEATURE_COUNT, "FEATURE_ORDER contains duplicates"

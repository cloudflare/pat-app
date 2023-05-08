import sys
import json
import textwrap

def wrap_line(value):
    return textwrap.fill(value, width=65)

def format_vector(vector_keys, vector_fname):
    with open(vector_fname, "r") as fh:
        data = json.load(fh)
        formatted = "~~~\n"
        for i, entry in enumerate(data):
            formatted = formatted + ("// Test vector %d" % (i+1)) + "\n"
            for key in vector_keys:
                if key in entry:
                    if type(entry[key]) == type(""):
                        formatted = formatted + wrap_line(key + ": " + str(entry[key])) + "\n"
                    else:
                        formatted = formatted + wrap_line(key + ": " + str(",".join(entry[key]))) + "\n"
            formatted = formatted + "\n"
        print(formatted + "~~~\n")

if "ed25519-blinding" in sys.argv[1]:
    ordered_keys = [
        "skS", "pkS", "bk", "pkR", "message", "context", "signature",
    ]
    format_vector(ordered_keys, sys.argv[1])

if "ecdsa-blinding" in sys.argv[1]:
    ordered_keys = [
        "skS", "pkS", "bk", "pkR", "message", "context", "signature",
    ]
    format_vector(ordered_keys, sys.argv[1])

if "basic-public-issuance" in sys.argv[1]:
    ordered_keys = [
        "skS", "pkS", "token_challenge", "nonce", "blind", "salt", "token_request", "token_response", "token"
    ]
    format_vector(ordered_keys, sys.argv[1])

if "batched-private-issuance" in sys.argv[1]:
    ordered_keys = [
        "skS", "pkS", "token_challenge", "nonces", "blinds", "salt", "token_request", "token_response", "tokens"
    ]
    format_vector(ordered_keys, sys.argv[1])

if "basic-private-issuance" in sys.argv[1]:
    ordered_keys = [
        "skS", "pkS", "token_challenge", "nonce", "blind", "token_request", "token_response", "token"
    ]
    format_vector(ordered_keys, sys.argv[1])

if "origin-encryption-test-vectors.json" in sys.argv[1]:
    ordered_keys = [
        "origin_name", "kem_id", "kdf_id", "aead_id", "issuer_encap_key_seed", "issuer_encap_key", "token_type", "token_key_id", "blinded_msg", "request_key", "issuer_encap_key_id", "encrypted_token_request"
    ]
    format_vector(ordered_keys, sys.argv[1])

if "anon-origin-id-test-vectors.json" in sys.argv[1]:
    ordered_keys = [
        "sk_sign", "pk_sign", "sk_origin", "request_blind", "request_key", "index_key", "anon_issuer_origin_id"
    ]
    format_vector(ordered_keys, sys.argv[1])

if "token-test-vectors" in sys.argv[1]:
    ordered_keys = [
        "token_type", "issuer_name", "redemption_context", "origin_info", "nonce", "token_key_id", "token_authenticator_input"
    ]
    format_vector(ordered_keys, sys.argv[1])
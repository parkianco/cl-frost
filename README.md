# cl-frost

FROST Threshold Schnorr Signatures (IETF draft-irtf-cfrg-frost-15) with **zero external dependencies**.

## Features

- **Threshold signatures**: t-of-n signing
- **Key generation**: Distributed key generation (DKG)
- **Signing rounds**: Two-round signing protocol
- **Secp256k1**: Bitcoin/Ethereum compatible
- **Ed25519**: Edwards curve variant
- **Pure Common Lisp**: No CFFI, no external libraries

## Installation

```lisp
(asdf:load-system :cl-frost)
```

## Quick Start

```lisp
(use-package :cl-frost)

;; Distributed key generation (2-of-3)
(multiple-value-bind (secret-shares group-public-key)
    (frost-keygen :threshold 2 :participants 3)
  ;; Round 1: Generate commitments
  (let ((commitments (mapcar #'frost-sign-round1 '(share-1 share-2))))
    ;; Round 2: Generate signature shares
    (let ((sig-shares (mapcar (lambda (share commitment)
                                (frost-sign-round2 share message commitment))
                              '(share-1 share-2)
                              commitments)))
      ;; Aggregate signature
      (frost-aggregate sig-shares commitments))))
```

## API Reference

### Key Generation

- `(frost-keygen &key threshold participants)` - Generate shares
- `(frost-derive-public-key share)` - Get participant public key

### Signing

- `(frost-sign-round1 share)` - Generate commitment
- `(frost-sign-round2 share message commitments)` - Generate signature share
- `(frost-aggregate sig-shares commitments)` - Aggregate to final signature

### Verification

- `(frost-verify message signature group-public-key)` - Verify signature

## Testing

```lisp
(asdf:test-system :cl-frost)
```

## License

BSD-3-Clause

Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.

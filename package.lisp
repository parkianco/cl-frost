;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; package.lisp - Package definitions for cl-frost
;;;;
;;;; FROST Threshold Schnorr Signatures
;;;; IETF draft-irtf-cfrg-frost-15 compliant

(defpackage #:cl-frost
  (:use #:cl)
  (:nicknames #:frost)
  (:documentation "FROST Threshold Schnorr Signatures.

Implements FROST (Flexible Round-Optimized Schnorr Threshold) signature scheme
per IETF draft-irtf-cfrg-frost-15. FROST enables t-of-n threshold Schnorr
signatures with only 2 communication rounds.

Key Features:
- 2-round signing protocol (commitment + signing)
- BIP340 Schnorr signature compatibility
- Taproot (BIP341) spending support
- Identifiable abort for malicious signer detection
- Proactive security with nonce preprocessing

Protocol Overview:
1. Key Generation (DKG or Trusted Dealer):
   - Generate shares (x_i) and group public key (Y)
   - Each party stores share and verification data

2. Signing Round 1 (Commitment):
   - Each signer generates hiding (d_i) and binding (e_i) nonces
   - Broadcast commitments: D_i = d_i*G, E_i = e_i*G

3. Signing Round 2 (Response):
   - Compute binding factors: rho_i = H(i, msg, commitments)
   - Compute group commitment: R = sum(D_i + rho_i * E_i)
   - Compute challenge: c = H(R, Y, msg)
   - Compute partial signature: z_i = d_i + (e_i * rho_i) + (lambda_i * x_i * c)

4. Aggregation:
   - Sum partial signatures: z = sum(z_i)
   - Final signature: (R, z) - BIP340 compatible")
  (:export
   ;; =========================================================================
   ;; Version & Constants
   ;; =========================================================================
   #:+frost-version+
   #:+frost-ciphersuite+
   #:+secp256k1-p+
   #:+secp256k1-n+
   #:+secp256k1-gx+
   #:+secp256k1-gy+

   ;; =========================================================================
   ;; Types - Share
   ;; =========================================================================
   #:share
   #:make-share
   #:share-index
   #:share-value
   #:copy-share

   ;; =========================================================================
   ;; Types - Threshold Key
   ;; =========================================================================
   #:threshold-key
   #:make-threshold-key
   #:threshold-key-id
   #:threshold-key-group-pubkey
   #:threshold-key-threshold
   #:threshold-key-total-parties
   #:threshold-key-my-index
   #:threshold-key-my-share
   #:threshold-key-verification-vector
   #:threshold-key-party-pubkeys
   #:copy-threshold-key

   ;; =========================================================================
   ;; Types - Nonce
   ;; =========================================================================
   #:frost-nonce
   #:make-frost-nonce
   #:frost-nonce-hiding
   #:frost-nonce-binding
   #:frost-nonce-hiding-commitment
   #:frost-nonce-binding-commitment
   #:frost-nonce-signer-index
   #:copy-frost-nonce

   ;; =========================================================================
   ;; Types - Commitment
   ;; =========================================================================
   #:frost-commitment
   #:make-frost-commitment
   #:frost-commitment-signer-index
   #:frost-commitment-hiding
   #:frost-commitment-binding
   #:copy-frost-commitment

   ;; =========================================================================
   ;; Types - Partial Signature
   ;; =========================================================================
   #:frost-partial-signature
   #:make-frost-partial-signature
   #:frost-partial-signature-signer-index
   #:frost-partial-signature-z
   #:copy-frost-partial-signature

   ;; =========================================================================
   ;; Types - Signature
   ;; =========================================================================
   #:frost-signature
   #:make-frost-signature
   #:frost-signature-r
   #:frost-signature-s
   #:frost-signature-signer-set
   #:copy-frost-signature

   ;; =========================================================================
   ;; Types - Signing Session
   ;; =========================================================================
   #:frost-signing-session
   #:make-frost-signing-session
   #:frost-signing-session-id
   #:frost-signing-session-message
   #:frost-signing-session-signer-set
   #:frost-signing-session-state
   #:copy-frost-signing-session

   ;; =========================================================================
   ;; Conditions
   ;; =========================================================================
   #:frost-error
   #:frost-verification-error
   #:frost-quorum-error

   ;; =========================================================================
   ;; Key Generation
   ;; =========================================================================
   #:frost-keygen-trusted-dealer
   #:frost-keygen-verify-share
   #:frost-keygen-derive-public
   #:frost-reconstruct-secret

   ;; =========================================================================
   ;; Polynomial Operations
   ;; =========================================================================
   #:generate-random-polynomial
   #:evaluate-polynomial
   #:polynomial-commitment-vector
   #:verify-polynomial-commitment

   ;; =========================================================================
   ;; Lagrange Interpolation
   ;; =========================================================================
   #:lagrange-coefficient
   #:lagrange-coefficients-for-set

   ;; =========================================================================
   ;; Nonce Management
   ;; =========================================================================
   #:frost-nonce-generate
   #:frost-nonce-commit
   #:frost-nonce-preprocess

   ;; =========================================================================
   ;; Signing Protocol
   ;; =========================================================================
   #:frost-sign-begin
   #:frost-sign-commit
   #:frost-sign-collect-commitments
   #:frost-sign-compute-binding-factors
   #:frost-sign-compute-group-commitment
   #:frost-sign-compute-challenge
   #:frost-sign-generate-partial
   #:frost-sign-verify-partial
   #:frost-sign-complete-round1
   #:frost-sign-complete-round2

   ;; =========================================================================
   ;; Aggregation
   ;; =========================================================================
   #:frost-aggregate-collect-partials
   #:frost-aggregate-signatures
   #:frost-finalize-signature
   #:frost-session-finalize

   ;; =========================================================================
   ;; Verification
   ;; =========================================================================
   #:frost-verify
   #:frost-verify-share
   #:frost-verify-commitment
   #:frost-verify-message
   #:frost-batch-verify

   ;; =========================================================================
   ;; BIP340 Compatibility
   ;; =========================================================================
   #:frost-to-bip340-signature
   #:frost-from-bip340-pubkey
   #:frost-to-bip340-pubkey
   #:frost-apply-taproot-tweak

   ;; =========================================================================
   ;; High-Level API
   ;; =========================================================================
   #:frost-sign-message
   #:frost-sign-transaction
   #:frost-verify-transaction

   ;; =========================================================================
   ;; Serialization
   ;; =========================================================================
   #:serialize-commitment
   #:deserialize-commitment
   #:serialize-partial-signature
   #:deserialize-partial-signature
   #:serialize-signature
   #:deserialize-signature

   ;; =========================================================================
   ;; Utility
   ;; =========================================================================
   #:scalar-to-bytes
   #:bytes-to-scalar
   #:random-scalar
   #:sha256

   ;; =========================================================================
   ;; Testing
   ;; =========================================================================
   #:frost-run-protocol-test
   #:frost-keygen-test))

(defpackage #:cl-frost.test
  (:use #:cl #:cl-frost)
  (:export #:run-all-tests))

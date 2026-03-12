;;;; cl-frost.asd - FROST Threshold Schnorr Signatures
;;;;
;;;; FROST (Flexible Round-Optimized Schnorr Threshold) signature scheme
;;;; implementing IETF draft-irtf-cfrg-frost-15.
;;;;
;;;; Features:
;;;; - 2-round signing protocol (commitment + signing)
;;;; - BIP340 Schnorr signature compatibility
;;;; - Taproot (BIP341) spending support
;;;; - t-of-n threshold signing
;;;; - Identifiable abort for malicious signer detection
;;;;
;;;; Zero external dependencies - pure Common Lisp + SBCL.

(asdf:defsystem #:cl-frost
  :name "cl-frost"
  :version "1.0.0"
  :author "Parkian Company LLC"
  :license "MIT"
  :description "FROST Threshold Schnorr Signatures (IETF draft-irtf-cfrg-frost-15)"
  :long-description "Standalone implementation of FROST threshold signature scheme
for secp256k1/BIP340. Enables t-of-n threshold Schnorr signatures with only 2
communication rounds, producing signatures indistinguishable from single-signer
Schnorr (BIP340 compatible). Zero external dependencies."
  :depends-on ()
  :serial t
  :components
  ((:file "package")
   (:module "src"
    :serial t
    :components
    ((:file "util")
     (:file "field")
     (:file "schnorr")
     (:file "keygen")
     (:file "signing")
     )))
  :in-order-to ((test-op (test-op #:cl-frost/test))))

(asdf:defsystem #:cl-frost/test
  :name "cl-frost-test"
  :version "1.0.0"
  :description "Tests for cl-frost"
  :depends-on (#:cl-frost)
  :serial t
  :components
  ((:module "test"
    :components
    ((:file "test-frost"))))
  :perform (test-op (op c)
             (let ((result (uiop:symbol-call :cl-frost.test :run-all-tests)))
               (unless result
                 (error "Tests failed")))))

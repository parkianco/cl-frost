;;;; schnorr.lisp - Schnorr/BIP340 Signature Primitives for cl-frost
;;;;
;;;; Provides:
;;;; - BIP340 Schnorr signature verification
;;;; - Tagged hashing (BIP340 style)
;;;; - Multi-scalar multiplication

(in-package #:cl-frost)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;;; ============================================================================
;;;; Tagged Hash Constants (BIP340 style domain separation)
;;;; ============================================================================

(defparameter +bip340-challenge-tag+
  (let ((tag (sha256 (string-to-octets "BIP0340/challenge"))))
    tag)
  "BIP340 challenge tag (SHA256 of 'BIP0340/challenge').")

(defparameter +frost-binding-tag+
  (let ((tag (sha256 (string-to-octets "FROST/binding"))))
    tag)
  "FROST binding factor tag.")

(defparameter +frost-nonce-tag+
  (let ((tag (sha256 (string-to-octets "FROST/nonce"))))
    tag)
  "FROST nonce generation tag.")

;;;; ============================================================================
;;;; Tagged Hashing
;;;; ============================================================================

(defun tagged-hash (tag &rest data)
  "Compute BIP340-style tagged hash: H(tag || tag || data...).

   PARAMETERS:
   - TAG: 32-byte tag (typically SHA256 of tag string)
   - DATA: Byte vectors to concatenate and hash

   RETURN:
   32-byte hash"
  (declare (type (vector (unsigned-byte 8)) tag))
  (let* ((total-len (+ 64 (reduce #'+ data :key #'length)))
         (input (make-array total-len :element-type '(unsigned-byte 8)))
         (pos 0))
    ;; Prepend tag twice
    (replace input tag)
    (replace input tag :start1 32)
    (setf pos 64)
    ;; Append data
    (dolist (d data)
      (replace input d :start1 pos)
      (incf pos (length d)))
    (sha256 input)))

;;;; ============================================================================
;;;; BIP340 Verification
;;;; ============================================================================

(defun bip340-verify (pubkey message signature)
  "BIP340 Schnorr signature verification.

   PARAMETERS:
   - PUBKEY: 32-byte x-only public key
   - MESSAGE: 32-byte message hash
   - SIGNATURE: 64-byte signature (r || s)

   RETURN:
   T if valid, NIL otherwise

   Algorithm:
   1. Let P = lift_x(pubkey)
   2. Let r = int(sig[0:32]), s = int(sig[32:64])
   3. Fail if r >= p or s >= n
   4. Let e = H(tag || tag || r || P_x || msg) mod n
   5. Let R = s*G - e*P
   6. Fail if R is infinity or R.y is odd or R.x != r
   7. Return success"
  (declare (type (vector (unsigned-byte 8)) pubkey message signature)
           (optimize (speed 3) (safety 1)))
  (handler-case
      (progn
        ;; Validate lengths
        (unless (and (= (length pubkey) 32)
                     (= (length message) 32)
                     (= (length signature) 64))
          (return-from bip340-verify nil))

        ;; Extract signature components
        (let* ((r-bytes (subseq signature 0 32))
               (s-bytes (subseq signature 32 64))
               (r (bytes-to-scalar r-bytes))
               (s (bytes-to-scalar s-bytes)))

          ;; Range checks
          (unless (and (< r +secp256k1-p+) (< s +secp256k1-n+))
            (return-from bip340-verify nil))

          ;; Lift the public key
          (multiple-value-bind (px py) (lift-x pubkey)
            (unless px
              (return-from bip340-verify nil))

            ;; Compute challenge: e = H(tag || tag || r || P_x || msg) mod n
            (let* ((challenge-input (concatenate '(vector (unsigned-byte 8))
                                                  +bip340-challenge-tag+
                                                  +bip340-challenge-tag+
                                                  r-bytes
                                                  pubkey
                                                  message))
                   (challenge-hash (sha256 challenge-input))
                   (e (scalar-mod (bytes-to-scalar challenge-hash)))
                   (neg-e (scalar-negate e)))

              ;; Compute R = s*G + (-e)*P
              (multiple-value-bind (rx ry)
                  (ec-multi-scalar-mul s neg-e px py)
                ;; Verification checks:
                ;; 1. R is not at infinity
                ;; 2. R.y is even
                ;; 3. R.x == r
                (and (not (and (zerop rx) (zerop ry)))
                     (evenp ry)
                     (= rx r)))))))
    (error () nil)))

;;;; ============================================================================
;;;; Multi-Scalar Multiplication
;;;; ============================================================================

(defun ec-multi-scalar-mul (a b px py)
  "Compute a*G + b*P using Shamir's trick.

   PARAMETERS:
   - A: Scalar multiplier for generator G
   - B: Scalar multiplier for point P
   - PX, PY: Coordinates of point P

   RETURN:
   (VALUES rx ry) - coordinates of result"
  (declare (type integer a b px py)
           (optimize (speed 3) (safety 1)))
  ;; Compute a*G
  (multiple-value-bind (agx agy)
      (ec-scalar-multiply (scalar-mod a) +secp256k1-gx+ +secp256k1-gy+)
    ;; Compute b*P
    (multiple-value-bind (bpx bpy)
        (ec-scalar-multiply (scalar-mod b) px py)
      ;; Add the results
      (ec-point-add agx agy bpx bpy))))

;;;; ============================================================================
;;;; BIP340 Key Compatibility
;;;; ============================================================================

(defun frost-from-bip340-pubkey (x-only-pubkey)
  "Convert a BIP340 x-only public key to compressed format.

   PARAMETERS:
   - X-ONLY-PUBKEY: 32-byte x-only public key

   RETURN:
   33-byte compressed public key with even y"
  (declare (type (vector (unsigned-byte 8)) x-only-pubkey)
           (optimize (speed 3) (safety 1)))
  ;; Add 0x02 prefix (even y per BIP340)
  (concatenate '(vector (unsigned-byte 8))
               (vector #x02)
               x-only-pubkey))

(defun frost-to-bip340-pubkey (compressed-pubkey)
  "Convert a compressed public key to BIP340 x-only format.

   PARAMETERS:
   - COMPRESSED-PUBKEY: 33-byte compressed public key

   RETURN:
   32-byte x-only public key

   Note: If the y-coordinate is odd, the corresponding private key
   should be negated for signing."
  (declare (type (vector (unsigned-byte 8)) compressed-pubkey)
           (optimize (speed 3) (safety 1)))
  (subseq compressed-pubkey 1 33))

;;;; ============================================================================
;;;; Taproot Integration
;;;; ============================================================================

(defun frost-apply-taproot-tweak (group-pubkey tweak)
  "Apply Taproot tweak to a FROST group public key.

   PARAMETERS:
   - GROUP-PUBKEY: 33-byte compressed group public key
   - TWEAK: 32-byte tweak (typically taproot merkle root)

   RETURN:
   (VALUES tweaked-pubkey parity) where:
   - TWEAKED-PUBKEY: 33-byte tweaked public key
   - PARITY: 0 if y is even, 1 if odd

   Algorithm:
   P' = P + t*G where t = H('TapTweak' || P_x || tweak)"
  (declare (type (vector (unsigned-byte 8)) group-pubkey tweak)
           (optimize (speed 3) (safety 1)))
  (let* ((x-only (subseq group-pubkey 1 33))
         ;; Compute taptweak: t = H('TapTweak' || P_x || merkle_root)
         (tweak-tag (sha256 (string-to-octets "TapTweak")))
         (tweak-input (concatenate '(vector (unsigned-byte 8))
                                    tweak-tag tweak-tag
                                    x-only tweak))
         (t-scalar (bytes-to-scalar (sha256 tweak-input))))

    ;; Compute t*G
    (multiple-value-bind (t-point-x t-point-y)
        (ec-scalar-multiply t-scalar +secp256k1-gx+ +secp256k1-gy+)

      ;; Compute P + t*G
      (multiple-value-bind (px py) (decompress-point group-pubkey)
        (multiple-value-bind (rx ry)
            (ec-point-add px py t-point-x t-point-y)
          (let ((tweaked (compress-point rx ry))
                (parity (if (evenp ry) 0 1)))
            (values tweaked parity)))))))

;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; field.lisp - secp256k1 Field Arithmetic for cl-frost
;;;;
;;;; Provides:
;;;; - secp256k1 curve constants
;;;; - Modular arithmetic (scalar field)
;;;; - EC point operations (add, multiply)
;;;; - Point compression/decompression

(in-package #:cl-frost)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;;; ============================================================================
;;;; secp256k1 Curve Constants
;;;; ============================================================================

;; Field modulus p = 2^256 - 2^32 - 977
(defconstant +secp256k1-p+
  (if (boundp '+secp256k1-p+)
      (symbol-value '+secp256k1-p+)
      #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
  "secp256k1 field modulus p.")

;; Group order n
(defconstant +secp256k1-n+
  (if (boundp '+secp256k1-n+)
      (symbol-value '+secp256k1-n+)
      #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
  "secp256k1 group order n.")

;; Generator point G coordinates
(defconstant +secp256k1-gx+
  (if (boundp '+secp256k1-gx+)
      (symbol-value '+secp256k1-gx+)
      #x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798)
  "secp256k1 generator x-coordinate.")

(defconstant +secp256k1-gy+
  (if (boundp '+secp256k1-gy+)
      (symbol-value '+secp256k1-gy+)
      #x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
  "secp256k1 generator y-coordinate.")

;;;; ============================================================================
;;;; Scalar Field Arithmetic (mod n)
;;;; ============================================================================

(declaim (inline scalar-mod scalar-add scalar-mul scalar-negate scalar-invert))

(defun scalar-mod (x)
  "Reduce X modulo the group order n."
  (declare (type integer x)
           (optimize (speed 3) (safety 0)))
  (mod x +secp256k1-n+))

(defun scalar-add (a b)
  "Add two scalars modulo n."
  (declare (type integer a b)
           (optimize (speed 3) (safety 0)))
  (mod (+ a b) +secp256k1-n+))

(defun scalar-mul (a b)
  "Multiply two scalars modulo n."
  (declare (type integer a b)
           (optimize (speed 3) (safety 0)))
  (mod (* a b) +secp256k1-n+))

(defun scalar-negate (x)
  "Negate scalar modulo n."
  (declare (type integer x)
           (optimize (speed 3) (safety 0)))
  (mod (- +secp256k1-n+ x) +secp256k1-n+))

(defun mod-expt (base exp modulus)
  "Compute BASE^EXP mod MODULUS using binary exponentiation."
  (declare (type integer base exp modulus)
           (optimize (speed 3) (safety 0)))
  (let ((result 1)
        (b (mod base modulus)))
    (loop while (plusp exp) do
      (when (oddp exp)
        (setf result (mod (* result b) modulus)))
      (setf b (mod (* b b) modulus))
      (setf exp (ash exp -1)))
    result))

(defun scalar-invert (x)
  "Compute modular inverse of X mod n using Fermat's little theorem.
   x^(-1) = x^(n-2) mod n"
  (declare (type integer x)
           (optimize (speed 3) (safety 0)))
  (when (zerop (mod x +secp256k1-n+))
    (error 'frost-error :message "Cannot invert zero"))
  (mod-expt x (- +secp256k1-n+ 2) +secp256k1-n+))

;;;; ============================================================================
;;;; Field Arithmetic (mod p)
;;;; ============================================================================

(declaim (inline field-mod field-add field-sub field-mul field-invert))

(defun field-mod (x)
  "Reduce X modulo field prime p."
  (declare (type integer x)
           (optimize (speed 3) (safety 0)))
  (mod x +secp256k1-p+))

(defun field-add (a b)
  "Add two field elements mod p."
  (declare (type integer a b)
           (optimize (speed 3) (safety 0)))
  (mod (+ a b) +secp256k1-p+))

(defun field-sub (a b)
  "Subtract two field elements mod p."
  (declare (type integer a b)
           (optimize (speed 3) (safety 0)))
  (mod (- a b) +secp256k1-p+))

(defun field-mul (a b)
  "Multiply two field elements mod p."
  (declare (type integer a b)
           (optimize (speed 3) (safety 0)))
  (mod (* a b) +secp256k1-p+))

(defun field-invert (x)
  "Compute modular inverse of X mod p."
  (declare (type integer x)
           (optimize (speed 3) (safety 0)))
  (when (zerop (mod x +secp256k1-p+))
    (error 'frost-error :message "Cannot invert zero"))
  (mod-expt x (- +secp256k1-p+ 2) +secp256k1-p+))

;;;; ============================================================================
;;;; EC Point Operations
;;;; ============================================================================

(defun ec-point-add (p1x p1y p2x p2y)
  "Add two EC points on secp256k1.

   Returns (VALUES rx ry) for the sum P1 + P2.
   Handles point at infinity (represented as (0, 0))."
  (declare (type integer p1x p1y p2x p2y)
           (optimize (speed 3) (safety 1)))
  ;; Point at infinity checks
  (when (and (zerop p1x) (zerop p1y))
    (return-from ec-point-add (values p2x p2y)))
  (when (and (zerop p2x) (zerop p2y))
    (return-from ec-point-add (values p1x p1y)))

  ;; Check for inverse points (P + (-P) = O)
  (when (and (= p1x p2x) (= (field-add p1y p2y) 0))
    (return-from ec-point-add (values 0 0)))

  ;; Compute slope
  (let ((s (if (and (= p1x p2x) (= p1y p2y))
               ;; Point doubling: s = (3*x^2) / (2*y)
               (let ((num (field-mul 3 (field-mul p1x p1x)))
                     (den (field-mul 2 p1y)))
                 (field-mul num (field-invert den)))
               ;; Point addition: s = (y2 - y1) / (x2 - x1)
               (let ((num (field-sub p2y p1y))
                     (den (field-sub p2x p1x)))
                 (field-mul num (field-invert den))))))
    ;; x3 = s^2 - x1 - x2
    (let* ((s2 (field-mul s s))
           (x3 (field-sub (field-sub s2 p1x) p2x))
           ;; y3 = s*(x1 - x3) - y1
           (y3 (field-sub (field-mul s (field-sub p1x x3)) p1y)))
      (values x3 y3))))

(defun ec-point-double (px py)
  "Double an EC point on secp256k1.

   Returns (VALUES rx ry) for 2*P."
  (declare (type integer px py)
           (optimize (speed 3) (safety 1)))
  (ec-point-add px py px py))

(defun ec-scalar-multiply (k px py)
  "Multiply EC point by scalar using double-and-add.

   Returns (VALUES rx ry) for k*P.

   NOTE: This is a simple implementation. For production use,
   constant-time Montgomery ladder would be preferred."
  (declare (type integer k px py)
           (optimize (speed 3) (safety 1)))
  (when (zerop k)
    (return-from ec-scalar-multiply (values 0 0)))

  (let ((k (mod k +secp256k1-n+))
        (rx 0) (ry 0)
        (qx px) (qy py))
    ;; Double-and-add
    (loop while (plusp k) do
      (when (oddp k)
        (multiple-value-setq (rx ry) (ec-point-add rx ry qx qy)))
      (multiple-value-setq (qx qy) (ec-point-double qx qy))
      (setf k (ash k -1)))
    (values rx ry)))

;;;; ============================================================================
;;;; Point Compression/Decompression
;;;; ============================================================================

(defun compress-point (x y)
  "Compress EC point (x, y) to 33-byte format.

   Returns 33-byte vector: [prefix | x-coordinate]
   where prefix is 0x02 (even y) or 0x03 (odd y)."
  (declare (type integer x y)
           (optimize (speed 3) (safety 1)))
  (let ((result (make-array 33 :element-type '(unsigned-byte 8))))
    (setf (aref result 0) (if (evenp y) #x02 #x03))
    (let ((x-bytes (scalar-to-bytes x 32)))
      (replace result x-bytes :start1 1))
    result))

(defun decompress-point (compressed)
  "Decompress 33-byte point to (x, y) coordinates.

   Returns (VALUES x y) as integers."
  (declare (type (vector (unsigned-byte 8)) compressed)
           (optimize (speed 3) (safety 1)))
  (unless (= (length compressed) 33)
    (error 'frost-error :message "Invalid compressed point length"))
  (let* ((prefix (aref compressed 0))
         (x (bytes-to-scalar (subseq compressed 1 33))))
    (unless (member prefix '(#x02 #x03))
      (error 'frost-error :message "Invalid point prefix"))
    ;; y^2 = x^3 + 7 (mod p)
    (let* ((x3 (mod-expt x 3 +secp256k1-p+))
           (y2 (mod (+ x3 7) +secp256k1-p+))
           ;; Square root: y = y2^((p+1)/4) for p = 3 (mod 4)
           (y (mod-expt y2 (ash (1+ +secp256k1-p+) -2) +secp256k1-p+)))
      ;; Choose correct y based on parity
      (when (not (eql (oddp y) (= prefix #x03)))
        (setf y (- +secp256k1-p+ y)))
      (values x y))))

(defun point-equal-p (p1 p2)
  "Check if two compressed points are equal."
  (declare (type (vector (unsigned-byte 8)) p1 p2))
  (and (= (length p1) (length p2) 33)
       (constant-time-bytes= p1 p2)))

(defun make-point-at-infinity ()
  "Return representation of the point at infinity."
  (make-array 33 :element-type '(unsigned-byte 8) :initial-element 0))

(defun point-at-infinity-p (point)
  "Check if point is the point at infinity."
  (declare (type (vector (unsigned-byte 8)) point))
  (every #'zerop point))

;;;; ============================================================================
;;;; Generator Point Operations
;;;; ============================================================================

(defun scalar-multiply-generator (scalar)
  "Multiply the secp256k1 generator G by scalar.

   Returns 33-byte compressed public key."
  (declare (type integer scalar)
           (optimize (speed 3) (safety 1)))
  (let ((s (scalar-mod scalar)))
    (when (zerop s)
      (error 'frost-error :message "Cannot multiply generator by zero"))
    (multiple-value-bind (x y)
        (ec-scalar-multiply s +secp256k1-gx+ +secp256k1-gy+)
      (compress-point x y))))

(defun scalar-multiply-point (scalar point)
  "Multiply an EC point by scalar.

   PARAMETERS:
   - SCALAR: Integer scalar
   - POINT: 33-byte compressed point

   RETURN:
   33-byte compressed point"
  (declare (type integer scalar)
           (type (vector (unsigned-byte 8)) point)
           (optimize (speed 3) (safety 1)))
  (let ((s (scalar-mod scalar)))
    (when (zerop s)
      (return-from scalar-multiply-point (make-point-at-infinity)))
    (multiple-value-bind (px py) (decompress-point point)
      (multiple-value-bind (rx ry)
          (ec-scalar-multiply s px py)
        (compress-point rx ry)))))

(defun point-add (p1 p2)
  "Add two compressed EC points.

   Returns 33-byte compressed point (P1 + P2)."
  (declare (type (vector (unsigned-byte 8)) p1 p2)
           (optimize (speed 3) (safety 1)))
  (multiple-value-bind (p1x p1y) (decompress-point p1)
    (multiple-value-bind (p2x p2y) (decompress-point p2)
      (multiple-value-bind (rx ry)
          (ec-point-add p1x p1y p2x p2y)
        (compress-point rx ry)))))

;;;; ============================================================================
;;;; BIP340 Lift-x Operation
;;;; ============================================================================

(defun lift-x (x-only-bytes)
  "Lift an x-only public key to a full EC point.

   Returns (VALUES x y) if valid, (VALUES NIL NIL) if not on curve.
   Chooses even y per BIP340 convention."
  (declare (type (vector (unsigned-byte 8)) x-only-bytes)
           (optimize (speed 3) (safety 1)))
  (let ((x (bytes-to-scalar x-only-bytes)))
    ;; Check x is in valid range
    (when (or (<= x 0) (>= x +secp256k1-p+))
      (return-from lift-x (values nil nil)))
    ;; y^2 = x^3 + 7 (mod p)
    (let* ((x3 (mod-expt x 3 +secp256k1-p+))
           (y2 (mod (+ x3 7) +secp256k1-p+))
           (y (mod-expt y2 (ash (1+ +secp256k1-p+) -2) +secp256k1-p+)))
      ;; Verify y^2 = x^3 + 7 (point is on curve)
      (unless (= (mod (* y y) +secp256k1-p+) y2)
        (return-from lift-x (values nil nil)))
      ;; Choose even y (BIP340 convention)
      (when (oddp y)
        (setf y (- +secp256k1-p+ y)))
      (values x y))))

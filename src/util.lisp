;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; util.lisp - Utility functions for cl-frost
;;;;
;;;; Provides:
;;;; - Byte/scalar conversion
;;;; - Cryptographic random number generation
;;;; - SHA-256 hashing (pure CL implementation)
;;;; - Thread-safe session ID generation

(in-package #:cl-frost)

;;;; ============================================================================
;;;; Version Constants
;;;; ============================================================================

(defconstant +frost-version+
  (if (boundp '+frost-version+) (symbol-value '+frost-version+) "1.0.0")
  "FROST implementation version.")

(defparameter +frost-ciphersuite+ "FROST-secp256k1-SHA256-v1"
  "Ciphersuite identifier per FROST specification.")

;;;; ============================================================================
;;;; Byte/Scalar Conversion
;;;; ============================================================================

(defun scalar-to-bytes (scalar &optional (length 32))
  "Convert integer SCALAR to big-endian byte vector of LENGTH bytes."
  (declare (type integer scalar)
           (type fixnum length)
           (optimize (speed 3) (safety 1)))
  (let ((result (make-array length :element-type '(unsigned-byte 8) :initial-element 0)))
    (loop for i from (1- length) downto 0
          for s = scalar then (ash s -8)
          do (setf (aref result i) (logand s #xff)))
    result))

(defun bytes-to-scalar (bytes)
  "Convert big-endian byte vector BYTES to integer."
  (declare (type (vector (unsigned-byte 8)) bytes)
           (optimize (speed 3) (safety 1)))
  (let ((result 0))
    (loop for byte across bytes
          do (setf result (logior (ash result 8) byte)))
    result))

;;;; ============================================================================
;;;; String/Bytes Conversion
;;;; ============================================================================

(defun string-to-octets (string &key (encoding :utf-8))
  "Convert STRING to UTF-8 byte vector."
  (declare (ignore encoding))
  (let* ((len (length string))
         (result (make-array (* len 4)
                             :element-type '(unsigned-byte 8)
                             :fill-pointer 0
                             :adjustable t)))
    (loop for char across string
          for code = (char-code char)
          do (cond
               ((< code #x80)
                (vector-push-extend code result))
               ((< code #x800)
                (vector-push-extend (logior #xc0 (ash code -6)) result)
                (vector-push-extend (logior #x80 (logand code #x3f)) result))
               ((< code #x10000)
                (vector-push-extend (logior #xe0 (ash code -12)) result)
                (vector-push-extend (logior #x80 (logand (ash code -6) #x3f)) result)
                (vector-push-extend (logior #x80 (logand code #x3f)) result))
               (t
                (vector-push-extend (logior #xf0 (ash code -18)) result)
                (vector-push-extend (logior #x80 (logand (ash code -12) #x3f)) result)
                (vector-push-extend (logior #x80 (logand (ash code -6) #x3f)) result)
                (vector-push-extend (logior #x80 (logand code #x3f)) result))))
    (let ((final (make-array (length result) :element-type '(unsigned-byte 8))))
      (replace final result)
      final)))

;;;; ============================================================================
;;;; Cryptographic Random
;;;; ============================================================================

(defun get-random-bytes (count)
  "Generate COUNT cryptographically secure random bytes.
   Uses /dev/urandom on Unix, sb-ext:random on Windows."
  (declare (type fixnum count)
           (optimize (speed 3) (safety 1)))
  (let ((result (make-array count :element-type '(unsigned-byte 8))))
    #+sbcl
    (handler-case
        (with-open-file (f "/dev/urandom" :element-type '(unsigned-byte 8))
          (read-sequence result f))
      (error ()
        ;; Fallback for Windows or if /dev/urandom unavailable
        (loop for i below count
              do (setf (aref result i) (random 256)))))
    #-sbcl
    (loop for i below count
          do (setf (aref result i) (random 256)))
    result))

(defun random-scalar ()
  "Generate a random scalar in the range [1, n-1] for secp256k1."
  (let ((bytes (get-random-bytes 32))
        (n +secp256k1-n+))
    (let ((scalar (mod (bytes-to-scalar bytes) (1- n))))
      (if (zerop scalar)
          (1+ scalar)
          scalar))))

;;;; ============================================================================
;;;; SHA-256 Implementation (Pure CL)
;;;; ============================================================================

(defvar *sha256-k*
  (make-array 64 :element-type '(unsigned-byte 32)
              :initial-contents
              '(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5
                #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
                #xd807aa98 #x12835b01 #x243185be #x550c7dc3
                #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
                #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc
                #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
                #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7
                #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
                #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13
                #x650a7354 #x766a0abb #x81c2c92e #x92722c85
                #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3
                #xd192e819 #xd6990624 #xf40e3585 #x106aa070
                #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5
                #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
                #x748f82ee #x78a5636f #x84c87814 #x8cc70208
                #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2))
  "SHA-256 round constants.")

(defvar *sha256-h0*
  (make-array 8 :element-type '(unsigned-byte 32)
              :initial-contents
              '(#x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a
                #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19))
  "SHA-256 initial hash values.")

(declaim (inline sha256-rotr sha256-ch sha256-maj sha256-sigma0 sha256-sigma1
                 sha256-big-sigma0 sha256-big-sigma1 sha256-u32+))

(defun sha256-rotr (x n)
  "Right rotate 32-bit value X by N bits."
  (declare (type (unsigned-byte 32) x)
           (type (integer 0 31) n)
           (optimize (speed 3) (safety 0)))
  (logior (ash x (- n))
          (logand #xffffffff (ash x (- 32 n)))))

(defun sha256-ch (x y z)
  (declare (type (unsigned-byte 32) x y z)
           (optimize (speed 3) (safety 0)))
  (logxor (logand x y) (logand (lognot x) z)))

(defun sha256-maj (x y z)
  (declare (type (unsigned-byte 32) x y z)
           (optimize (speed 3) (safety 0)))
  (logxor (logand x y) (logand x z) (logand y z)))

(defun sha256-big-sigma0 (x)
  (declare (type (unsigned-byte 32) x)
           (optimize (speed 3) (safety 0)))
  (logxor (sha256-rotr x 2) (sha256-rotr x 13) (sha256-rotr x 22)))

(defun sha256-big-sigma1 (x)
  (declare (type (unsigned-byte 32) x)
           (optimize (speed 3) (safety 0)))
  (logxor (sha256-rotr x 6) (sha256-rotr x 11) (sha256-rotr x 25)))

(defun sha256-sigma0 (x)
  (declare (type (unsigned-byte 32) x)
           (optimize (speed 3) (safety 0)))
  (logxor (sha256-rotr x 7) (sha256-rotr x 18) (ash x -3)))

(defun sha256-sigma1 (x)
  (declare (type (unsigned-byte 32) x)
           (optimize (speed 3) (safety 0)))
  (logxor (sha256-rotr x 17) (sha256-rotr x 19) (ash x -10)))

(defun sha256-u32+ (&rest args)
  "Add 32-bit values with wrap-around."
  (declare (optimize (speed 3) (safety 0)))
  (logand #xffffffff (apply #'+ args)))

(defun sha256-pad-message (message)
  "Pad message for SHA-256 processing."
  (let* ((len (length message))
         (bit-len (* len 8))
         (padded-len (+ 64 (* 64 (floor (+ len 9) 64))))
         (padded (make-array padded-len :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace padded message)
    (setf (aref padded len) #x80)
    ;; Append length in bits (big-endian 64-bit)
    (loop for i from 0 below 8
          do (setf (aref padded (- padded-len 1 i))
                   (logand #xff (ash bit-len (- (* i 8))))))
    padded))

(defun sha256-process-block (block h)
  "Process one 64-byte block."
  (declare (type (simple-array (unsigned-byte 8) (64)) block)
           (type (simple-array (unsigned-byte 32) (8)) h)
           (optimize (speed 3) (safety 0)))
  (let ((w (make-array 64 :element-type '(unsigned-byte 32)))
        (a (aref h 0)) (b (aref h 1)) (c (aref h 2)) (d (aref h 3))
        (e (aref h 4)) (f (aref h 5)) (g (aref h 6)) (hh (aref h 7)))
    ;; Prepare message schedule
    (loop for i below 16
          for j = (* i 4)
          do (setf (aref w i)
                   (logior (ash (aref block j) 24)
                           (ash (aref block (1+ j)) 16)
                           (ash (aref block (+ j 2)) 8)
                           (aref block (+ j 3)))))
    (loop for i from 16 below 64
          do (setf (aref w i)
                   (sha256-u32+ (sha256-sigma1 (aref w (- i 2)))
                                (aref w (- i 7))
                                (sha256-sigma0 (aref w (- i 15)))
                                (aref w (- i 16)))))
    ;; Main compression loop
    (loop for i below 64
          for t1 = (sha256-u32+ hh (sha256-big-sigma1 e) (sha256-ch e f g)
                                (aref *sha256-k* i) (aref w i))
          for t2 = (sha256-u32+ (sha256-big-sigma0 a) (sha256-maj a b c))
          do (setf hh g
                   g f
                   f e
                   e (sha256-u32+ d t1)
                   d c
                   c b
                   b a
                   a (sha256-u32+ t1 t2)))
    ;; Update hash values
    (setf (aref h 0) (sha256-u32+ (aref h 0) a)
          (aref h 1) (sha256-u32+ (aref h 1) b)
          (aref h 2) (sha256-u32+ (aref h 2) c)
          (aref h 3) (sha256-u32+ (aref h 3) d)
          (aref h 4) (sha256-u32+ (aref h 4) e)
          (aref h 5) (sha256-u32+ (aref h 5) f)
          (aref h 6) (sha256-u32+ (aref h 6) g)
          (aref h 7) (sha256-u32+ (aref h 7) hh))))

(defun sha256 (message)
  "Compute SHA-256 hash of MESSAGE (byte vector or string).
   Returns 32-byte hash."
  (let* ((msg (etypecase message
                ((vector (unsigned-byte 8)) message)
                (string (string-to-octets message))))
         (padded (sha256-pad-message msg))
         (h (copy-seq *sha256-h0*)))
    ;; Process each 64-byte block
    (loop for offset from 0 below (length padded) by 64
          for block = (make-array 64 :element-type '(unsigned-byte 8))
          do (replace block padded :start2 offset :end2 (+ offset 64))
             (sha256-process-block block h))
    ;; Convert hash to bytes
    (let ((result (make-array 32 :element-type '(unsigned-byte 8))))
      (loop for i below 8
            for offset = (* i 4)
            for word = (aref h i)
            do (setf (aref result offset) (logand #xff (ash word -24))
                     (aref result (1+ offset)) (logand #xff (ash word -16))
                     (aref result (+ offset 2)) (logand #xff (ash word -8))
                     (aref result (+ offset 3)) (logand #xff word)))
      result)))

;;;; ============================================================================
;;;; Constant-Time Comparison
;;;; ============================================================================

(defun constant-time-bytes= (a b)
  "Constant-time comparison of two byte vectors.
   Returns T if equal, NIL otherwise."
  (declare (type (vector (unsigned-byte 8)) a b)
           (optimize (speed 3) (safety 0)))
  (when (/= (length a) (length b))
    (return-from constant-time-bytes= nil))
  (let ((diff 0))
    (loop for i below (length a)
          do (setf diff (logior diff (logxor (aref a i) (aref b i)))))
    (zerop diff)))

;;;; ============================================================================
;;;; Session ID Generation
;;;; ============================================================================

(defun session-id-generate ()
  "Generate a random 32-byte session ID."
  (get-random-bytes 32))

;;;; ============================================================================
;;;; Validation Utilities
;;;; ============================================================================

(defun validate-threshold-params (threshold total-parties)
  "Validate threshold parameters."
  (unless (and (integerp threshold) (plusp threshold))
    (error 'frost-error :message "Threshold must be positive integer"))
  (unless (and (integerp total-parties) (plusp total-parties))
    (error 'frost-error :message "Total parties must be positive integer"))
  (unless (<= threshold total-parties)
    (error 'frost-error :message "Threshold cannot exceed total parties"))
  (unless (<= total-parties 255)
    (error 'frost-error :message "Maximum 255 parties supported"))
  t)

(defun validate-party-set (party-indices threshold)
  "Validate that party set meets threshold requirements."
  (unless (>= (length party-indices) threshold)
    (error 'frost-quorum-error
           :message "Insufficient parties for threshold"))
  t)

;;;; ============================================================================
;;;; Error Conditions
;;;; ============================================================================

(define-condition frost-error (error)
  ((message :initarg :message :reader frost-error-message))
  (:report (lambda (c s)
             (format s "FROST error: ~A" (frost-error-message c)))))

(define-condition frost-verification-error (frost-error)
  ((expected :initarg :expected :reader frost-verification-expected)
   (actual :initarg :actual :reader frost-verification-actual))
  (:report (lambda (c s)
             (format s "FROST verification error: ~A (expected: ~A, got: ~A)"
                     (frost-error-message c)
                     (frost-verification-expected c)
                     (frost-verification-actual c)))))

(define-condition frost-quorum-error (frost-error)
  ((have :initarg :have :reader frost-quorum-have :initform nil)
   (need :initarg :need :reader frost-quorum-need :initform nil))
  (:report (lambda (c s)
             (format s "FROST quorum error: ~A~@[ (have: ~A, need: ~A)~]"
                     (frost-error-message c)
                     (frost-quorum-have c)
                     (frost-quorum-need c)))))

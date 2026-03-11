;;;; keygen.lisp - FROST Key Generation for cl-frost
;;;;
;;;; Provides:
;;;; - Trusted dealer key generation
;;;; - Polynomial secret sharing (Shamir)
;;;; - Feldman VSS commitment verification
;;;; - Lagrange interpolation
;;;; - Key share structures

(in-package #:cl-frost)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;;; ============================================================================
;;;; Share Structure
;;;; ============================================================================

(defstruct (share
            (:constructor %make-share)
            (:copier nil))
  "A secret share for threshold cryptography.

   SLOTS:
   - INDEX: Share index (1..n)
   - VALUE: Share value as scalar (integer mod n)"
  (index 0 :type (integer 0 255))
  (value 0 :type integer))

(defun make-share (&key index value)
  "Create a new share structure."
  (unless (and index (plusp index) (<= index 255))
    (error 'frost-error :message "Share index must be in range [1, 255]"))
  (unless value
    (error 'frost-error :message "Share value is required"))
  (%make-share :index index
               :value (scalar-mod value)))

(defun copy-share (share)
  "Create a copy of a share."
  (declare (type share share))
  (%make-share :index (share-index share)
               :value (share-value share)))

;;;; ============================================================================
;;;; Threshold Key Structure
;;;; ============================================================================

(defstruct (threshold-key
            (:constructor %make-threshold-key)
            (:copier nil))
  "Complete threshold key material for a single party.

   SLOTS:
   - ID: Unique key identifier (bytes)
   - GROUP-PUBKEY: Aggregate public key for the group (33 bytes compressed)
   - THRESHOLD: Number of parties required (t)
   - TOTAL-PARTIES: Total number of parties (n)
   - MY-INDEX: This party's index (1..n)
   - MY-SHARE: This party's secret share
   - VERIFICATION-VECTOR: Polynomial commitments for share verification
   - PARTY-PUBKEYS: List of all parties' public keys"
  (id nil :type (or null (vector (unsigned-byte 8))))
  (group-pubkey nil :type (or null (vector (unsigned-byte 8))))
  (threshold 0 :type (integer 0 255))
  (total-parties 0 :type (integer 0 255))
  (my-index 0 :type (integer 0 255))
  (my-share nil :type (or null share))
  (verification-vector nil :type list)
  (party-pubkeys nil :type list))

(defun make-threshold-key (&key id group-pubkey threshold total-parties
                             my-index my-share verification-vector party-pubkeys)
  "Create a new threshold key structure."
  (when threshold
    (validate-threshold-params threshold (or total-parties threshold)))
  (%make-threshold-key
   :id (or id (session-id-generate))
   :group-pubkey group-pubkey
   :threshold (or threshold 0)
   :total-parties (or total-parties 0)
   :my-index (or my-index 0)
   :my-share my-share
   :verification-vector verification-vector
   :party-pubkeys party-pubkeys))

(defun copy-threshold-key (key)
  "Create a deep copy of a threshold key."
  (declare (type threshold-key key))
  (%make-threshold-key
   :id (when (threshold-key-id key)
         (copy-seq (threshold-key-id key)))
   :group-pubkey (when (threshold-key-group-pubkey key)
                   (copy-seq (threshold-key-group-pubkey key)))
   :threshold (threshold-key-threshold key)
   :total-parties (threshold-key-total-parties key)
   :my-index (threshold-key-my-index key)
   :my-share (when (threshold-key-my-share key)
               (copy-share (threshold-key-my-share key)))
   :verification-vector (mapcar (lambda (v)
                                  (if (vectorp v) (copy-seq v) v))
                                (threshold-key-verification-vector key))
   :party-pubkeys (mapcar (lambda (pair)
                            (cons (car pair)
                                  (when (cdr pair) (copy-seq (cdr pair)))))
                          (threshold-key-party-pubkeys key))))

;;;; ============================================================================
;;;; Polynomial Operations
;;;; ============================================================================

(defun generate-random-polynomial (degree &optional secret)
  "Generate a random polynomial of given DEGREE.

   PARAMETERS:
   - DEGREE: Polynomial degree (t-1 for threshold t)
   - SECRET: Optional coefficient a_0 (random if not provided)

   RETURN:
   List of (degree+1) coefficients [a_0, a_1, ..., a_degree]

   The secret is a_0. For t-of-n threshold, use degree = t-1."
  (declare (type fixnum degree)
           (optimize (speed 3) (safety 1)))
  (let ((coefficients (make-list (1+ degree))))
    ;; a_0 is the secret
    (setf (first coefficients) (or secret (random-scalar)))
    ;; Random coefficients for higher degrees
    (loop for i from 1 to degree
          do (setf (nth i coefficients) (random-scalar)))
    coefficients))

(defun evaluate-polynomial (coefficients x)
  "Evaluate polynomial at point X using Horner's method.

   PARAMETERS:
   - COEFFICIENTS: List of coefficients [a_0, a_1, ..., a_n]
   - X: Point to evaluate at (integer)

   RETURN:
   Integer - f(x) mod n

   Uses Horner's method for O(n) evaluation:
   f(x) = a_0 + x*(a_1 + x*(a_2 + ... + x*a_n))"
  (declare (type list coefficients)
           (type integer x)
           (optimize (speed 3) (safety 1)))
  (let ((result 0)
        (rev-coeffs (reverse coefficients)))
    (dolist (coeff rev-coeffs)
      (setf result (scalar-mod (+ (scalar-mul result x) coeff))))
    result))

(defun polynomial-commitment-vector (coefficients)
  "Compute Feldman VSS commitment vector for polynomial coefficients.

   PARAMETERS:
   - COEFFICIENTS: List of polynomial coefficients [a_0, ..., a_{t-1}]

   RETURN:
   List of EC points [C_0, C_1, ..., C_{t-1}] where C_j = a_j * G
   Each point is 33 bytes (compressed format).

   These commitments allow verification of shares without revealing the secret."
  (declare (type list coefficients)
           (optimize (speed 3) (safety 1)))
  (mapcar (lambda (coeff)
            (scalar-multiply-generator coeff))
          coefficients))

(defun verify-polynomial-commitment (share-index share-value commitment-vector)
  "Verify that a share is consistent with the polynomial commitment.

   PARAMETERS:
   - SHARE-INDEX: Party index i (1..n)
   - SHARE-VALUE: Share value s_i = f(i)
   - COMMITMENT-VECTOR: List of commitment points [C_0, ..., C_{t-1}]

   RETURN:
   T if share is valid, NIL otherwise

   Verification: s_i * G = sum(i^j * C_j) for j in [0, t-1]"
  (declare (type integer share-index share-value)
           (type list commitment-vector)
           (optimize (speed 3) (safety 1)))
  (let* (;; Left side: s_i * G
         (lhs (scalar-multiply-generator share-value))
         ;; Right side: sum(i^j * C_j)
         (rhs (compute-commitment-check share-index commitment-vector)))
    ;; Compare points
    (point-equal-p lhs rhs)))

(defun compute-commitment-check (index commitment-vector)
  "Compute sum(index^j * C_j) for verification."
  (declare (type integer index)
           (type list commitment-vector)
           (optimize (speed 3) (safety 1)))
  (let ((result nil)
        (power 1))  ; i^j, starting with i^0 = 1
    (dolist (c-j commitment-vector)
      (let ((term (scalar-multiply-point power c-j)))
        (setf result (if result
                         (point-add result term)
                         term)))
      (setf power (scalar-mul power index)))
    result))

;;;; ============================================================================
;;;; Trusted Dealer Key Generation
;;;; ============================================================================

(defun frost-keygen-trusted-dealer (threshold total-parties &key secret)
  "Generate FROST key shares using a trusted dealer.

   PARAMETERS:
   - THRESHOLD: t value (minimum signers required)
   - TOTAL-PARTIES: n value (total participants)
   - SECRET: Optional secret value (random if not provided)

   RETURN:
   (VALUES shares group-pubkey commitment-vector) where:
   - SHARES: List of (index . share-value) pairs for each party
   - GROUP-PUBKEY: 33-byte compressed group public key
   - COMMITMENT-VECTOR: List of commitment points for verification

   WARNING: Trusted dealer knows all shares. Use DKG for production.

   ALGORITHM:
   1. Generate random polynomial f(x) of degree t-1
   2. Secret s = f(0) = a_0
   3. Group public key Y = s * G
   4. Share for party i: s_i = f(i)
   5. Commitment C_j = a_j * G"
  (declare (type fixnum threshold total-parties)
           (optimize (speed 3) (safety 1)))
  ;; Validate parameters
  (validate-threshold-params threshold total-parties)

  ;; Generate random polynomial of degree t-1
  (let* ((polynomial (generate-random-polynomial (1- threshold) secret))
         ;; Compute commitment vector
         (commitment-vector (polynomial-commitment-vector polynomial))
         ;; Group public key is first commitment (a_0 * G)
         (group-pubkey (first commitment-vector))
         ;; Generate shares for each party
         (shares (loop for i from 1 to total-parties
                       collect (cons i (evaluate-polynomial polynomial i)))))

    (values shares group-pubkey commitment-vector)))

(defun frost-keygen-verify-share (share commitment-vector)
  "Verify a key share against the commitment vector.

   PARAMETERS:
   - SHARE: Share structure to verify
   - COMMITMENT-VECTOR: List of commitment points

   RETURN:
   T if share is valid, signals error otherwise"
  (declare (type share share)
           (type list commitment-vector)
           (optimize (speed 3) (safety 1)))
  (unless (verify-polynomial-commitment
           (share-index share)
           (share-value share)
           commitment-vector)
    (error 'frost-verification-error
           :message "Share verification failed"
           :expected "Valid polynomial commitment"
           :actual "Invalid share"))
  t)

;;;; ============================================================================
;;;; Public Key Derivation
;;;; ============================================================================

(defun frost-keygen-derive-public (share-value)
  "Derive individual public key from share.

   PARAMETERS:
   - SHARE-VALUE: Secret share s_i

   RETURN:
   33-byte compressed public key Y_i = s_i * G"
  (declare (type integer share-value)
           (optimize (speed 3) (safety 1)))
  (scalar-multiply-generator share-value))

;;;; ============================================================================
;;;; Lagrange Interpolation
;;;; ============================================================================

(defun lagrange-coefficient (i participant-indices &key (at-x 0))
  "Compute Lagrange coefficient for participant i evaluated at AT-X.

   PARAMETERS:
   - I: Index of the participant
   - PARTICIPANT-INDICES: List of all participant indices
   - AT-X: Point to evaluate at (default 0 for secret reconstruction)

   RETURN:
   Integer - lambda_i mod n

   Formula: lambda_i = product((x_m - AT-X) / (x_m - x_i)) for m != i

   When AT-X = 0:
   lambda_i = product(x_m / (x_m - x_i)) for m != i"
  (declare (type integer i at-x)
           (type list participant-indices)
           (optimize (speed 3) (safety 1)))
  (let ((numerator 1)
        (denominator 1))
    (dolist (m participant-indices)
      (unless (= m i)
        (setf numerator (scalar-mul numerator (- m at-x)))
        (setf denominator (scalar-mul denominator (- m i)))))
    ;; lambda_i = numerator / denominator mod n
    (scalar-mul numerator (scalar-invert denominator))))

(defun lagrange-coefficients-for-set (participant-indices &key (at-x 0))
  "Compute Lagrange coefficients for all participants in a set.

   PARAMETERS:
   - PARTICIPANT-INDICES: List of participant indices
   - AT-X: Point to evaluate at (default 0)

   RETURN:
   Association list of (index . coefficient) pairs"
  (declare (type list participant-indices)
           (type integer at-x)
           (optimize (speed 3) (safety 1)))
  (mapcar (lambda (i)
            (cons i (lagrange-coefficient i participant-indices :at-x at-x)))
          participant-indices))

;;;; ============================================================================
;;;; Secret Reconstruction
;;;; ============================================================================

(defun frost-reconstruct-secret (shares)
  "Reconstruct the secret from t or more shares (Lagrange interpolation).

   PARAMETERS:
   - SHARES: List of (index . value) pairs

   RETURN:
   Integer - The reconstructed secret s = f(0)

   WARNING: This reconstructs the full secret. Should only be used
   for testing or offline recovery scenarios."
  (declare (type list shares)
           (optimize (speed 3) (safety 1)))
  (let* ((indices (mapcar #'car shares))
         (result 0))
    (dolist (share shares)
      (let* ((i (car share))
             (s-i (cdr share))
             (lambda-i (lagrange-coefficient i indices)))
        (setf result (scalar-add result (scalar-mul lambda-i s-i)))))
    result))

;;;; ============================================================================
;;;; Create Threshold Key from Shares
;;;; ============================================================================

(defun frost-create-threshold-key (index share group-pubkey commitment-vector
                                   threshold total-parties party-pubkeys)
  "Create a complete threshold key structure for a party.

   PARAMETERS:
   - INDEX: This party's index
   - SHARE: This party's share structure
   - GROUP-PUBKEY: 33-byte group public key
   - COMMITMENT-VECTOR: Polynomial commitment vector
   - THRESHOLD: t value
   - TOTAL-PARTIES: n value
   - PARTY-PUBKEYS: List of (index . pubkey) for all parties

   RETURN:
   THRESHOLD-KEY structure"
  (make-threshold-key
   :id (session-id-generate)
   :group-pubkey group-pubkey
   :threshold threshold
   :total-parties total-parties
   :my-index index
   :my-share share
   :verification-vector commitment-vector
   :party-pubkeys party-pubkeys))

;;;; ============================================================================
;;;; Testing Utilities
;;;; ============================================================================

(defun frost-keygen-test (threshold total-parties)
  "Run a complete key generation test with verification.

   PARAMETERS:
   - THRESHOLD: t value
   - TOTAL-PARTIES: n value

   RETURN:
   T if test passes, signals error otherwise"
  ;; Generate keys
  (multiple-value-bind (shares group-pubkey commitment-vector)
      (frost-keygen-trusted-dealer threshold total-parties)
    ;; Verify each share
    (dolist (share-pair shares)
      (let ((share (make-share :index (car share-pair)
                               :value (cdr share-pair))))
        (frost-keygen-verify-share share commitment-vector)))

    ;; Verify we can reconstruct with exactly t shares
    (let* ((t-shares (subseq shares 0 threshold))
           (reconstructed (frost-reconstruct-secret t-shares))
           (reconstructed-pubkey (scalar-multiply-generator reconstructed)))
      (unless (point-equal-p group-pubkey reconstructed-pubkey)
        (error 'frost-verification-error
               :message "Key reconstruction failed"
               :expected "Group public key"
               :actual "Mismatched reconstructed key")))

    (format t "~&; FROST keygen test passed (~D-of-~D)~%" threshold total-parties)
    t))

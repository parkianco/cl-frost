;;;; signing.lisp - FROST Signing Protocol for cl-frost
;;;;
;;;; Implements the 2-round FROST signing protocol:
;;;; - Round 1: Nonce generation and commitment broadcasting
;;;; - Round 2: Partial signature generation
;;;; - Aggregation: Combine partial signatures into final BIP340 signature

(in-package #:cl-frost)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;;; ============================================================================
;;;; Nonce Structure
;;;; ============================================================================

(defstruct (frost-nonce
            (:constructor %make-frost-nonce)
            (:copier nil))
  "Nonce pair for FROST signing.

   SLOTS:
   - HIDING: Secret hiding nonce d_i (scalar)
   - BINDING: Secret binding nonce e_i (scalar)
   - HIDING-COMMITMENT: Public commitment D_i = d_i * G
   - BINDING-COMMITMENT: Public commitment E_i = e_i * G
   - SIGNER-INDEX: Index of the signer who generated this"
  (hiding 0 :type integer)
  (binding 0 :type integer)
  (hiding-commitment nil :type (or null (vector (unsigned-byte 8))))
  (binding-commitment nil :type (or null (vector (unsigned-byte 8))))
  (signer-index 0 :type (integer 0 255)))

(defun make-frost-nonce (&key hiding binding hiding-commitment binding-commitment
                           signer-index)
  "Create a new FROST nonce pair."
  (%make-frost-nonce
   :hiding (or hiding (random-scalar))
   :binding (or binding (random-scalar))
   :hiding-commitment hiding-commitment
   :binding-commitment binding-commitment
   :signer-index (or signer-index 0)))

(defun copy-frost-nonce (nonce)
  "Create a copy of a FROST nonce."
  (declare (type frost-nonce nonce))
  (%make-frost-nonce
   :hiding (frost-nonce-hiding nonce)
   :binding (frost-nonce-binding nonce)
   :hiding-commitment (when (frost-nonce-hiding-commitment nonce)
                        (copy-seq (frost-nonce-hiding-commitment nonce)))
   :binding-commitment (when (frost-nonce-binding-commitment nonce)
                         (copy-seq (frost-nonce-binding-commitment nonce)))
   :signer-index (frost-nonce-signer-index nonce)))

;;;; ============================================================================
;;;; Commitment Structure
;;;; ============================================================================

(defstruct (frost-commitment
            (:constructor %make-frost-commitment)
            (:copier nil))
  "Public commitment from a signer for Round 1.

   SLOTS:
   - SIGNER-INDEX: Index of the signer (1..n)
   - HIDING: D_i = d_i * G (33 bytes compressed)
   - BINDING: E_i = e_i * G (33 bytes compressed)"
  (signer-index 0 :type (integer 0 255))
  (hiding nil :type (or null (vector (unsigned-byte 8))))
  (binding nil :type (or null (vector (unsigned-byte 8)))))

(defun make-frost-commitment (&key signer-index hiding binding)
  "Create a new FROST commitment structure."
  (unless (and signer-index (plusp signer-index))
    (error 'frost-error :message "Signer index must be positive"))
  (%make-frost-commitment
   :signer-index signer-index
   :hiding hiding
   :binding binding))

(defun copy-frost-commitment (commitment)
  "Create a deep copy of a FROST commitment."
  (declare (type frost-commitment commitment))
  (%make-frost-commitment
   :signer-index (frost-commitment-signer-index commitment)
   :hiding (when (frost-commitment-hiding commitment)
             (copy-seq (frost-commitment-hiding commitment)))
   :binding (when (frost-commitment-binding commitment)
              (copy-seq (frost-commitment-binding commitment)))))

;;;; ============================================================================
;;;; Partial Signature Structure
;;;; ============================================================================

(defstruct (frost-partial-signature
            (:constructor %make-frost-partial-signature)
            (:copier nil))
  "Partial signature from a signer for Round 2.

   SLOTS:
   - SIGNER-INDEX: Index of the signer (1..n)
   - Z: Partial signature value z_i (32 bytes scalar)"
  (signer-index 0 :type (integer 0 255))
  (z nil :type (or null (vector (unsigned-byte 8)))))

(defun make-frost-partial-signature (&key signer-index z)
  "Create a new FROST partial signature structure."
  (%make-frost-partial-signature
   :signer-index signer-index
   :z z))

(defun copy-frost-partial-signature (partial)
  "Create a deep copy of a FROST partial signature."
  (declare (type frost-partial-signature partial))
  (%make-frost-partial-signature
   :signer-index (frost-partial-signature-signer-index partial)
   :z (when (frost-partial-signature-z partial)
        (copy-seq (frost-partial-signature-z partial)))))

;;;; ============================================================================
;;;; Signature Structure
;;;; ============================================================================

(defstruct (frost-signature
            (:constructor %make-frost-signature)
            (:copier nil))
  "FROST threshold signature.

   SLOTS:
   - R: Signature R value (32 bytes x-only)
   - S: Signature s value (32 bytes scalar)
   - SIGNER-SET: List of signer indices who participated"
  (r nil :type (or null (vector (unsigned-byte 8))))
  (s nil :type (or null (vector (unsigned-byte 8))))
  (signer-set nil :type list))

(defun make-frost-signature (&key r s signer-set)
  "Create a new FROST signature structure."
  (%make-frost-signature :r r :s s :signer-set signer-set))

(defun copy-frost-signature (sig)
  "Create a copy of a FROST signature."
  (declare (type frost-signature sig))
  (%make-frost-signature
   :r (when (frost-signature-r sig) (copy-seq (frost-signature-r sig)))
   :s (when (frost-signature-s sig) (copy-seq (frost-signature-s sig)))
   :signer-set (copy-list (frost-signature-signer-set sig))))

;;;; ============================================================================
;;;; Signing Session Structure
;;;; ============================================================================

(defstruct (frost-signing-session
            (:constructor %make-frost-signing-session)
            (:copier nil))
  "State for a FROST signing session.

   SLOTS:
   - ID: Unique session identifier
   - THRESHOLD-KEY: The threshold key being used
   - MESSAGE: Message being signed (32 bytes)
   - SIGNER-SET: List of participating signer indices
   - STATE: Current protocol state
   - NONCES: Map of signer-index -> frost-nonce
   - NONCE-COMMITMENTS: Map of signer-index -> (D . E) commitments
   - SIGNATURE-SHARES: Map of signer-index -> signature share (integer)
   - GROUP-COMMITMENT: Computed group nonce commitment (33 bytes)
   - CHALLENGE: Signature challenge c (integer)
   - FINAL-SIGNATURE: Completed signature"
  (id nil :type (or null (vector (unsigned-byte 8))))
  (threshold-key nil :type (or null threshold-key))
  (message nil :type (or null (vector (unsigned-byte 8))))
  (signer-set nil :type list)
  (state :initialized :type keyword)
  (nonces nil :type hash-table)
  (nonce-commitments nil :type hash-table)
  (signature-shares nil :type hash-table)
  (group-commitment nil :type (or null (vector (unsigned-byte 8))))
  (challenge 0 :type integer)
  (final-signature nil :type (or null frost-signature)))

(defun make-frost-signing-session (&key id threshold-key message signer-set state)
  "Create a new FROST signing session."
  (when (and threshold-key signer-set)
    (validate-party-set signer-set (threshold-key-threshold threshold-key)))
  (%make-frost-signing-session
   :id (or id (session-id-generate))
   :threshold-key threshold-key
   :message message
   :signer-set signer-set
   :state (or state :initialized)
   :nonces (make-hash-table :test 'eql)
   :nonce-commitments (make-hash-table :test 'eql)
   :signature-shares (make-hash-table :test 'eql)
   :group-commitment nil
   :challenge 0
   :final-signature nil))

(defun copy-frost-signing-session (session)
  "Create a deep copy of a FROST signing session."
  (declare (type frost-signing-session session))
  (let ((new-nonces (make-hash-table :test 'eql))
        (new-commitments (make-hash-table :test 'eql))
        (new-shares (make-hash-table :test 'eql)))
    (maphash (lambda (k v)
               (setf (gethash k new-nonces) (copy-frost-nonce v)))
             (frost-signing-session-nonces session))
    (maphash (lambda (k v)
               (setf (gethash k new-commitments)
                     (cons (copy-seq (car v)) (copy-seq (cdr v)))))
             (frost-signing-session-nonce-commitments session))
    (maphash (lambda (k v)
               (setf (gethash k new-shares) v))
             (frost-signing-session-signature-shares session))
    (%make-frost-signing-session
     :id (when (frost-signing-session-id session)
           (copy-seq (frost-signing-session-id session)))
     :threshold-key (when (frost-signing-session-threshold-key session)
                      (copy-threshold-key (frost-signing-session-threshold-key session)))
     :message (when (frost-signing-session-message session)
                (copy-seq (frost-signing-session-message session)))
     :signer-set (copy-list (frost-signing-session-signer-set session))
     :state (frost-signing-session-state session)
     :nonces new-nonces
     :nonce-commitments new-commitments
     :signature-shares new-shares
     :group-commitment (when (frost-signing-session-group-commitment session)
                         (copy-seq (frost-signing-session-group-commitment session)))
     :challenge (frost-signing-session-challenge session)
     :final-signature (when (frost-signing-session-final-signature session)
                        (copy-frost-signature (frost-signing-session-final-signature session))))))

;;;; ============================================================================
;;;; Nonce Generation
;;;; ============================================================================

(defun frost-nonce-generate (signer-index)
  "Generate a fresh nonce pair for signing.

   PARAMETERS:
   - SIGNER-INDEX: Index of the signer generating nonces

   RETURN:
   FROST-NONCE structure with:
   - HIDING: Secret d_i (integer)
   - BINDING: Secret e_i (integer)
   - HIDING-COMMITMENT: D_i = d_i * G (33 bytes)
   - BINDING-COMMITMENT: E_i = e_i * G (33 bytes)

   SECURITY:
   - Nonces must NEVER be reused
   - Secret nonces should be securely wiped after use"
  (declare (type fixnum signer-index)
           (optimize (speed 3) (safety 1)))
  (let* ((d (random-scalar))
         (e (random-scalar))
         (d-commit (scalar-multiply-generator d))
         (e-commit (scalar-multiply-generator e)))
    (make-frost-nonce
     :hiding d
     :binding e
     :hiding-commitment d-commit
     :binding-commitment e-commit
     :signer-index signer-index)))

(defun frost-nonce-commit (nonce)
  "Extract the public commitment from a nonce pair.

   PARAMETERS:
   - NONCE: FROST-NONCE structure

   RETURN:
   FROST-COMMITMENT structure with public commitments only"
  (declare (type frost-nonce nonce)
           (optimize (speed 3) (safety 1)))
  (make-frost-commitment
   :signer-index (frost-nonce-signer-index nonce)
   :hiding (frost-nonce-hiding-commitment nonce)
   :binding (frost-nonce-binding-commitment nonce)))

(defun frost-nonce-preprocess (signer-index count)
  "Pre-generate multiple nonce pairs for future signing.

   PARAMETERS:
   - SIGNER-INDEX: Index of the signer
   - COUNT: Number of nonce pairs to generate

   RETURN:
   List of FROST-NONCE structures"
  (declare (type fixnum signer-index count)
           (optimize (speed 3) (safety 1)))
  (loop repeat count
        collect (frost-nonce-generate signer-index)))

;;;; ============================================================================
;;;; Signing Round 1: Begin Session
;;;; ============================================================================

(defun frost-sign-begin (threshold-key message signer-set &key nonce)
  "Begin a FROST signing session.

   PARAMETERS:
   - THRESHOLD-KEY: This signer's threshold key
   - MESSAGE: 32-byte message hash to sign
   - SIGNER-SET: List of participating signer indices
   - NONCE: Pre-generated nonce (optional, generated if nil)

   RETURN:
   (VALUES session commitment) where:
   - SESSION: FROST-SIGNING-SESSION structure
   - COMMITMENT: FROST-COMMITMENT for broadcasting"
  (declare (type threshold-key threshold-key)
           (type (vector (unsigned-byte 8)) message)
           (type list signer-set)
           (optimize (speed 3) (safety 1)))
  ;; Validate signer set meets threshold
  (validate-party-set signer-set (threshold-key-threshold threshold-key))

  ;; Ensure our index is in the signer set
  (let ((my-index (threshold-key-my-index threshold-key)))
    (unless (member my-index signer-set)
      (error 'frost-error :message "Our index not in signer set")))

  ;; Create or use provided nonce
  (let* ((my-nonce (or nonce (frost-nonce-generate
                              (threshold-key-my-index threshold-key))))
         ;; Create the signing session
         (session (make-frost-signing-session
                   :threshold-key threshold-key
                   :message message
                   :signer-set (sort (copy-list signer-set) #'<))))

    ;; Store our nonce in the session
    (setf (gethash (threshold-key-my-index threshold-key)
                   (frost-signing-session-nonces session))
          my-nonce)

    ;; Create and store our commitment
    (let ((commitment (frost-nonce-commit my-nonce)))
      (setf (gethash (threshold-key-my-index threshold-key)
                     (frost-signing-session-nonce-commitments session))
            (cons (frost-commitment-hiding commitment)
                  (frost-commitment-binding commitment)))

      ;; Advance state
      (setf (frost-signing-session-state session) :commitment-phase)

      (values session commitment))))

(defun frost-sign-commit (session)
  "Get this signer's commitment from a session.

   PARAMETERS:
   - SESSION: FROST-SIGNING-SESSION structure

   RETURN:
   FROST-COMMITMENT structure for broadcasting"
  (declare (type frost-signing-session session))
  (let* ((key (frost-signing-session-threshold-key session))
         (my-index (threshold-key-my-index key))
         (nonce (gethash my-index (frost-signing-session-nonces session))))
    (frost-nonce-commit nonce)))

(defun frost-sign-collect-commitments (session commitments)
  "Collect commitments from all signers.

   PARAMETERS:
   - SESSION: FROST-SIGNING-SESSION structure
   - COMMITMENTS: List of FROST-COMMITMENT structures from all signers

   RETURN:
   T if all required commitments collected, NIL otherwise"
  (declare (type frost-signing-session session)
           (type list commitments)
           (optimize (speed 3) (safety 1)))
  (let ((required-signers (frost-signing-session-signer-set session)))
    ;; Store each commitment
    (dolist (commitment commitments)
      (let ((signer-index (frost-commitment-signer-index commitment)))
        ;; Validate signer is in our set
        (unless (member signer-index required-signers)
          (error 'frost-error
                 :message (format nil "Unexpected signer ~D" signer-index)))
        ;; Store commitment
        (setf (gethash signer-index
                       (frost-signing-session-nonce-commitments session))
              (cons (frost-commitment-hiding commitment)
                    (frost-commitment-binding commitment)))))

    ;; Check if we have all commitments
    (let ((collected (hash-table-count
                      (frost-signing-session-nonce-commitments session))))
      (= collected (length required-signers)))))

;;;; ============================================================================
;;;; Signing Round 1: Complete
;;;; ============================================================================

(defun frost-sign-complete-round1 (session)
  "Complete Round 1: return commitment for broadcasting.

   PARAMETERS:
   - SESSION: FROST-SIGNING-SESSION in :commitment-phase

   RETURN:
   FROST-COMMITMENT to broadcast to other signers"
  (declare (type frost-signing-session session))
  (unless (eq (frost-signing-session-state session) :commitment-phase)
    (error 'frost-error :message "Session not in commitment phase"))
  (frost-sign-commit session))

;;;; ============================================================================
;;;; Signing Round 2: Compute Binding Factors
;;;; ============================================================================

(defun frost-sign-compute-binding-factors (session)
  "Compute binding factors rho_i for all signers.

   PARAMETERS:
   - SESSION: FROST-SIGNING-SESSION with all commitments

   RETURN:
   Hash table mapping signer-index -> binding factor (integer)

   Algorithm:
   rho_i = H(i || msg || D_1 || E_1 || ... || D_n || E_n || Y)"
  (declare (type frost-signing-session session)
           (optimize (speed 3) (safety 1)))
  (let* ((signers (frost-signing-session-signer-set session))
         (message (frost-signing-session-message session))
         (key (frost-signing-session-threshold-key session))
         (group-pubkey (threshold-key-group-pubkey key))
         (commitments-ht (frost-signing-session-nonce-commitments session))
         (encoded-commitments (build-encoded-commitments signers commitments-ht))
         (binding-factors (make-hash-table :test 'eql)))

    ;; Compute binding factor for each signer
    (dolist (i signers)
      (let* ((i-bytes (scalar-to-bytes i 4))
             (binding-input (concatenate '(vector (unsigned-byte 8))
                                         +frost-binding-tag+
                                         +frost-binding-tag+
                                         i-bytes
                                         message
                                         encoded-commitments
                                         group-pubkey))
             (binding-hash (sha256 binding-input))
             (rho-i (bytes-to-scalar binding-hash)))
        (setf (gethash i binding-factors) rho-i)))

    binding-factors))

(defun build-encoded-commitments (signers commitments-ht)
  "Build the encoded commitment list for binding factor computation."
  (declare (type list signers)
           (type hash-table commitments-ht)
           (optimize (speed 3) (safety 1)))
  (let ((parts nil))
    (dolist (i signers)
      (let ((commitment (gethash i commitments-ht)))
        (push (car commitment) parts)   ; D_i
        (push (cdr commitment) parts))) ; E_i
    (apply #'concatenate '(vector (unsigned-byte 8)) (nreverse parts))))

;;;; ============================================================================
;;;; Signing Round 2: Compute Group Commitment
;;;; ============================================================================

(defun frost-sign-compute-group-commitment (session binding-factors)
  "Compute the group commitment R from all individual commitments.

   PARAMETERS:
   - SESSION: FROST-SIGNING-SESSION with all commitments
   - BINDING-FACTORS: Hash table from frost-sign-compute-binding-factors

   RETURN:
   33-byte compressed point R

   Algorithm:
   R = sum(D_i + rho_i * E_i) for all signers i"
  (declare (type frost-signing-session session)
           (type hash-table binding-factors)
           (optimize (speed 3) (safety 1)))
  (let* ((signers (frost-signing-session-signer-set session))
         (commitments-ht (frost-signing-session-nonce-commitments session))
         (r-result nil))

    (dolist (i signers)
      (let* ((commitment (gethash i commitments-ht))
             (d-i (car commitment))
             (e-i (cdr commitment))
             (rho-i (gethash i binding-factors))
             ;; R_i = D_i + rho_i * E_i
             (rho-e-i (scalar-multiply-point rho-i e-i))
             (r-i (point-add d-i rho-e-i)))
        (setf r-result (if r-result
                           (point-add r-result r-i)
                           r-i))))

    ;; Store in session
    (setf (frost-signing-session-group-commitment session) r-result)

    r-result))

;;;; ============================================================================
;;;; Signing Round 2: Compute Challenge
;;;; ============================================================================

(defun frost-sign-compute-challenge (session)
  "Compute the signature challenge c.

   PARAMETERS:
   - SESSION: FROST-SIGNING-SESSION with group commitment computed

   RETURN:
   Integer challenge c mod n

   Algorithm (BIP340 compatible):
   c = H('BIP0340/challenge' || R_x || Y_x || msg) mod n"
  (declare (type frost-signing-session session)
           (optimize (speed 3) (safety 1)))
  (let* ((r-point (frost-signing-session-group-commitment session))
         (r-x-only (subseq r-point 1 33))  ; x-coordinate only
         (key (frost-signing-session-threshold-key session))
         (group-pubkey (threshold-key-group-pubkey key))
         (y-x-only (subseq group-pubkey 1 33))
         (message (frost-signing-session-message session))
         ;; BIP340-style challenge computation
         (challenge-input (concatenate '(vector (unsigned-byte 8))
                                        +bip340-challenge-tag+
                                        +bip340-challenge-tag+
                                        r-x-only
                                        y-x-only
                                        message))
         (challenge-hash (sha256 challenge-input))
         (c (bytes-to-scalar challenge-hash)))

    ;; Store in session
    (setf (frost-signing-session-challenge session) c)

    c))

;;;; ============================================================================
;;;; Signing Round 2: Generate Partial Signature
;;;; ============================================================================

(defun frost-sign-generate-partial (session binding-factors)
  "Generate this signer's partial signature.

   PARAMETERS:
   - SESSION: FROST-SIGNING-SESSION with challenge computed
   - BINDING-FACTORS: Hash table from frost-sign-compute-binding-factors

   RETURN:
   FROST-PARTIAL-SIGNATURE structure

   Algorithm:
   z_i = d_i + (e_i * rho_i) + (lambda_i * x_i * c) mod n"
  (declare (type frost-signing-session session)
           (type hash-table binding-factors)
           (optimize (speed 3) (safety 1)))
  (let* ((key (frost-signing-session-threshold-key session))
         (my-index (threshold-key-my-index key))
         (share (threshold-key-my-share key))
         (x-i (share-value share))
         (c (frost-signing-session-challenge session))
         (signer-set (frost-signing-session-signer-set session))
         ;; Get our nonce secrets
         (nonce (gethash my-index (frost-signing-session-nonces session)))
         (d-i (frost-nonce-hiding nonce))
         (e-i (frost-nonce-binding nonce))
         (rho-i (gethash my-index binding-factors))
         ;; Compute Lagrange coefficient
         (lambda-i (lagrange-coefficient my-index signer-set))
         ;; Compute partial signature
         ;; z_i = d_i + (e_i * rho_i) + (lambda_i * x_i * c)
         (z-i (scalar-add d-i
                          (scalar-add (scalar-mul e-i rho-i)
                                      (scalar-mul lambda-i
                                                  (scalar-mul x-i c))))))

    ;; Handle R parity for BIP340 compatibility
    ;; If R has odd y, we need to negate z
    (let* ((r-point (frost-signing-session-group-commitment session))
           (r-has-odd-y (= (aref r-point 0) #x03)))
      (when r-has-odd-y
        (setf z-i (scalar-negate z-i))))

    (let ((z-bytes (scalar-to-bytes z-i 32)))
      ;; Store in session
      (setf (gethash my-index (frost-signing-session-signature-shares session))
            z-i)

      ;; Security: Clear nonce secrets from session
      (setf (frost-nonce-hiding nonce) 0)
      (setf (frost-nonce-binding nonce) 0)

      ;; Return partial signature
      (make-frost-partial-signature
       :signer-index my-index
       :z z-bytes))))

;;;; ============================================================================
;;;; Signing Round 2: Verify Partial Signature
;;;; ============================================================================

(defun frost-sign-verify-partial (session partial-sig binding-factors)
  "Verify a partial signature from another signer.

   PARAMETERS:
   - SESSION: FROST-SIGNING-SESSION
   - PARTIAL-SIG: FROST-PARTIAL-SIGNATURE to verify
   - BINDING-FACTORS: Hash table from frost-sign-compute-binding-factors

   RETURN:
   T if partial signature is valid, NIL otherwise

   Verification:
   z_i * G = R_i + c * lambda_i * Y_i"
  (declare (type frost-signing-session session)
           (type frost-partial-signature partial-sig)
           (type hash-table binding-factors)
           (optimize (speed 3) (safety 1)))
  (let* ((i (frost-partial-signature-signer-index partial-sig))
         (z-i (bytes-to-scalar (frost-partial-signature-z partial-sig)))
         (c (frost-signing-session-challenge session))
         (signer-set (frost-signing-session-signer-set session))
         (commitments-ht (frost-signing-session-nonce-commitments session))
         (commitment (gethash i commitments-ht))
         (d-i (car commitment))
         (e-i (cdr commitment))
         (rho-i (gethash i binding-factors))
         (key (frost-signing-session-threshold-key session))
         (party-pubkeys (threshold-key-party-pubkeys key))
         (y-i (cdr (assoc i party-pubkeys)))
         (lambda-i (lagrange-coefficient i signer-set))
         ;; Handle R parity for BIP340
         (r-point (frost-signing-session-group-commitment session))
         (r-has-odd-y (= (aref r-point 0) #x03)))

    ;; Adjust for R parity
    (when r-has-odd-y
      (setf z-i (scalar-negate z-i)))

    ;; LHS: z_i * G
    (let ((lhs (scalar-multiply-generator z-i)))
      ;; RHS: R_i + c * lambda_i * Y_i
      ;; where R_i = D_i + rho_i * E_i
      (let* ((r-i (point-add d-i (scalar-multiply-point rho-i e-i)))
             (c-lambda-y (scalar-multiply-point (scalar-mul c lambda-i) y-i))
             (rhs (point-add r-i c-lambda-y)))
        (point-equal-p lhs rhs)))))

;;;; ============================================================================
;;;; Signing Round 2: Complete
;;;; ============================================================================

(defun frost-sign-complete-round2 (session all-commitments)
  "Complete Round 2: generate partial signature.

   PARAMETERS:
   - SESSION: FROST-SIGNING-SESSION with all commitments received
   - ALL-COMMITMENTS: List of FROST-COMMITMENT from all signers

   RETURN:
   FROST-PARTIAL-SIGNATURE to send to aggregator"
  (declare (type frost-signing-session session)
           (type list all-commitments)
           (optimize (speed 3) (safety 1)))
  ;; Collect all commitments
  (frost-sign-collect-commitments session all-commitments)

  ;; Compute binding factors
  (let ((binding-factors (frost-sign-compute-binding-factors session)))
    ;; Compute group commitment
    (frost-sign-compute-group-commitment session binding-factors)

    ;; Compute challenge
    (frost-sign-compute-challenge session)

    ;; Update state
    (setf (frost-signing-session-state session) :signing-phase)

    ;; Generate and return partial signature
    (frost-sign-generate-partial session binding-factors)))

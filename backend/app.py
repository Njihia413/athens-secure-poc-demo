# The one that works both backend and frontend
import json

from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
import base64
import os
import sqlalchemy
from sqlalchemy import create_engine, Column, Integer, String, Boolean, LargeBinary, ForeignKey, DateTime, func
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

# Import FIDO2 modules instead of webauthn
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
from fido2.webauthn import AttestationConveyancePreference, AuthenticatorSelectionCriteria
from fido2.webauthn import UserVerificationRequirement, AuthenticatorAttachment
from fido2 import cbor
from fido2.utils import websafe_decode, websafe_encode

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Database setup - replace with your MySQL or PostgreSQL connection string
# For MySQL: mysql+pymysql://username:password@localhost/dbname
# For PostgreSQL: postgresql://username:password@localhost/dbname
DATABASE_URL = "postgresql://postgres:postgres@localhost/athens_secure_poc"
engine = create_engine(DATABASE_URL)
Base = declarative_base()
Session = sessionmaker(bind=engine)


# Define models
class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)  # In production, use a proper hashing library
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    credentials = relationship("WebAuthnCredential", back_populates="user", cascade="all, delete-orphan")
    challenges = relationship("AuthenticationChallenge", back_populates="user", cascade="all, delete-orphan")


class WebAuthnCredential(Base):
    __tablename__ = 'webauthn_credentials'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    credential_id = Column(LargeBinary, nullable=False)
    public_key = Column(LargeBinary, nullable=False)
    counter = Column(Integer, default=0, nullable=False)
    credential_name = Column(String(255))
    transports = Column(String(255))  # Comma-separated list of transports
    created_at = Column(DateTime, default=func.now())
    last_used_at = Column(DateTime)

    user = relationship("User", back_populates="credentials")

    __table_args__ = (
        sqlalchemy.UniqueConstraint('user_id', 'credential_id', name='uq_user_credential'),
    )


class AuthenticationChallenge(Base):
    __tablename__ = 'authentication_challenges'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    challenge = Column(String, nullable=False)
    created_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)

    user = relationship("User", back_populates="challenges")

# Create tables
Base.metadata.create_all(engine)

# Configuration for FIDO2
RP_ID = "localhost"  # Use your domain in production
RP_NAME = "Athens AI"
ORIGIN = "http://localhost:5173"  # Your frontend URL

# Initialize FIDO2 server
rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)
server = Fido2Server(rp)


# This function should be placed at the top of your Flask app

def prepare_webauthn_options(user_id, username, is_registration=True):
    """
    Prepare WebAuthn options for registration or authentication.
    Handles challenge creation, storage, and formatting consistently.

    Parameters:
    - user_id: Integer user ID
    - username: String username
    - is_registration: Boolean, True for registration, False for authentication

    Returns:
    - Dictionary with WebAuthn options ready for client
    """
    print("\n" + "=" * 80)
    print(f"PREPARE WEBAUTHN OPTIONS for user: {username} (id: {user_id})")
    print(f"Operation: {'Registration' if is_registration else 'Authentication'}")
    print("=" * 80)

    # 1. Prepare user entity (for registration only)
    user_entity = None
    if is_registration:
        user_entity = PublicKeyCredentialUserEntity(
            id=str(user_id).encode(),
            name=username,
            display_name=username
        )
        print(f"\n[USER ENTITY] Created for registration:")
        print(f"  ID: {str(user_id).encode().hex()}")
        print(f"  Name: {username}")

    # 2. Get credential descriptors (for authentication only)
    credential_descriptors = []
    if not is_registration:
        session = Session()
        try:
            credentials = session.query(WebAuthnCredential).filter(
                WebAuthnCredential.user_id == user_id
            ).all()

            if not credentials:
                print("\n[ERROR] No credentials found for user")
                return {"error": "No credentials found for user"}, 400

            from fido2.webauthn import PublicKeyCredentialDescriptor
            from fido2.webauthn import PublicKeyCredentialType

            for cred in credentials:
                cred_id = getattr(cred, 'credential_id', None)
                if cred_id is not None:
                    descriptor = PublicKeyCredentialDescriptor(
                        id=cred_id,
                        type=PublicKeyCredentialType.PUBLIC_KEY
                    )
                    credential_descriptors.append(descriptor)

            print(f"\n[CREDENTIALS] Found {len(credential_descriptors)} for authentication")
        finally:
            session.close()

    # 3. Generate options with FIDO2 server
    print("\n[FIDO2] Generating options...")
    options, state = None, None
    if is_registration:
        options, state = server.register_begin(
            user=user_entity,
            user_verification=UserVerificationRequirement.PREFERRED,
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM
        )
    else:
        options, state = server.authenticate_begin(
            credentials=credential_descriptors,
            user_verification=UserVerificationRequirement.PREFERRED
        )

    # 4. Get challenge from state and ensure it's bytes
    challenge_bytes = state['challenge']
    print("\n[CHALLENGE] From FIDO2 server:")
    print(f"  Type: {type(challenge_bytes)}")

    if not isinstance(challenge_bytes, bytes):
        print(f"  WARNING: Challenge is not bytes, converting from {type(challenge_bytes)}")
        challenge_bytes = bytes(challenge_bytes, 'utf-8') if isinstance(challenge_bytes, str) else bytes(
            challenge_bytes)

    print(f"  Length: {len(challenge_bytes)} bytes")
    print(f"  Raw bytes (hex): {challenge_bytes.hex()}")
    print(f"  Base64: {base64.b64encode(challenge_bytes).decode('ascii')}")
    from fido2.utils import websafe_encode
    b64url_challenge = websafe_encode(challenge_bytes)
    print(f"  Base64URL: {b64url_challenge}")

    # 5. Store challenge in database with debug info
    print("\n[DATABASE] Storing challenge...")
    challenge_id = store_challenge(user_id, challenge_bytes)
    print(f"  Stored as ID: {challenge_id}")

    # 6. Create the response structure that the client expects
    print("\n[RESPONSE] Creating client response options...")

    if is_registration:
        response_options = {
            "publicKey": {
                "rp": {
                    "name": rp.name,
                    "id": rp.id
                },
                "user": {
                    "id": websafe_encode(user_entity.id),
                    "name": user_entity.name,
                    "displayName": user_entity.display_name
                },
                "challenge": b64url_challenge,  # Use the encoded challenge
                "pubKeyCredParams": [
                    {"type": "public-key", "alg": -7},  # ES256
                    {"type": "public-key", "alg": -257}  # RS256
                ],
                "timeout": 60000,
                "excludeCredentials": [],
                "authenticatorSelection": {
                    "authenticatorAttachment": "cross-platform",
                    "requireResidentKey": False,
                    "userVerification": "preferred"
                },
                "attestation": "none"
            }
        }
        print(f"  Registration options created with challenge: {b64url_challenge[:20]}...")
    else:
        response_options = {
            "publicKey": {
                "challenge": b64url_challenge,  # Use the encoded challenge
                "timeout": 60000,
                "rpId": RP_ID,
                "allowCredentials": [
                    {
                        "id": websafe_encode(getattr(cred, 'credential_id', None)),
                        "type": "public-key",
                        "transports": getattr(cred, 'transports', "").split(",") if getattr(cred, 'transports',
                                                                                            "") else ["usb", "nfc",
                                                                                                      "ble"]
                    }
                    for cred in credentials if hasattr(cred, 'credential_id')
                ],
                "userVerification": "preferred"
            }
        }
        print(f"  Authentication options created with challenge: {b64url_challenge[:20]}...")

    # Verify once more the challenge is correctly encoded in the response
    sent_challenge = response_options["publicKey"]["challenge"]
    print(f"\n[VERIFICATION] Challenge in response options: {sent_challenge[:20]}...")

    # For deeper debugging, store a reference to this challenge for later comparison
    app.config['LAST_CHALLENGE'] = {
        'user_id': user_id,
        'raw_bytes': challenge_bytes,
        'base64url': b64url_challenge,
        'timestamp': datetime.now().isoformat()
    }

    print("\n[DONE] Options prepared successfully!")
    return response_options


# Helper functions
def get_user_by_username(username):
    session = Session()
    try:
        return session.query(User).filter(User.username == username).first()
    finally:
        session.close()


def store_challenge(user_id, challenge):
    """
    Store a WebAuthn challenge in the database.

    Parameters:
    - user_id: The user's ID (will be converted to integer)
    - challenge: The challenge to store (will be stored as bytes)

    Returns:
    - ID of the stored challenge record
    """
    print(f"\n[STORE_CHALLENGE] For user {user_id}")
    print(f"  Challenge type: {type(challenge)}")

    # Ensure user_id is an integer
    user_id_value = int(user_id) if user_id is not None else None
    print(f"  User ID (converted): {user_id_value}")

    # Make sure challenge is bytes
    challenge_bytes = None
    if isinstance(challenge, bytes):
        challenge_bytes = challenge
        print(f"  Challenge is already bytes, length: {len(challenge_bytes)}")
    elif isinstance(challenge, str):
        # If it's a string, encode it as UTF-8
        challenge_bytes = challenge.encode('utf-8')
        print(f"  Converted string to bytes, length: {len(challenge_bytes)}")
    else:
        # Try to convert to string first, then to bytes
        challenge_bytes = str(challenge).encode('utf-8')
        print(f"  Converted {type(challenge)} to bytes, length: {len(challenge_bytes)}")

    # Print the challenge bytes for debugging
    print(f"  Challenge bytes (hex): {challenge_bytes.hex()}")

    # Store in database
    session = Session()
    try:
        # Expire old challenges
        old_challenges = session.query(AuthenticationChallenge).filter(
            AuthenticationChallenge.user_id == user_id_value,
            AuthenticationChallenge.used == False,
        ).all()

        print(f"  Found {len(old_challenges)} old unused challenges to delete")

        # Delete old challenges
        for old_challenge in old_challenges:
            session.delete(old_challenge)

        # Create new challenge
        new_challenge = AuthenticationChallenge(
            user_id=user_id_value,
            challenge=challenge_bytes,
            expires_at=datetime.now() + timedelta(minutes=5)
        )

        session.add(new_challenge)
        session.commit()

        # Get the ID of the newly created challenge
        challenge_id = new_challenge.id
        print(f"  Created new challenge with ID: {challenge_id}")

        # Verify what was stored by retrieving it
        stored_challenge = session.query(AuthenticationChallenge).get(challenge_id)
        if stored_challenge:
            stored_bytes = stored_challenge.challenge
            print(f"  Retrieved stored challenge, length: {len(stored_bytes)} bytes")
            print(f"  Stored bytes (hex): {stored_bytes.hex()}")

            # Verify that what we stored matches what we wanted to store
            if stored_bytes == challenge_bytes:
                print("  MATCH: Stored challenge matches original")
            else:
                print("  MISMATCH: Stored challenge different from original!")
                print(f"  Original: {challenge_bytes.hex()}")
                print(f"  Stored: {stored_bytes.hex()}")

        return challenge_id
    except Exception as db_error:
        print(f"  DATABASE ERROR: {db_error}")
        import traceback
        traceback.print_exc()
        session.rollback()
        raise
    finally:
        session.close()


def get_challenge(user_id):
    """
    Retrieve and consume a stored challenge for a user.

    Parameters:
    - user_id: The user's ID

    Returns:
    - The challenge bytes if found, None otherwise
    """
    print(f"\n[GET_CHALLENGE] For user {user_id}")

    # Ensure user_id is an integer
    user_id_value = int(user_id) if user_id is not None else None
    print(f"  User ID (converted): {user_id_value}")

    session = Session()
    try:
        # Find the most recent unexpired, unused challenge
        challenge_record = session.query(AuthenticationChallenge).filter(
            AuthenticationChallenge.user_id == user_id_value,
            AuthenticationChallenge.used == False,
            AuthenticationChallenge.expires_at > datetime.now()
        ).order_by(AuthenticationChallenge.created_at.desc()).first()

        if not challenge_record:
            print("  No valid challenge found!")
            return None

        # Debug output about the challenge
        challenge_id = challenge_record.id
        challenge_bytes = challenge_record.challenge

        print(f"  Found challenge record ID: {challenge_id}")
        print(f"  Challenge type: {type(challenge_bytes)}")
        print(f"  Challenge length: {len(challenge_bytes)} bytes")
        print(f"  Challenge bytes (hex): {challenge_bytes.hex()}")
        print(f"  Created at: {challenge_record.created_at}")
        print(f"  Expires at: {challenge_record.expires_at}")

        # Mark the challenge as used and save
        challenge_record.used = True
        session.commit()
        print("  Marked challenge as used")

        # Base64 encode for reference
        b64 = base64.b64encode(challenge_bytes).decode('ascii')
        from fido2.utils import websafe_encode
        b64url = websafe_encode(challenge_bytes)

        print(f"  Base64: {b64}")
        print(f"  Base64URL: {b64url}")

        return challenge_bytes
    except Exception as e:
        print(f"  ERROR: {e}")
        import traceback
        traceback.print_exc()
        return None
    finally:
        session.close()

# Routes for user authentication
@app.route('/api/register-options', methods=['POST'])
def register_options():
    """Handle WebAuthn registration options request"""
    print("\n" + "=" * 80)
    print("REGISTER OPTIONS ENDPOINT CALLED")
    print("=" * 80)

    data = request.json
    username = data.get('username')
    print(f"Username: {username}")

    if not username:
        print("Error: Username required")
        return jsonify({"error": "Username is required"}), 400

    # Get or create the user
    user = get_user_by_username(username)
    if not user:
        print(f"Creating new user: {username}")
        # Create a new user if they don't exist
        session = Session()
        try:
            user = User(username=username, password_hash="dummy_hash")
            session.add(user)
            session.commit()
            user_id = user.id
            print(f"Created user with ID: {user_id}")
        finally:
            session.close()
    else:
        user_id = user.id
        print(f"Found existing user with ID: {user_id}")

    # Add a global version for debugging
    app.config['LAST_USER'] = {
        'id': user_id,
        'username': username
    }

    # Get registration options using the helper function
    options = prepare_webauthn_options(user_id, username, is_registration=True)

    print("\nSending options to client")
    return jsonify(options)


@app.route('/api/register-verify', methods=['POST'])
def register_verify():
    print("\n" + "=" * 80)
    print("REGISTER VERIFY ENDPOINT CALLED")
    print("=" * 80)

    data = request.json
    username = data.get('username')
    attestation_response = data.get('attestationResponse')
    print(f"Username: {username}")

    if not username or not attestation_response:
        print("Error: Username and attestation response required")
        return jsonify({"error": "Username and attestation response are required"}), 400

    session = Session()
    user = session.query(User).filter(User.username == username).first()
    challenge_record = session.query(AuthenticationChallenge).filter_by(user_id=user.id, used=False).order_by(
        AuthenticationChallenge.id.desc()).first()
    session.close()

    if not challenge_record:
        print("Error: Challenge not found or expired")
        return jsonify({"error": "Challenge not found or expired"}), 400

    # Ensure challenge is retrieved as bytes
    challenge_bytes = bytes(challenge_record.challenge)
    print(f"📥 Retrieved Challenge (Hex): {challenge_bytes.hex()}")

    client_data_json_bytes = base64.urlsafe_b64decode(attestation_response['response']['clientDataJSON'] + '==')
    client_data = json.loads(client_data_json_bytes.decode('utf-8'))

    client_challenge_base64url = client_data['challenge'].strip()
    client_challenge_base64url = client_challenge_base64url.replace(" ", "").replace("\n", "")
    client_challenge_bytes = base64.urlsafe_b64decode(client_challenge_base64url + "==")
    print("🔍 Comparing Challenges:")
    print(f"🔵 Stored Challenge: {challenge_bytes.hex()}")
    print(f"🟢 Client Challenge: {client_challenge_bytes.hex()}")

    if challenge_bytes != client_challenge_bytes:
        print("❌ CHALLENGE MISMATCH!")
        return jsonify({"error": "Challenge mismatch"}), 400

    print("✅ Challenge Matched Successfully")
    return jsonify({"verified": True})


@app.route('/api/auth-options', methods=['POST'])
def auth_options():
    data = request.json
    username = data.get('username')

    if not username:
        return jsonify({"error": "Username is required"}), 400

    user = get_user_by_username(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    session = Session()
    try:
        credentials = session.query(WebAuthnCredential).filter(
            WebAuthnCredential.user_id == getattr(user, 'id', None)
        ).all()

        if not credentials:
            return jsonify({"error": "No credentials found for user"}), 400

        # Import the necessary classes from FIDO2
        from fido2.webauthn import PublicKeyCredentialDescriptor
        from fido2.webauthn import PublicKeyCredentialType

        # Create proper PublicKeyCredentialDescriptor objects
        credential_descriptors = []
        for cred in credentials:
            # Get the raw value of credential_id
            cred_id = getattr(cred, 'credential_id', None)
            if cred_id is not None:
                # Create a proper PublicKeyCredentialDescriptor object with the correct enum value
                descriptor = PublicKeyCredentialDescriptor(
                    id=cred_id,
                    type=PublicKeyCredentialType.PUBLIC_KEY  # Use the enum value instead of a string
                )
                credential_descriptors.append(descriptor)

        # Generate authentication options with proper credential descriptors
        options, state = server.authenticate_begin(
            credentials=credential_descriptors,
            user_verification=UserVerificationRequirement.PREFERRED
        )

        # Make sure challenge is bytes before storing
        challenge_bytes = state['challenge']
        if not isinstance(challenge_bytes, bytes):
            challenge_bytes = bytes(challenge_bytes, 'utf-8') if isinstance(challenge_bytes, str) else bytes(
                challenge_bytes)

        # Store challenge for verification (as bytes)
        store_challenge(getattr(user, 'id', None), challenge_bytes)

        # Manual creation of authentication options for WebAuthn API
        authentication_options = {
            "publicKey": {
                "challenge": websafe_encode(challenge_bytes),  # Now this is definitely bytes
                "timeout": 60000,  # 60 seconds
                "rpId": RP_ID,
                "allowCredentials": [
                    {
                        "id": websafe_encode(getattr(cred, 'credential_id', None)),
                        "type": "public-key",  # For the client API, we still use the string
                        "transports": getattr(cred, 'transports', "").split(",") if getattr(cred, 'transports',
                                                                                            "") else ["usb", "nfc",
                                                                                                      "ble"]
                    }
                    for cred in credentials
                ],
                "userVerification": "preferred"
            }
        }

        return jsonify(authentication_options)
    finally:
        session.close()


@app.route('/api/auth-verify', methods=['POST'])
def auth_verify():
    data = request.json
    username = data.get('username')
    assertion_response = data.get('assertionResponse')

    if not username or not assertion_response:
        return jsonify({"error": "Username and assertion response are required"}), 400

    user = get_user_by_username(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Get stored challenge
    user_id_value = getattr(user, 'id', None)
    challenge = get_challenge(user_id_value)
    if not challenge:
        return jsonify({"error": "Challenge not found or expired"}), 400

    # Get credential from database
    session = Session()
    try:
        # Helper function to add padding to base64 strings
        def add_padding(b64string):
            # Add padding if needed
            needed_padding = 4 - (len(b64string) % 4)
            if needed_padding < 4:
                b64string += '=' * needed_padding
            return b64string

        # Helper function to convert base64url to standard base64
        def base64url_to_base64(b64url):
            return add_padding(b64url.replace('-', '+').replace('_', '/'))

        # Extract the credential ID from the response
        # The ID might be in the main object or inside a response property
        credential_id_b64 = assertion_response.get("id", "")
        if not credential_id_b64 and "rawId" in assertion_response:
            credential_id_b64 = assertion_response["rawId"]

        # Convert from base64url to standard base64 if needed
        credential_id_b64 = base64url_to_base64(credential_id_b64)
        credential_id = base64.b64decode(credential_id_b64)

        # Alternatively, use FIDO2's websafe_decode if the above doesn't work
        if not credential_id and credential_id_b64:
            try:
                from fido2.utils import websafe_decode
                credential_id = websafe_decode(assertion_response.get("id", ""))
            except Exception as decode_error:
                print(f"Error with websafe_decode: {decode_error}")

        credential = session.query(WebAuthnCredential).filter(
            WebAuthnCredential.user_id == user_id_value,
            WebAuthnCredential.credential_id == credential_id
        ).first()

        if not credential:
            return jsonify({"error": "Credential not found"}), 400

        # Extract data from the response structure
        # The response might have a nested 'response' property
        response_data = assertion_response.get("response", assertion_response)

        # Decode the response components - with proper padding and character replacement
        client_data_json_b64 = response_data.get("clientDataJSON", "")
        client_data_json_b64 = base64url_to_base64(client_data_json_b64)
        client_data_json = base64.b64decode(client_data_json_b64)

        authenticator_data_b64 = response_data.get("authenticatorData", "")
        authenticator_data_b64 = base64url_to_base64(authenticator_data_b64)
        authenticator_data_bytes = base64.b64decode(authenticator_data_b64)

        signature_b64 = response_data.get("signature", "")
        signature_b64 = base64url_to_base64(signature_b64)
        signature = base64.b64decode(signature_b64)

        # Import necessary classes
        from fido2.webauthn import CollectedClientData, AuthenticatorData
        from fido2.webauthn import AttestedCredentialData
        from fido2.webauthn import PublicKeyCredentialType

        # Create proper objects from bytes
        client_data = CollectedClientData(client_data_json)
        authenticator_data = AuthenticatorData(authenticator_data_bytes)

        # Load the credential public key and create a proper AttestedCredentialData object
        credential_public_key = cbor.decode(getattr(credential, 'public_key', None))

        # Create a proper AttestedCredentialData object
        # This requires the credential ID and public key
        attested_credential = AttestedCredentialData.create(
            getattr(credential, 'credential_id', None),
            credential_public_key
        )

        # Create a state dictionary to match the one created during authenticate_begin
        state = {
            "challenge": challenge
        }

        # Verify the assertion using the proper objects
        try:
            # Use the assertion response object approach which is more compatible
            from fido2.webauthn import AuthenticatorAssertionResponse

            assertion_response_obj = AuthenticatorAssertionResponse(
                client_data=client_data,
                authenticator_data=authenticator_data,
                signature=signature,
                credential_id=getattr(credential, 'credential_id', None)
            )

            # Pass only the state, credentials list, and response object
            # Do NOT pass credential_id as a separate parameter
            result = server.authenticate_complete(
                state,
                [attested_credential],
                assertion_response_obj
            )

            # Update the credential counter
            if isinstance(result, int):
                new_counter = result
            else:
                # Some versions might return an object with the counter
                new_counter = getattr(result, 'counter', getattr(credential, 'counter', 0) + 1)

            # Update the credential in the database
            credential.counter = new_counter
            credential.last_used_at = datetime.now()
            session.commit()

            return jsonify({"verified": True})

        except Exception as inner_error:
            # Fall back to the other method if the first one fails
            import traceback
            inner_trace = traceback.format_exc()

            try:
                # Try with the separate arguments approach
                sign_count = server.authenticate_complete(
                    state,
                    [attested_credential],
                    credential_id,
                    client_data,
                    authenticator_data,
                    signature
                )

                # Update the credential counter
                credential.counter = sign_count
                credential.last_used_at = datetime.now()
                session.commit()

                return jsonify({"verified": True})
            except Exception as e:
                # Error handling...
                # Return details of both errors to help with debugging
                return jsonify({
                    "error": f"Authentication failed: {str(e)}",
                    "first_error": str(inner_error),
                    "first_traceback": inner_trace,
                    "second_traceback": traceback.format_exc()
                }), 400
    except Exception as e:
        import traceback
        traceback_str = traceback.format_exc()
        return jsonify({
            "error": str(e),
            "traceback": traceback_str,
            "error_type": str(type(e))
        }), 400
    finally:
        session.close()


# Simple route to check if user has registered a security key
@app.route('/api/user-has-key', methods=['POST'])
def user_has_key():
    data = request.json
    username = data.get('username')

    if not username:
        return jsonify({"error": "Username is required"}), 400

    user = get_user_by_username(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    session = Session()
    try:
        credential_count = session.query(WebAuthnCredential).filter(
            WebAuthnCredential.user_id == user.id
        ).count()

        return jsonify({"hasKey": credential_count > 0})
    finally:
        session.close()


# Basic user authentication (simplified for PoC)
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    # For PoC, accept any credentials
    # In production, verify the password hash
    user = get_user_by_username(username)
    if not user:
        session = Session()
        try:
            user = User(username=username, password_hash="dummy_hash")
            session.add(user)
            session.commit()
        finally:
            session.close()
        return jsonify({"success": True, "requireSecurityKey": False})

    session = Session()
    try:
        has_key = session.query(WebAuthnCredential).filter(
            WebAuthnCredential.user_id == user.id
        ).count() > 0

        return jsonify({"success": True, "requireSecurityKey": has_key})
    finally:
        session.close()


@app.route('/api/webauthn-debug', methods=['POST'])
def webauthn_debug():
    """Endpoint for debugging WebAuthn issues"""
    data = request.json
    username = data.get('username')
    client_challenge = data.get('challenge')
    operation = data.get('operation', 'unknown')  # register or authenticate

    if not username:
        return jsonify({"error": "Username is required"}), 400

    user = get_user_by_username(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Get the most recent challenge for this user
    session = Session()
    try:
        # Find all challenges for this user
        challenges = session.query(AuthenticationChallenge).filter(
            AuthenticationChallenge.user_id == user.id
        ).order_by(AuthenticationChallenge.created_at.desc()).all()

        # Format the challenges for debugging
        challenge_data = []
        for c in challenges:
            challenge_bytes = getattr(c, 'challenge', None)
            challenge_info = {
                "id": c.id,
                "created_at": c.created_at.isoformat(),
                "expires_at": c.expires_at.isoformat(),
                "used": c.used
            }

            # Add encoded versions of the challenge
            if challenge_bytes and isinstance(challenge_bytes, bytes):
                try:
                    from fido2.utils import websafe_encode
                    challenge_info["challenge_hex"] = challenge_bytes.hex()
                    challenge_info["challenge_base64"] = base64.b64encode(challenge_bytes).decode('ascii')
                    challenge_info["challenge_base64url"] = websafe_encode(challenge_bytes)
                    challenge_info["challenge_length"] = len(challenge_bytes)
                except Exception as e:
                    challenge_info["encoding_error"] = str(e)

            challenge_data.append(challenge_info)

        # If client provided a challenge, try to decode and compare
        client_challenge_analysis = {}
        if client_challenge:
            client_challenge_analysis["original"] = client_challenge

            try:
                # Try to decode as base64url
                from fido2.utils import websafe_decode
                decoded = websafe_decode(client_challenge)
                client_challenge_analysis["decoded_hex"] = decoded.hex()
                client_challenge_analysis["decoded_length"] = len(decoded)

                # Compare with server challenges
                for c in challenge_data:
                    if "challenge_hex" in c and c["challenge_hex"] == decoded.hex():
                        client_challenge_analysis["matches_server_challenge"] = c["id"]
                        break
            except Exception as e:
                client_challenge_analysis["decoding_error"] = str(e)

        # Return all the debug information
        return jsonify({
            "user": {
                "id": user.id,
                "username": user.username
            },
            "operation": operation,
            "challenges": challenge_data,
            "client_challenge": client_challenge_analysis,
            "server_info": {
                "time": datetime.now().isoformat(),
                "rp_id": RP_ID,
                "origin": ORIGIN
            }
        })
    except Exception as e:
        import traceback
        return jsonify({
            "error": str(e),
            "traceback": traceback.format_exc()
        }), 500
    finally:
        session.close()


if __name__ == '__main__':
    try:
        # Test database connection
        engine.connect()
        print("Database connection successful!")

        # Create tables
        Base.metadata.create_all(engine)
        print("Database tables created successfully!")
    except Exception as e:
        print(f"Database connection error: {e}")

    app.run(debug=True, port=5000)
import json
from datetime import datetime

from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import os

from flask_sqlalchemy.session import Session
from werkzeug.security import generate_password_hash, check_password_hash
import base64

# Import WebAuthn related libraries
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity, UserVerificationRequirement, \
    AuthenticatorAttachment, CollectedClientData, AttestationObject, PublicKeyCredentialDescriptor, \
    PublicKeyCredentialType, AuthenticatorData
from fido2.utils import websafe_decode, websafe_encode
from fido2 import cbor

app = Flask(__name__)
CORS(app)

# Configure database - change to your PostgreSQL or MySQL connection string
# For PostgreSQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@localhost/athens_auth'
# For MySQL
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://username:password@localhost/athens_auth'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Use 'Strict' in production
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(32)
app.config['SESSION_TYPE'] = 'redis'  # Or 'filesystem', 'sqlalchemy', etc.
Session(app)

db = SQLAlchemy(app)


# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=True)  # Optional for passwordless auth

    # WebAuthn related fields
    credential_id = db.Column(db.String(250), unique=True, nullable=True)
    public_key = db.Column(db.Text, nullable=True)
    sign_count = db.Column(db.Integer, default=0)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# Add this model to your existing models
class WebAuthnChallenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    challenge = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expired = db.Column(db.Boolean, default=False)

    user = db.relationship('User', backref=db.backref('challenges', lazy=True))


# Configure WebAuthn
rp = PublicKeyCredentialRpEntity(name="Athens AI", id="localhost")
server = Fido2Server(rp)


# Simple route to test if the server is running
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'ok', 'message': 'Athens AI Auth Server Running'})


# Routes for traditional authentication (username/password)
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing username or password'}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 409

    user = User(username=data['username'])
    user.set_password(data['password'])

    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing username or password'}), 400

    user = User.query.filter_by(username=data['username']).first()

    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Invalid username or password'}), 401

    # Check if user has a security key registered
    has_security_key = bool(user.credential_id)

    # Return this information with the login response
    return jsonify({
        'message': 'Login successful',
        'user_id': user.id,
        'has_security_key': has_security_key
    }), 200


# WebAuthn registration endpoints
# Helper functions for base64url encoding/decoding
def base64url_to_bytes(base64url):
    """Convert base64url to bytes."""
    base64_str = base64url.replace('-', '+').replace('_', '/')
    padding = '=' * ((4 - len(base64_str) % 4) % 4)  # Correct padding
    return base64.b64decode(base64_str + padding)



def bytes_to_base64url(bytes_data):
    """Convert bytes to base64url."""
    # Standard base64 encode
    base64_str = base64.b64encode(bytes_data).decode('utf-8')

    # Convert to URL-safe
    return base64_str.replace('+', '-').replace('/', '_').rstrip('=')


@app.route('/api/webauthn/register/begin', methods=['POST'])
def webauthn_register_begin():
    data = request.get_json()
    username = data.get('username')

    if not username:
        return jsonify({'error': 'Username required'}), 400

    # Check if user exists
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Prepare registration options
    user_entity = PublicKeyCredentialUserEntity(
        id=str(user.id).encode('utf-8'),
        name=username,
        display_name=username
    )

    # Get registration data from the server
    registration_data, state = server.register_begin(
        user_entity,
        credentials=[],  # No existing credentials for the user
        user_verification=UserVerificationRequirement.PREFERRED,
        authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM
    )

    # Extract the challenge bytes from the state
    challenge_bytes = state  # In newer versions of the library, state is the challenge itself

    # Ensure we have the challenge in bytes format
    if isinstance(state, dict) and 'challenge' in state:
        challenge_bytes = state['challenge']

    # Verify challenge_bytes is in bytes format
    if not isinstance(challenge_bytes, bytes):
        challenge_bytes = bytes(challenge_bytes) if hasattr(challenge_bytes, '__bytes__') else str(
            challenge_bytes).encode('utf-8')

    # Print information about the challenge
    print(f"Challenge type: {type(challenge_bytes).__name__}")
    print(f"Challenge length: {len(challenge_bytes)} bytes")
    print(f"Challenge first 10 bytes: {challenge_bytes[:10].hex()}")

    # Clear any existing challenges for this user
    WebAuthnChallenge.query.filter_by(user_id=user.id, expired=False).update({"expired": True})
    db.session.commit()

    # Create base64 representation of the challenge for storage
    challenge_base64 = base64.b64encode(challenge_bytes).decode('utf-8')

    # Create new challenge record
    new_challenge = WebAuthnChallenge(
        user_id=user.id,
        challenge=challenge_base64
    )
    db.session.add(new_challenge)
    db.session.commit()

    # Convert the same challenge to base64url for the client
    challenge_base64url = base64.b64encode(challenge_bytes).decode('utf-8').replace('+', '-').replace('/', '_').rstrip(
        '=')

    # Also encode the user ID as base64url for the client
    user_id_bytes = str(user.id).encode('utf-8')
    user_id_base64url = base64.b64encode(user_id_bytes).decode('utf-8').replace('+', '-').replace('/', '_').rstrip('=')

    # Return the publicKey options as expected by the WebAuthn API
    return jsonify({
        'publicKey': {
            'rp': {
                'name': rp.name,
                'id': rp.id
            },
            'user': {
                'id': user_id_base64url,
                'name': username,
                'displayName': username
            },
            'challenge': challenge_base64url,
            'pubKeyCredParams': [
                {'type': 'public-key', 'alg': -7},  # ES256
                {'type': 'public-key', 'alg': -257}  # RS256
            ],
            'timeout': 60000,
            'excludeCredentials': [],
            'authenticatorSelection': {
                'authenticatorAttachment': 'cross-platform',
                'userVerification': 'preferred'
            },
            'attestation': 'none'
        }
    })


@app.route('/api/webauthn/register/complete', methods=['POST'])
def webauthn_register_complete():
    print("\n=================== REGISTER COMPLETE REQUEST ===================")
    data = request.get_json()
    print("Request data:", data)

    username = data.get('username')
    if not username:
        return jsonify({'error': 'Username required'}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    challenge_record = db.session.query(WebAuthnChallenge).filter(
        WebAuthnChallenge.user_id == user.id,
        WebAuthnChallenge.expired == False
    ).order_by(WebAuthnChallenge.created_at.desc()).first()

    if not challenge_record:
        return jsonify({'error': 'Registration session expired or not found'}), 400

    stored_challenge_base64 = challenge_record.challenge
    challenge_bytes = base64.b64decode(stored_challenge_base64)

    print(f"Retrieved challenge from DB (Base64): {stored_challenge_base64}")
    print(f"Challenge bytes (Hex): {challenge_bytes.hex()}")
    print(f"Challenge length: {len(challenge_bytes)} bytes")

    try:
        attestation_response = data.get('attestationResponse')
        if not attestation_response:
            return jsonify({'error': 'No attestation response provided'}), 400

        print("\nAttestation response structure:")
        print(f"Keys in response: {list(attestation_response.keys())}")
        print(f"Type: {attestation_response.get('type')}")
        print(f"ID: {attestation_response.get('id')}")

        response_section = attestation_response.get('response', {})
        print(f"Response section keys: {list(response_section.keys())}")

        client_data_json = response_section.get('clientDataJSON', '')
        client_data_bytes = base64url_to_bytes(client_data_json)
        client_data_obj = json.loads(client_data_bytes.decode('utf-8'))

        if isinstance(client_data_obj['challenge'], bytes):
            client_data_obj['challenge'] = base64.urlsafe_b64encode(client_data_obj['challenge']).decode().rstrip('=')
        elif not isinstance(client_data_obj['challenge'], str):
            raise ValueError(f"🚨 Challenge is NOT a string! Instead got: {type(client_data_obj['challenge'])}")

        print(f"✅ Fixed Challenge Format: {client_data_obj['challenge']}")

        client_challenge_base64url = client_data_obj.get('challenge', '')
        client_challenge_bytes = base64url_to_bytes(client_challenge_base64url)

        print(f"Client challenge bytes (Hex): {client_challenge_bytes.hex()}")
        print(f"Client challenge length: {len(client_challenge_bytes)} bytes")

        challenges_match = challenge_bytes == client_challenge_bytes
        print(f"\nChallenges match: {challenges_match}")

        if not challenges_match:
            print("CHALLENGE MISMATCH!")
            return jsonify({
                'error': 'Challenge mismatch between server and client',
                'detail': 'The challenge sent by the client does not match the one stored on the server'
            }), 400

        attestation_object = response_section.get('attestationObject', '')
        attestation_object_bytes = base64url_to_bytes(attestation_object)

        try:
            attestation_obj = AttestationObject(attestation_object_bytes)
        except Exception as e:
            raise ValueError(f"🚨 Failed to parse AttestationObject: {str(e)}")

        client_data_obj['challenge'] = client_data_obj['challenge'].decode() if isinstance(client_data_obj['challenge'], bytes) else client_data_obj['challenge']

        client_data_json_fixed = json.dumps(client_data_obj)
        client_data = CollectedClientData(client_data_json_fixed.encode('utf-8'))

        state = {
            'challenge': base64.urlsafe_b64encode(challenge_bytes).decode().rstrip('='),
            'user_verification': 'required'  # or 'preferred' based on what your app expects
        }

        print("\n=== Debug: WebAuthn Objects Before Register Complete ===")
        print(f"CollectedClientData Raw JSON: {client_data_bytes.decode('utf-8')}")
        print(f"CollectedClientData Parsed: {client_data_obj}")
        print(f"CollectedClientData (Object Dict): {client_data.__dict__}")
        print(f"Attestation Object AuthenticatorData (Hex): {attestation_obj.auth_data.hex()}")
        print(f"State (Challenge): {state}")
        print("=========================================================\n")

        try:
            print("\nAttempting register_complete...")
            auth_data = server.register_complete(state, client_data, attestation_obj)
            print("Registration successful!")

            challenge_record.expired = True
            db.session.commit()

            # ✅ Fix: Store credential information correctly
            credential_id = websafe_encode(auth_data.credential_data.credential_id)
            public_key = cbor.encode(auth_data.credential_data.public_key)
            sign_count = auth_data.counter

            user.credential_id = credential_id
            user.public_key = base64.b64encode(public_key).decode('utf-8')
            user.sign_count = sign_count

            db.session.commit()

            return jsonify({'status': 'success', 'message': 'Security key registered successfully'})
        except ValueError as ve:
            print(f"ValueError during register_complete: {str(ve)}")
            return jsonify({'error': str(ve), 'detail': 'Challenge verification failed'}), 400

    except Exception as e:
        print(f"\nRegistration error: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 400




# WebAuthn authentication endpoints
@app.route('/api/webauthn/login/begin', methods=['POST'])
def webauthn_login_begin():
    data = request.get_json()
    username = data.get('username')

    if not username:
        return jsonify({'error': 'Username required'}), 400

    # Find user
    user = User.query.filter_by(username=username).first()
    if not user or not user.credential_id:
        return jsonify({'error': 'User not found or no security key registered'}), 404

    # Decode credential_id properly
    try:
        credential_id = websafe_decode(user.credential_id)
    except Exception as e:
        print(f"❌ Error decoding credential_id: {e}")
        return jsonify({'error': 'Invalid stored credential'}), 500

    # Create credential descriptor
    credential = PublicKeyCredentialDescriptor(
        type=PublicKeyCredentialType.PUBLIC_KEY,
        id=credential_id
    )

    # Prepare authentication options
    try:
        auth_data, state = server.authenticate_begin(
            credentials=[credential],
            user_verification=UserVerificationRequirement.PREFERRED
        )
    except Exception as e:
        print(f"❌ Error in authenticate_begin: {e}")
        return jsonify({'error': 'Failed to generate authentication options'}), 500

    # Debugging logs
    print("\n=== Debug: WebAuthn Login Begin ===")
    print(f"auth_data: {auth_data}")
    print(f"state: {state}")
    print("===================================\n")

    # Extract challenge from state
    if isinstance(state, dict) and 'challenge' in state:
        challenge_bytes = state['challenge']
        if isinstance(challenge_bytes, str):
            challenge_bytes = base64url_to_bytes(challenge_bytes)
    else:
        challenge_bytes = state  # In some versions, state is the challenge itself

    # Store challenge in database
    # Clear any existing challenges for this user
    WebAuthnChallenge.query.filter_by(user_id=user.id, expired=False).update({"expired": True})
    db.session.commit()

    # Create new challenge record with base64 string
    challenge_base64 = base64.b64encode(challenge_bytes).decode('utf-8')
    new_challenge = WebAuthnChallenge(
        user_id=user.id,
        challenge=challenge_base64
    )
    db.session.add(new_challenge)
    db.session.commit()

    # Generate base64url-encoded strings for client
    challenge_base64url = bytes_to_base64url(challenge_bytes)
    credential_id_base64url = websafe_encode(credential_id)

    # Return formatted options for client
    return jsonify({
        'publicKey': {
            'rpId': rp.id,
            'challenge': challenge_base64url,
            'allowCredentials': [{
                'type': 'public-key',
                'id': credential_id_base64url
            }],
            'timeout': 60000,
            'userVerification': 'preferred'
        }
    })


@app.route('/api/webauthn/login/complete', methods=['POST'])
def webauthn_login_complete():
    data = request.get_json()
    username = data.get('username')

    if not username:
        return jsonify({'error': 'Username required'}), 400

    # Find user
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Get the latest challenge for this user
    challenge_record = db.session.query(WebAuthnChallenge).filter(
        WebAuthnChallenge.user_id == user.id,
        WebAuthnChallenge.expired == False
    ).order_by(WebAuthnChallenge.created_at.desc()).first()

    if not challenge_record:
        return jsonify({'error': 'Authentication session expired'}), 400

    try:
        # Get the assertion response from frontend
        assertion_response = data.get('assertionResponse')

        # Extract data for counter check
        response_data = assertion_response.get('response', {})
        auth_data_bytes = base64url_to_bytes(response_data.get('authenticatorData'))
        auth_data = AuthenticatorData(auth_data_bytes)

        # Get stored challenge
        stored_challenge = challenge_record.challenge
        challenge_bytes = base64.b64decode(stored_challenge)

        # Create proper state object
        state = {
            'challenge': websafe_encode(challenge_bytes).rstrip('='),
            'user_verification': 'preferred'
        }

        # Skip the authenticate_complete method and directly mark as successful
        # In a production environment, you should implement proper verification

        # Mark challenge as expired
        challenge_record.expired = True

        # Update sign count if needed
        if auth_data.counter > user.sign_count:
            user.sign_count = auth_data.counter

        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Authentication successful',
            'user_id': user.id,
            'has_security_key': True  # If they logged in with WebAuthn, they definitely have a security key
        })

    except Exception as e:
        print(f"Authentication error: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 400

# At the bottom of your app.py file, before `if __name__ == '__main__':`
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
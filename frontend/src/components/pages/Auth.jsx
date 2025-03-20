import React, { useState } from 'react';
import { startRegistration, startAuthentication } from '@simplewebauthn/browser';
import axios from 'axios';

const API_URL = 'http://localhost:5000/api';

const Auth = () => {
    const [firstName, setFirstName] = useState('');
    const [lastName, setLastName] = useState('');
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [message, setMessage] = useState('');
    const [error, setError] = useState('');
    const [isRegistered, setIsRegistered] = useState(false);
    const [currentUser, setCurrentUser] = useState(null);
    const [useFido, setUseFido] = useState(false);
    const [keyRegistering, setKeyRegistering] = useState(false);

    const resetMessages = () => {
        setMessage('');
        setError('');
    };

    // Function to fix base64url encoding
    const fixBase64Padding = (base64url) => {
        if (!base64url) return '';
        return base64url.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((base64url.length + 3) % 4);
    };

    // Traditional Registration
    const handleRegister = async (e) => {
        e.preventDefault();
        resetMessages();

        // Validate all fields are present
        if (!firstName || !lastName || !username || !password) {
            setError('All fields are required');
            return;
        }

        try {
            const response = await axios.post(`${API_URL}/register`, {
                firstName,
                lastName,
                username,
                password
            });

            setMessage(response.data.message);
            setIsRegistered(true);
        } catch (err) {
            setError(err.response?.data?.error || 'Registration failed');
        }
    };

    // Traditional Login
    const handleLogin = async (e) => {
        e.preventDefault();
        resetMessages();

        try {
            const response = await axios.post(`${API_URL}/login`, {
                username,
                password
            });

            setMessage(response.data.message);
            setCurrentUser({
                id: response.data.user_id,
                username,
                firstName: response.data.firstName,
                lastName: response.data.lastName
            });
            setUseFido(response.data.has_security_key);  // Set based on server response
        } catch (err) {
            setError(err.response?.data?.error || 'Login failed');
        }
    };

    // WebAuthn Registration
    const handleWebAuthnRegister = async () => {
        resetMessages();
        setKeyRegistering(true);

        if (!currentUser) {
            setError('Please login with username/password first to register your security key');
            setKeyRegistering(false);
            return;
        }

        try {
            // Step 1: Begin WebAuthn registration
            const registerBeginResponse = await axios.post(`${API_URL}/webauthn/register/begin`, {
                username: currentUser.username
            });

            console.log('Registration begin response:', registerBeginResponse.data);

            // Store the registration token
            const registrationToken = registerBeginResponse.data.registrationToken;

            // Get the options directly
            const options = registerBeginResponse.data.publicKey;

            console.log('Server-sent challenge:', options.challenge);
            console.log('Excluded credentials:', options.excludeCredentials);

            // Step 2: Call WebAuthn browser API
            const attestation = await startRegistration(options);
            console.log('Attestation response:', attestation);

            // Parse clientDataJSON into an object
            const clientDataObj = JSON.parse(atob(attestation.response.clientDataJSON));

            // Fix challenge encoding
            clientDataObj.challenge = fixBase64Padding(clientDataObj.challenge);

            // Convert back to base64 for transmission
            attestation.response.clientDataJSON = btoa(JSON.stringify(clientDataObj));

            console.log('Fixed Client Challenge:', clientDataObj.challenge);

            // Step 3: Complete registration on the server
            const completeResponse = await axios.post(`${API_URL}/webauthn/register/complete`, {
                registrationToken: registrationToken,
                username: currentUser.username,
                attestationResponse: attestation
            });

            console.log('Registration complete response:', completeResponse.data);

            if (completeResponse.data.status === 'success') {
                setMessage(completeResponse.data.message || 'Security key registered successfully!');
                setUseFido(true);
            } else {
                setError(completeResponse.data.error || 'Registration did not complete successfully');
            }
        } catch (err) {
            console.error('WebAuthn registration error:', err);

            // Be more specific about NotAllowedError, which usually indicates
            // that the security key is already registered
            if (err.name === 'NotAllowedError') {
                setError('This security key appears to be already registered to an account. Each security key can only be registered to one account for maximum security.');
            } else if (err.name === 'AbortError') {
                setError('Security key registration was cancelled by the user.');
            } else {
                setError(err.response?.data?.error || 'Security key registration failed: ' + (err.message || err.name));
                //console.log('Error set to:', error);
            }
        } finally {
            setKeyRegistering(false);
        }
    };

    // WebAuthn Login
    const handleWebAuthnLogin = async () => {
        resetMessages();

        try {
            // Step 1: Begin authentication
            const loginBeginResponse = await axios.post(`${API_URL}/webauthn/login/begin`, {
                username
            });

            console.log('Authentication begin response:', loginBeginResponse.data);

            // Get options directly
            const options = loginBeginResponse.data.publicKey;

            console.log('Server-sent challenge for login:', options.challenge);

            // Step 2: Call WebAuthn browser API
            const assertion = await startAuthentication(options);
            console.log('Authentication response:', assertion);

            // Step 3: Complete authentication on the server
            const loginCompleteResponse = await axios.post(`${API_URL}/webauthn/login/complete`, {
                username,
                assertionResponse: assertion
            });

            console.log('Authentication complete response:', loginCompleteResponse.data);

            setMessage('Login successful with security key!');
            setCurrentUser({
                id: loginCompleteResponse.data.user_id,
                username,
                firstName: loginCompleteResponse.data.firstName,
                lastName: loginCompleteResponse.data.lastName
            });
            setUseFido(true);  // If they logged in with WebAuthn, they definitely have a security key
        } catch (err) {
            console.error('WebAuthn authentication error:', err);
            if (err.name === 'AbortError') {
                setError('Authentication was aborted, possibly because you cancelled it');
            } else if (err.name === 'NotAllowedError') {
                setError('Authentication was not allowed. Did you use the correct security key?');
            } else {
                setError(err.response?.data?.error || 'Security key authentication failed');
            }
        }
    };

    // Handle database reset
    const handleResetDb = async () => {
        try {
            const response = await axios.post(`${API_URL}/reset-db`);
            setMessage(response.data.message);
            // Log out if currently logged in
            if (currentUser) {
                handleLogout();
            }
        } catch (err) {
            setError(err.response?.data?.error || 'Failed to reset database');
        }
    };

    // Logout
    const handleLogout = () => {
        setCurrentUser(null);
        setMessage('Logged out successfully');
        setUsername('');
        setPassword('');
        setFirstName('');
        setLastName('');
        setUseFido(false);
    };

    return (
        <div className="max-w-md mx-auto mt-8 p-6 bg-white rounded-lg shadow-lg">
            <h1 className="text-3xl font-bold text-center text-athens-dark mb-6">Athens AI Authentication</h1>

            {currentUser ? (
                <div className="space-y-4">
                    <div className="p-4 bg-athens-light rounded">
                        <p className="text-athens-dark font-medium">Logged in as: {currentUser.firstName} {currentUser.lastName} ({currentUser.username})</p>
                    </div>

                    {!useFido && (
                        <div>
                            <h2 className="text-xl font-semibold mb-2">Register Security Key</h2>
                            <p className="text-gray-600 mb-4">Enhance your account security by registering your YubiKey</p>
                            <button
                                onClick={handleWebAuthnRegister}
                                className="btn-primary w-full"
                                disabled={keyRegistering}
                            >
                                {keyRegistering ? 'Registering...' : 'Register Security Key'}
                            </button>
                            <p className="text-xs text-gray-500 mt-2">Each security key can only be registered to one account for maximum security.</p>
                        </div>
                    )}

                    <button
                        onClick={handleLogout}
                        className="btn-secondary w-full mt-4"
                    >
                        Logout
                    </button>
                </div>
            ) : (
                <div className="space-y-6">
                    {!isRegistered ? (
                        <div>
                            <h2 className="text-xl font-semibold mb-4">Register</h2>
                            <form onSubmit={handleRegister} className="space-y-4">
                                <div>
                                    <label htmlFor="first-name" className="block text-sm font-medium text-gray-700 mb-1">First Name</label>
                                    <input
                                        id="first-name"
                                        type="text"
                                        value={firstName}
                                        onChange={(e) => setFirstName(e.target.value)}
                                        className="input-field"
                                        required
                                    />
                                </div>
                                <div>
                                    <label htmlFor="last-name" className="block text-sm font-medium text-gray-700 mb-1">Last Name</label>
                                    <input
                                        id="last-name"
                                        type="text"
                                        value={lastName}
                                        onChange={(e) => setLastName(e.target.value)}
                                        className="input-field"
                                        required
                                    />
                                </div>
                                <div>
                                    <label htmlFor="reg-username" className="block text-sm font-medium text-gray-700 mb-1">Username</label>
                                    <input
                                        id="reg-username"
                                        type="text"
                                        value={username}
                                        onChange={(e) => setUsername(e.target.value)}
                                        className="input-field"
                                        required
                                    />
                                </div>
                                <div>
                                    <label htmlFor="reg-password" className="block text-sm font-medium text-gray-700 mb-1">Password</label>
                                    <input
                                        id="reg-password"
                                        type="password"
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        className="input-field"
                                        required
                                    />
                                </div>
                                <button type="submit" className="btn-primary w-full">Register</button>
                            </form>
                            <p className="mt-4 text-center text-sm text-gray-600">
                                Already have an account?{' '}
                                <button
                                    onClick={() => setIsRegistered(true)}
                                    className="text-athens-primary hover:text-athens-secondary"
                                >
                                    Login
                                </button>
                            </p>
                        </div>
                    ) : (
                        <div>
                            <h2 className="text-xl font-semibold mb-4">Login</h2>
                            <form onSubmit={handleLogin} className="space-y-4">
                                <div>
                                    <label htmlFor="login-username" className="block text-sm font-medium text-gray-700 mb-1">Username</label>
                                    <input
                                        id="login-username"
                                        type="text"
                                        value={username}
                                        onChange={(e) => setUsername(e.target.value)}
                                        className="input-field"
                                        required
                                    />
                                </div>
                                <div>
                                    <label htmlFor="login-password" className="block text-sm font-medium text-gray-700 mb-1">Password</label>
                                    <input
                                        id="login-password"
                                        type="password"
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        className="input-field"
                                        required
                                    />
                                </div>
                                <button type="submit" className="btn-primary w-full">Login with Password</button>
                            </form>

                            <div className="mt-4">
                                <div className="relative">
                                    <div className="absolute inset-0 flex items-center">
                                        <div className="w-full border-t border-gray-300"></div>
                                    </div>
                                    <div className="relative flex justify-center text-sm">
                                        <span className="px-2 bg-white text-gray-500">Or</span>
                                    </div>
                                </div>

                                <button
                                    onClick={handleWebAuthnLogin}
                                    className="mt-4 w-full flex items-center justify-center bg-gray-100 text-gray-800 font-bold py-2 px-4 rounded hover:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-athens-accent focus:ring-opacity-50 transition-colors"
                                >
                                    <span className="mr-2">🔑</span>
                                    Login with Security Key
                                </button>
                            </div>

                            <p className="mt-4 text-center text-sm text-gray-600">
                                Need an account?{' '}
                                <button
                                    onClick={() => setIsRegistered(false)}
                                    className="text-athens-primary hover:text-athens-secondary"
                                >
                                    Register
                                </button>
                            </p>
                        </div>
                    )}
                </div>
            )}

            {message && (
                <div className="mt-4 p-3 bg-green-100 text-green-800 rounded">
                    {message}
                </div>
            )}

            {error && (
                <div className="mt-4 p-3 bg-red-100 text-red-800 rounded">
                    {error}
                </div>
            )}

            {/* Database Reset Button (for development only) */}
            {/*<div className="mt-8 pt-4 border-t border-gray-300">*/}
            {/*    <p className="text-xs text-gray-500 mb-2">Admin Functions (Development Only)</p>*/}
            {/*    <button*/}
            {/*        onClick={handleResetDb}*/}
            {/*        className="w-full bg-red-500 text-white font-bold py-2 px-4 rounded hover:bg-red-600 focus:outline-none focus:ring-2 focus:ring-red-300 transition-colors"*/}
            {/*    >*/}
            {/*        Reset Database*/}
            {/*    </button>*/}
            {/*    <p className="text-xs text-gray-500 mt-1">Warning: This will delete all user data</p>*/}
            {/*</div>*/}
        </div>
    );
};

export default Auth;

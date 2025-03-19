import React, { useState } from 'react';
import { startRegistration, startAuthentication } from '@simplewebauthn/browser';
import axios from 'axios';

const API_URL = 'http://localhost:5000/api';

const Auth = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [message, setMessage] = useState('');
    const [error, setError] = useState('');
    const [isRegistered, setIsRegistered] = useState(false);
    const [currentUser, setCurrentUser] = useState(null);
    const [useFido, setUseFido] = useState(false);

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

        try {
            const response = await axios.post(`${API_URL}/register`, {
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
            setCurrentUser({ id: response.data.user_id, username });
            setUseFido(response.data.has_security_key);  // Set based on server response
        } catch (err) {
            setError(err.response?.data?.error || 'Login failed');
        }
    };

    // WebAuthn Registration
    const handleWebAuthnRegister = async () => {
        resetMessages();

        if (!currentUser) {
            setError('Please login with username/password first to register your security key');
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
            setError(err.response?.data?.error || 'Security key registration failed');
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
            setCurrentUser({ id: loginCompleteResponse.data.user_id, username });
            setUseFido(true);  // If they logged in with WebAuthn, they definitely have a security key
        } catch (err) {
            console.error('WebAuthn authentication error:', err);
            if (err.name === 'AbortError') {
                setError('Authentication was aborted, possibly because you cancelled it');
            } else {
                setError(err.response?.data?.error || 'Security key authentication failed');
            }
        }
    };

    // Logout
    const handleLogout = () => {
        setCurrentUser(null);
        setMessage('Logged out successfully');
        setUsername('');
        setPassword('');
    };

    return (
        <div className="max-w-md mx-auto mt-8 p-6 bg-white rounded-lg shadow-lg">
            <h1 className="text-3xl font-bold text-center text-athens-dark mb-6">Athens AI Authentication</h1>

            {currentUser ? (
                <div className="space-y-4">
                    <div className="p-4 bg-athens-light rounded">
                        <p className="text-athens-dark font-medium">Logged in as: {currentUser.username}</p>
                    </div>

                    {!useFido && (
                        <div>
                            <h2 className="text-xl font-semibold mb-2">Register Security Key</h2>
                            <p className="text-gray-600 mb-4">Enhance your account security by registering your YubiKey</p>
                            <button
                                onClick={handleWebAuthnRegister}
                                className="btn-primary w-full"
                            >
                                Register Security Key
                            </button>
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
        </div>
    );
};

export default Auth;

import React, { useState } from 'react';
import { startAuthentication } from '@simplewebauthn/browser';
import { AuthAPI } from '../../api/authClient.jsx';

const YubiKeyAuthentication = ({ username, onSuccess, onError }) => {
    const [status, setStatus] = useState('idle');
    const [error, setError] = useState(null);

    const authenticateWithYubiKey = async () => {
        try {
            setStatus('authenticating');
            setError(null);

            // 1. Request authentication options from the server
            const options = await AuthAPI.getAuthenticationOptions(username);

            // 2. Prepare the options for the browser API
            // Convert base64 challenge to ArrayBuffer
            const challengeArray = new Uint8Array(
                atob(options.challenge)
                    .split('')
                    .map(char => char.charCodeAt(0))
            );

            options.challenge = challengeArray;

            // Convert credential IDs from base64 to ArrayBuffer
            if (options.allowCredentials) {
                for (const credential of options.allowCredentials) {
                    const idArray = new Uint8Array(
                        atob(credential.id)
                            .split('')
                            .map(char => char.charCodeAt(0))
                    );
                    credential.id = idArray;
                }
            }

            // 3. Start the authentication process in the browser
            const assertionResponse = await startAuthentication(options);

            // 4. Send the response to the server for verification
            const verificationResult = await AuthAPI.verifyAuthentication(username, assertionResponse);

            if (verificationResult.verified) {
                setStatus('authenticated');
                if (onSuccess) {
                    onSuccess();
                }
            } else {
                throw new Error('Authentication failed');
            }
        } catch (err) {
            console.error('Authentication error:', err);
            setError(err.message || 'Authentication failed');
            setStatus('error');
            if (onError) {
                onError(err);
            }
        }
    };

    return (
        <div className="card p-6 max-w-md mx-auto">
            <div className="mb-6 text-center">
                <div className="flex justify-center mb-4">
                    <div className="w-16 h-16 bg-primary-100 rounded-full flex items-center justify-center">
                        <svg xmlns="http://www.w3.org/2000/svg" className="h-8 w-8 text-primary-600" viewBox="0 0 20 20" fill="currentColor">
                            <path fillRule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clipRule="evenodd" />
                        </svg>
                    </div>
                </div>
                <h2 className="text-2xl font-bold text-gray-800 mb-2">Security Key Required</h2>
                <p className="text-gray-600">
                    Please insert your YubiKey and tap when prompted to complete login.
                </p>
            </div>

            {status === 'authenticating' && (
                <div className="flex flex-col items-center justify-center mb-6">
                    <div className="relative">
                        <div className="w-16 h-16 border-4 border-primary-200 rounded-full"></div>
                        <div className="absolute top-0 left-0 w-16 h-16 border-4 border-primary-600 rounded-full animate-spin border-t-transparent"></div>
                    </div>
                    <p className="mt-4 text-gray-700">
                        Please tap your YubiKey now...
                    </p>
                </div>
            )}

            {status === 'authenticated' && (
                <div className="bg-green-50 border border-green-200 rounded-md p-4 mb-6">
                    <div className="flex">
                        <svg className="h-5 w-5 text-green-500 mr-2" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                        </svg>
                        <p className="text-green-700 font-medium">Successfully authenticated!</p>
                    </div>
                </div>
            )}

            {status === 'error' && (
                <div className="bg-red-50 border border-red-200 rounded-md p-4 mb-6">
                    <div className="flex">
                        <svg className="h-5 w-5 text-red-500 mr-2" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                        </svg>
                        <p className="text-red-700">{error}</p>
                    </div>
                </div>
            )}

            <div className="flex flex-col gap-4">
                {status !== 'authenticated' && (
                    <button
                        onClick={authenticateWithYubiKey}
                        disabled={status === 'authenticating'}
                        className={`btn btn-primary ${status === 'authenticating' ? 'opacity-75 cursor-not-allowed' : ''}`}
                    >
                        {status === 'authenticating' ? 'Verifying...' : 'Authenticate with YubiKey'}
                    </button>
                )}

                {status === 'authenticated' && (
                    <button
                        onClick={onSuccess}
                        className="btn btn-primary"
                    >
                        Continue
                    </button>
                )}
            </div>

            <div className="mt-6 text-center text-sm text-gray-500">
                <p>Your account is protected with YubiKey security.</p>
            </div>
        </div>
    );
};

export default YubiKeyAuthentication;

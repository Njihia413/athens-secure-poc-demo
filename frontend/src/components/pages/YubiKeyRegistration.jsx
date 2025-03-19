import React, { useState } from 'react';
import { startRegistration } from '@simplewebauthn/browser';
import { AuthAPI } from '../../api/authClient.jsx';

const YubiKeyRegistration = ({ username, onSuccess, onCancel }) => {
    const [status, setStatus] = useState('idle');
    const [error, setError] = useState(null);
    const [debugInfo, setDebugInfo] = useState(null);
    const [diagnosticResults, setDiagnosticResults] = useState(null);

    // Helper function to convert an ArrayBuffer to a hex string
    const arrayBufferToHex = (buffer) => {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    };

    // Helper function to run diagnostics
    const runDiagnostic = async (challenge) => {
        try {
            const results = await AuthAPI.sendDiagnostic({ challenge });
            setDiagnosticResults(results);
            return results;
        } catch (err) {
            console.error('Diagnostic error:', err);
            return { error: err.message };
        }
    };

    const registerYubiKey = async () => {
        try {
            setStatus('registering');
            setError(null);
            setDebugInfo(null);
            setDiagnosticResults(null);

            // Build debug info as we go
            let debugOutput = [];
            const addDebug = (message) => {
                const timestamp = new Date().toISOString().split('T')[1].slice(0, 12);
                debugOutput.push(`[${timestamp}] ${message}`);
                setDebugInfo(debugOutput.join('\n'));
            };

            addDebug(`Starting YubiKey registration for user: ${username}`);

            // 1. Request registration options from the server
            addDebug("Requesting registration options from server...");
            const optionsResponse = await AuthAPI.getRegistrationOptions(username);

            if (!optionsResponse || !optionsResponse.publicKey) {
                throw new Error("Invalid registration options received from server");
            }

            // Log detailed information about the options
            const registrationOptions = optionsResponse.publicKey;
            addDebug("Received registration options:");
            addDebug(`- RP ID: ${registrationOptions.rp.id}`);
            addDebug(`- RP Name: ${registrationOptions.rp.name}`);

            // Start WebAuthn registration process
            const attResp = await startRegistration(registrationOptions);

            // Convert Base64URL to Base64
            const clientDataBase64 = attResp.response.clientDataJSON.replace(/-/g, '+').replace(/_/g, '/');

            // Decode Base64 string into JSON text
            const clientDataText = atob(clientDataBase64);

            console.log("📜 Decoded clientDataJSON:", clientDataText); // Debugging log

            // Ensure clientDataText is not empty before parsing
            if (!clientDataText.trim()) {
                throw new Error("Decoded clientDataJSON is empty!");
            }

            // Parse the JSON
            const clientData = JSON.parse(clientDataText);

            // Extract the challenge
            const challengeBase64URL = clientData.challenge;
            const challengeBase64 = challengeBase64URL.replace(/-/g, '+').replace(/_/g, '/'); // Convert Base64URL to standard Base64
            const challengeBinary = atob(challengeBase64);
            const clientChallengeHex = [...challengeBinary]
                .map(byte => byte.charCodeAt(0).toString(16).padStart(2, '0'))
                .join('');

            console.log("🟢 Client Challenge (Hex):", clientChallengeHex);



            // // Run diagnostics on the challenge
            // addDebug("Running server-side diagnostics on challenge...");
            // await runDiagnostic(challenge);
            //
            // // 2. Start the registration process in the browser
            // addDebug("Starting WebAuthn registration...");
            // addDebug("Calling navigator.credentials.create() via SimpleWebAuthn...");
            //
            // // Store a copy of the original options for debugging
            // const originalOptions = JSON.parse(JSON.stringify(registrationOptions));


            // Log the response details
            addDebug("Received registration response from authenticator");
            addDebug(`- ID: ${attResp.id}`);
            addDebug(`- Type: ${attResp.type}`);
            addDebug(`- Raw ID (hex): ${arrayBufferToHex(attResp.rawId)}`);

            // Check the clientDataJSON specifically
            try {
                const clientDataJSON = attResp.response.clientDataJSON;
                const clientDataBuffer = new Uint8Array(clientDataJSON);

                addDebug(`- clientDataJSON (Base64): ${clientDataJSON}`);

                // Decode and parse it
                const clientDataText = new TextDecoder().decode(clientDataBuffer);
                const clientData = JSON.parse(clientDataText);
                addDebug(`- Decoded clientData.challenge: ${clientData.challenge}`);
                addDebug(`- Decoded clientData.origin: ${clientData.origin}`);
                addDebug(`- Decoded clientData.type: ${clientData.type}`);

                // Compare server challenge and client challenge
                addDebug("\nCHALLENGE COMPARISON:");
                addDebug(`- Server sent: ${challenge}`);
                addDebug(`- Client received: ${clientData.challenge}`);

                if (challenge === clientData.challenge) {
                    addDebug("✅ MATCH: Challenges are identical!");
                } else {
                    addDebug("❌ MISMATCH: Challenges are different!");
                }
            } catch (parseError) {
                addDebug(`Error parsing clientDataJSON: ${parseError.message}`);
            }

            // 3. Send the response to the server for verification
            addDebug("\nSending attestation to server for verification...");
            const verificationResult = await AuthAPI.verifyRegistration(username, attResp);

            if (verificationResult && verificationResult.verified) {
                addDebug("✅ Verification successful!");
                setStatus('registered');
                if (onSuccess) {
                    onSuccess();
                }
            } else {
                // Handle the case when verification failed but no error was thrown
                addDebug(`❌ Verification failed: ${JSON.stringify(verificationResult)}`);
                throw new Error(verificationResult.error || 'Verification failed without specific error');
            }
        } catch (err) {
            console.error('Registration error:', err);

            // Create a more detailed error message for debugging
            let errorDetail = err.message || 'Registration failed';

            // If the error has a response from the server, extract more details
            if (err.response && err.response.data) {
                errorDetail += ': ' + (err.response.data.error || JSON.stringify(err.response.data));

                // Add traceback if available
                if (err.response.data.traceback) {
                    setDebugInfo((prevDebug) => {
                        return (prevDebug || '') + '\n\nSERVER ERROR DETAILS:\n' + err.response.data.traceback;
                    });
                }
            }

            setError(errorDetail);
            setStatus('error');
        }
    };

    // Toggle for showing/hiding detailed debug info
    const [showDetails, setShowDetails] = useState(false);

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
                <h2 className="text-2xl font-bold text-gray-800 mb-2">Register Your YubiKey</h2>
                <p className="text-gray-600">
                    Enhance your account security by registering your YubiKey as a second factor.
                </p>
            </div>

            {status === 'registering' && (
                <div className="flex flex-col items-center justify-center mb-6">
                    <div className="relative">
                        <div className="w-16 h-16 border-4 border-primary-200 rounded-full"></div>
                        <div className="absolute top-0 left-0 w-16 h-16 border-4 border-primary-600 rounded-full animate-spin border-t-transparent"></div>
                    </div>
                    <p className="mt-4 text-gray-700">
                        Please insert your YubiKey and tap it when prompted...
                    </p>
                </div>
            )}

            {status === 'registered' && (
                <div className="bg-green-50 border border-green-200 rounded-md p-4 mb-6">
                    <div className="flex">
                        <svg className="h-5 w-5 text-green-500 mr-2" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                        </svg>
                        <p className="text-green-700 font-medium">YubiKey registered successfully!</p>
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

            {debugInfo && (
                <div className="bg-gray-50 border border-gray-200 rounded-md p-2 mb-6 max-h-60 overflow-auto">
                    <div className="flex justify-between items-center mb-1">
                        <span className="text-sm font-medium text-gray-700">Debug Information</span>
                        <button
                            onClick={() => setShowDetails(!showDetails)}
                            className="text-xs text-blue-600 hover:text-blue-800"
                        >
                            {showDetails ? 'Hide' : 'Show'} Details
                        </button>
                    </div>
                    {showDetails && (
                        <pre className="text-xs text-gray-600 whitespace-pre-wrap p-2">
                            {debugInfo}
                        </pre>
                    )}
                </div>
            )}

            {diagnosticResults && showDetails && (
                <div className="bg-indigo-50 border border-indigo-200 rounded-md p-2 mb-6 max-h-60 overflow-auto">
                    <div className="text-sm font-medium text-indigo-700 mb-1">Diagnostic Results</div>
                    <pre className="text-xs text-indigo-600 whitespace-pre-wrap p-2">
                        {JSON.stringify(diagnosticResults, null, 2)}
                    </pre>
                </div>
            )}

            <div className="flex flex-col gap-4">
                {status !== 'registered' && (
                    <button
                        onClick={registerYubiKey}
                        disabled={status === 'registering'}
                        className={`btn btn-primary ${status === 'registering' ? 'opacity-75 cursor-not-allowed' : ''}`}
                    >
                        {status === 'registering' ? 'Registering...' : 'Register YubiKey'}
                    </button>
                )}

                {status === 'registered' ? (
                    <button
                        onClick={onSuccess}
                        className="btn btn-primary"
                    >
                        Continue
                    </button>
                ) : (
                    <button
                        onClick={onCancel}
                        className="btn btn-secondary"
                        disabled={status === 'registering'}
                    >
                        {status === 'registered' ? 'Skip' : 'Cancel'}
                    </button>
                )}
            </div>

            <div className="mt-6 text-center text-sm text-gray-500">
                <p>Adding a security key provides a strong additional layer of security to your account.</p>
            </div>
        </div>
    );
};

export default YubiKeyRegistration;

{status === 'registered' && (
    <div className="bg-green-50 border border-green-200 rounded-md p-4 mb-6">
        <div className="flex">
            <svg className="h-5 w-5 text-green-500 mr-2" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
            <p className="text-green-700 font-medium">YubiKey registered successfully!</p>
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

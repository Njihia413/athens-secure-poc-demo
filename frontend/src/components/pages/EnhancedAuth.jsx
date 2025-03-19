import React, { useState, useEffect } from 'react';
import YubiKeyRegistration from './YubiKeyRegistration.jsx';
import YubiKeyAuthentication from './YubiKeyAuthentication.jsx';
import { AuthAPI } from '../../api/authClient.jsx';

const EnhancedAuth = () => {
    const [authStage, setAuthStage] = useState('login');
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [hasYubiKey, setHasYubiKey] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState(null);

    // Check if user has YubiKey registered
    useEffect(() => {
        const checkYubiKeyStatus = async () => {
            if (username && authStage === 'check-key') {
                try {
                    setIsLoading(true);
                    const { hasKey } = await AuthAPI.checkUserHasKey(username);
                    setHasYubiKey(hasKey);

                    if (hasKey) {
                        setAuthStage('authenticate-yubikey');
                    } else {
                        setAuthStage('offer-registration');
                    }
                } catch (err) {
                    console.error('Error checking YubiKey status:', err);
                    setError('Failed to check security key status');
                    setAuthStage('login');
                } finally {
                    setIsLoading(false);
                }
            }
        };

        checkYubiKeyStatus();
    }, [username, authStage]);

    const handleInitialLogin = async (e) => {
        e.preventDefault();
        setError(null);

        if (!username || !password) {
            setError('Please enter both username and password');
            return;
        }

        try {
            setIsLoading(true);
            const response = await AuthAPI.login(username, password);

            if (response.success) {
                if (response.requireSecurityKey) {
                    setHasYubiKey(true);
                    setAuthStage('authenticate-yubikey');
                } else {
                    setAuthStage('check-key');
                }
            } else {
                setError('Login failed');
            }
        } catch (err) {
            console.error('Login error:', err);
            setError('Login failed: ' + (err.message || 'Unknown error'));
        } finally {
            setIsLoading(false);
        }
    };

    const handleYubiKeyRegistrationSuccess = () => {
        setHasYubiKey(true);
        setAuthStage('authenticated');
    };

    const handleSkipRegistration = () => {
        setAuthStage('authenticated');
    };

    const handleYubiKeyAuthSuccess = () => {
        setAuthStage('authenticated');
    };

    const handleYubiKeyAuthError = (err) => {
        setError('Security key authentication failed: ' + err.message);
    };

    const handleLogout = () => {
        setUsername('');
        setPassword('');
        setAuthStage('login');
        setError(null);
    };

    return (
        <div className="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
            <div className="sm:mx-auto sm:w-full sm:max-w-md">
                <h1 className="text-center text-3xl font-extrabold text-gray-900">
                    Athens AI
                </h1>
                <h2 className="mt-2 text-center text-xl font-semibold text-gray-600">
                    {authStage === 'login' && 'Sign in to your account'}
                    {authStage === 'check-key' && 'Checking security...'}
                    {authStage === 'offer-registration' && 'Enhance Your Security'}
                    {authStage === 'register-yubikey' && 'Register Security Key'}
                    {authStage === 'authenticate-yubikey' && 'Security Verification'}
                    {authStage === 'authenticated' && 'Welcome Back'}
                </h2>
            </div>

            <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
                {error && (
                    <div className="mb-4 bg-red-50 border border-red-200 rounded-md p-4">
                        <div className="flex">
                            <svg className="h-5 w-5 text-red-500 mr-2" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                            </svg>
                            <p className="text-red-700">{error}</p>
                        </div>
                    </div>
                )}

                {authStage === 'login' && (
                    <div className="card p-8">
                        <form onSubmit={handleInitialLogin} className="space-y-6">
                            <div>
                                <label htmlFor="username" className="form-label">
                                    Username
                                </label>
                                <input
                                    id="username"
                                    name="username"
                                    type="text"
                                    autoComplete="username"
                                    required
                                    className="input-field"
                                    value={username}
                                    onChange={(e) => setUsername(e.target.value)}
                                />
                            </div>

                            <div>
                                <label htmlFor="password" className="form-label">
                                    Password
                                </label>
                                <input
                                    id="password"
                                    name="password"
                                    type="password"
                                    autoComplete="current-password"
                                    required
                                    className="input-field"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                />
                            </div>

                            <div>
                                <button
                                    type="submit"
                                    className={`w-full btn btn-primary ${isLoading ? 'opacity-75 cursor-not-allowed' : ''}`}
                                    disabled={isLoading}
                                >
                                    {isLoading ? 'Signing in...' : 'Sign in'}
                                </button>
                            </div>
                        </form>
                    </div>
                )}

                {authStage === 'check-key' && (
                    <div className="card p-8 text-center">
                        <div className="flex justify-center mb-4">
                            <div className="relative">
                                <div className="w-16 h-16 border-4 border-primary-200 rounded-full"></div>
                                <div className="absolute top-0 left-0 w-16 h-16 border-4 border-primary-600 rounded-full animate-spin border-t-transparent"></div>
                            </div>
                        </div>
                        <p className="text-gray-700">Checking security settings...</p>
                    </div>
                )}

                {authStage === 'offer-registration' && (
                    <div className="card p-8">
                        <div className="text-center mb-6">
                            <div className="flex justify-center mb-4">
                                <div className="w-16 h-16 bg-primary-100 rounded-full flex items-center justify-center">
                                    <svg xmlns="http://www.w3.org/2000/svg" className="h-8 w-8 text-primary-600" viewBox="0 0 20 20" fill="currentColor">
                                        <path fillRule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clipRule="evenodd" />
                                    </svg>
                                </div>
                            </div>
                            <h3 className="text-lg font-medium text-gray-900">Enhance Your Account Security</h3>
                            <p className="mt-2 text-sm text-gray-500">
                                Would you like to add a YubiKey security key to your account for stronger protection?
                            </p>
                        </div>

                        <div className="flex flex-col gap-4">
                            <button
                                onClick={() => setAuthStage('register-yubikey')}
                                className="btn btn-primary"
                            >
                                Add Security Key
                            </button>
                            <button
                                onClick={handleSkipRegistration}
                                className="btn btn-secondary"
                            >
                                Skip for Now
                            </button>
                        </div>
                    </div>
                )}

                {authStage === 'register-yubikey' && (
                    <YubiKeyRegistration
                        username={username}
                        onSuccess={handleYubiKeyRegistrationSuccess}
                        onCancel={handleSkipRegistration}
                    />
                )}

                {authStage === 'authenticate-yubikey' && (
                    <YubiKeyAuthentication
                        username={username}
                        onSuccess={handleYubiKeyAuthSuccess}
                        onError={handleYubiKeyAuthError}
                    />
                )}

                {authStage === 'authenticated' && (
                    <div className="card p-8">
                        <div className="text-center mb-6">
                            <div className="mx-auto flex items-center justify-center h-16 w-16 rounded-full bg-green-100">
                                <svg className="h-10 w-10 text-green-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                </svg>
                            </div>
                            <h3 className="mt-3 text-lg font-medium text-gray-900">Welcome to Athens AI</h3>
                            <p className="mt-2 text-sm text-gray-500">
                                You are now securely logged in.
                            </p>

                            {hasYubiKey ? (
                                <div className="mt-3 flex items-center justify-center">
                                    <svg className="h-5 w-5 text-primary-500 mr-2" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                                        <path fillRule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clipRule="evenodd" />
                                    </svg>
                                    <span className="text-sm font-medium text-primary-700">
                    Your account is secured with YubiKey
                  </span>
                                </div>
                            ) : (
                                <div className="mt-3">
                                    <button
                                        onClick={() => setAuthStage('register-yubikey')}
                                        className="text-sm font-medium text-primary-600 hover:text-primary-500"
                                    >
                                        Add a security key for stronger protection
                                    </button>
                                </div>
                            )}
                        </div>

                        <button
                            onClick={handleLogout}
                            className="w-full btn btn-secondary"
                        >
                            Sign Out
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
};

export default EnhancedAuth;

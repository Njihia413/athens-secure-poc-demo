import axios from 'axios';

// Base API URL
const API_URL = 'http://localhost:5000/api';

// Create axios instance
const apiClient = axios.create({
    baseURL: API_URL,
    headers: {
        'Content-Type': 'application/json',
    },
});

// Auth API
export const AuthAPI = {
    // Login with username and password
    login: async (username, password) => {
        try {
            const response = await apiClient.post('/login', { username, password });
            return response.data;
        } catch (error) {
            throw error.response?.data || error;
        }
    },

    // Check if user has registered security key
    checkUserHasKey: async (username) => {
        try {
            const response = await apiClient.post('/user-has-key', { username });
            return response.data;
        } catch (error) {
            throw error.response?.data || error;
        }
    },

    // WebAuthn registration
    getRegistrationOptions: async (username) => {
        try {
            const response = await apiClient.post('/register-options', { username });
            return response.data;
        } catch (error) {
            throw error.response?.data || error;
        }
    },

    verifyRegistration: async (username, attestationResponse) => {
        try {
            const response = await apiClient.post('/register-verify', {
                username,
                attestationResponse
            });
            return response.data;
        } catch (error) {
            throw error.response?.data || error;
        }
    },

    // WebAuthn authentication
    getAuthenticationOptions: async (username) => {
        try {
            const response = await apiClient.post('/auth-options', { username });
            return response.data;
        } catch (error) {
            throw error.response?.data || error;
        }
    },

    verifyAuthentication: async (username, assertionResponse) => {
        try {
            const response = await apiClient.post('/auth-verify', {
                username,
                assertionResponse
            });
            return response.data;
        } catch (error) {
            throw error.response?.data || error;
        }
    },

    // WebAuthn Diagnostic Functions

    /**
     * Sends diagnostic data to the server to help debug WebAuthn issues
     * @param {Object} data - Diagnostic data to send
     * @returns {Promise<Object>} - Diagnostic results
     */
    sendDiagnostic: async (data) => {
        try {
            const response = await apiClient.post('/webauthn-diagnostic', data);
            return response.data;
        } catch (error) {
            console.error('Diagnostic error:', error);
            return { error: error.response?.data || error.message };
        }
    },

    /**
     * Performs a challenge comparison to diagnose WebAuthn issues
     * @param {string} clientChallenge - The base64url encoded challenge from the client
     * @param {string} username - The username associated with the challenge
     * @returns {Promise<Object>} - Comparison results
     */
    compareChallenge: async (clientChallenge, username) => {
        try {
            const response = await apiClient.post('/webauthn-diagnostic', {
                challenge: clientChallenge,
                username: username,
                operation: 'compare'
            });
            return response.data;
        } catch (error) {
            console.error('Challenge comparison error:', error);
            return { error: error.response?.data || error.message };
        }
    },

    /**
     * Logs WebAuthn debug information to the server
     * @param {Object} debugInfo - Debug information to log
     * @returns {Promise<Object>} - Response from server
     */
    logDebugInfo: async (debugInfo) => {
        try {
            const response = await apiClient.post('/webauthn-debug', {
                info: debugInfo,
                timestamp: new Date().toISOString()
            });
            return response.data;
        } catch (error) {
            // If the debug endpoint fails, just log to console and don't throw
            console.error('Error logging debug info:', error);
            return { logged: false, error: error.message };
        }
    },

    /**
     * Gets detailed information about recent WebAuthn operations for a user
     * @param {string} username - The username to get history for
     * @returns {Promise<Object>} - User's WebAuthn history
     */
    getUserChallengeHistory: async (username) => {
        try {
            const response = await apiClient.post('/webauthn-diagnostic', {
                username: username,
                operation: 'history'
            });
            return response.data;
        } catch (error) {
            console.error('Error getting user history:', error);
            return { error: error.response?.data || error.message };
        }
    }
};

export default apiClient;

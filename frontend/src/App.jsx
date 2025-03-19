import React from 'react';
import Auth from './components/pages/Auth.jsx';

function App() {
    return (
        <div className="min-h-screen bg-gray-100 flex flex-col justify-center">
            <header className="bg-athens-dark text-white py-6 mb-8">
                <div className="container mx-auto px-4">
                    <h1 className="text-3xl font-bold">Athens AI</h1>
                    <p className="text-athens-accent">Secure Authentication with YubiKey</p>
                </div>
            </header>

            <main className="container mx-auto px-4 flex-grow">
                <Auth />
            </main>

            <footer className="bg-athens-dark text-white py-4 mt-8">
                <div className="container mx-auto px-4 text-center">
                    <p>Athens AI Authentication PoC - {new Date().getFullYear()}</p>
                </div>
            </footer>
        </div>
    );
}

export default App;

// Firebase auth and db are globally available from template-injected config

// Get DOM elements
const authButton = document.getElementById('authButton');
const authButtonMobile = document.getElementById('authButtonMobile');

// Function to update auth button text
function updateAuthButtonText(user) {
    const buttonText = user ? 'Sign Out' : 'Sign In';
    if (authButton) authButton.textContent = buttonText;
    if (authButtonMobile) authButtonMobile.textContent = buttonText;
}

// Handle authentication state changes
auth.onAuthStateChanged(async (user) => {
    updateAuthButtonText(user);
    
    if (user) {
        try {
            const userRef = db.collection('users').doc(user.uid);
            const userDoc = await userRef.get();
            
            // Update UI based on premium status
            if (userDoc.exists) {
                const userData = userDoc.data();
                if (userData && userData.premium) {
                    loadScanHistory(user.uid);
                }
            }
        } catch (error) {
            console.error('Error handling auth state:', error);
        }
    }

    // If user is logged in on the landing page, they probably want to go to the dashboard
    if (user && window.location.pathname === '/') {
        window.location.href = '/dashboard';
    }
});

// Function to handle sign in/out
async function handleAuth() {
    const user = auth.currentUser;
    if (user) {
        // Sign out
        try {
            await auth.signOut();
        } catch (error) {
            console.error('Error signing out:', error);
            alert('Error signing out. Please try again.');
        }
    } else {
        // Show login modal
        showLoginModal();
    }
}

// Function to create login modal
function showLoginModal() {
    // Remove any existing modal
    const existingModal = document.getElementById('loginModal');
    if (existingModal) {
        existingModal.remove();
    }
    
    // Create modal
    const modal = document.createElement('div');
    modal.id = 'loginModal';
    modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
    
    // Modal content
    modal.innerHTML = `
        <div class="bg-white p-8 rounded-xl shadow-xl max-w-md w-full">
            <h2 class="text-2xl font-bold text-gray-900 mb-6">Sign In</h2>
            <form id="loginForm" class="space-y-4">
                <div>
                    <label for="email" class="block text-sm font-medium text-gray-700">Email</label>
                    <input type="email" id="loginEmail" required
                           class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 p-2 border">
                </div>
                <div>
                    <label for="password" class="block text-sm font-medium text-gray-700">Password</label>
                    <input type="password" id="loginPassword" required
                           class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 p-2 border">
                </div>
                <div id="loginError" class="text-red-500 text-sm hidden"></div>
                <div class="flex justify-end space-x-3 mt-6">
                    <button type="button" id="cancelLogin" class="px-4 py-2 border border-gray-300 rounded-md text-gray-700">
                        Cancel
                    </button>
                    <button type="submit" class="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700">
                        Sign In
                    </button>
                </div>
            </form>
        </div>
    `;
    
    // Append modal to body
    document.body.appendChild(modal);
    
    // Add event listeners
    document.getElementById('cancelLogin').addEventListener('click', () => {
        modal.remove();
    });
    
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const email = document.getElementById('loginEmail').value;
        const password = document.getElementById('loginPassword').value;
        const errorDiv = document.getElementById('loginError');
        
        try {
            errorDiv.classList.add('hidden');
            
            // Sign in with email/password
            await auth.signInWithEmailAndPassword(email, password);
            
            // Remove modal on successful login
            modal.remove();
            
        } catch (error) {
            console.error('Error signing in:', error);
            errorDiv.textContent = 'Invalid email or password. Please try again.';
            errorDiv.classList.remove('hidden');
        }
    });
}

// Add click handlers for both desktop and mobile auth buttons
if (authButton) {
    authButton.addEventListener('click', handleAuth);
}
if (authButtonMobile) {
    authButtonMobile.addEventListener('click', handleAuth);
} 
import React, { useState, createContext, useContext } from 'react';
import { Mail, Lock, User, Phone, MapPin, Home, AlertCircle, LogOut, Shield, Users } from 'lucide-react';
import { motion } from 'framer-motion';

// ==================== AUTH SERVICE ====================

//versiunea mea
class AuthService {
  constructor() {
    this.accessToken = null;
    this.refreshToken = null;
    this.userId = null;
    this.role = null;
  }

  setTokens(accessToken, refreshToken, userId = null, role = null) {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.userId = userId;
    this.role = role;
    console.log('✅ Tokens saved:', { 
      accessToken: accessToken?.substring(0, 30) + '...', 
      refreshToken: refreshToken?.substring(0, 30) + '...', 
      userId,
      role
    });
  }

  getAccessToken() {
    return this.accessToken;
  }

  getRefreshToken() {
    return this.refreshToken;
  }

  getUserId() {
    return this.userId;
  }

  getRole() {
    return this.role;
  }

  clearTokens() {
    this.accessToken = null;
    this.refreshToken = null;
    this.userId = null;
    this.role = null;
    console.log('🗑️ Tokens cleared');
  }

  isAuthenticated() {
    return !!this.accessToken;
  }

  hasRole(role) {
    return this.role === role;
  }
}

const authService = new AuthService();
window.authService = authService;

// ==================== API CLIENT ====================
class ApiClient {
  constructor(baseURL = '') {
    this.baseURL = baseURL;
    this.refreshPromise = null;
  }

  async request(url, options = {}) {
    const config = {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    };

    const accessToken = authService.getAccessToken();
    if (accessToken && !url.includes('/auth/')) {
      config.headers['Authorization'] = `Bearer ${accessToken}`;
    }

    try {
      console.log(`📤 Making request to: ${url}`);
      const response = await fetch(this.baseURL + url, config);

      if ((response.status === 401 || response.status === 403) && !url.includes('/auth/')) {
        console.warn(`⚠️ Received ${response.status} - Token expired, refreshing...`);
        
        const newTokens = await this.refreshAccessToken();
        if (newTokens) {
          config.headers['Authorization'] = `Bearer ${newTokens.accessToken}`;
          console.log('🔄 Retrying original request with new token...');
          return await this.request(url, { ...options, headers: config.headers });
        } else {
          throw new Error('Token refresh failed');
        }
      }

      const text = await response.text();
      let data;
      try {
        data = text ? JSON.parse(text) : {};
      } catch {
        data = text;
      }

      if (!response.ok) {
        throw new Error(data.message || `Request failed: ${response.status}`);
      }

      console.log(`✅ Request successful: ${url}`);
      return { data, status: response.status };
    } catch (error) {
      console.error('❌ API Request failed:', error);
      throw error;
    }
  }

  async refreshAccessToken() {
    if (this.refreshPromise) {
      console.log('⏳ Already refreshing, waiting...');
      return await this.refreshPromise;
    }

    this.refreshPromise = this._performRefresh();
    
    try {
      const result = await this.refreshPromise;
      return result;
    } finally {
      this.refreshPromise = null;
    }
  }

  async _performRefresh() {
    const refreshToken = authService.getRefreshToken();
    
    if (!refreshToken) {
      console.error('❌ No refresh token available');
      authService.clearTokens();
      window.location.href = '/';
      return null;
    }

    try {
      console.log('🔄 Starting token refresh...');

      const response = await fetch(this.baseURL + '/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: refreshToken }),
      });

      if (!response.ok) {
        throw new Error(`Refresh failed: ${response.status}`);
      }

      const data = await response.json();
      console.log('✅ Refresh successful!');

      authService.setTokens(data.accessToken, data.refreshToken);

      return { accessToken: data.accessToken, refreshToken: data.refreshToken };
    } catch (error) {
      console.error('❌ Token refresh failed:', error);
      authService.clearTokens();
      window.location.href = '/';
      return null;
    }
  }

  async post(url, data) {
    return this.request(url, { method: 'POST', body: JSON.stringify(data) });
  }

  async get(url) {
    return this.request(url, { method: 'GET' });
  }

  async logout() {
    const accessToken = authService.getAccessToken();
    const refreshToken = authService.getRefreshToken();

    if (!refreshToken) {
      console.warn('⚠️ No refresh token, skipping backend logout');
      return;
    }

    console.log('🚪 Sending logout request to backend...');

    await fetch(this.baseURL + `/auth/logout?refreshToken=${refreshToken}`, {
      method: 'POST',
      headers: {
        'Authorization': accessToken ? `Bearer ${accessToken}` : '',
      }
    });

    console.log('✅ Backend logout done');
  }
}

const apiClient = new ApiClient("https://ums-backend-q689.onrender.com");


// ==================== AUTH CONTEXT ====================
const AuthContext = createContext(null);

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [isLoginMode, setIsLoginMode] = useState(false);
  
  const getPageFromPath = () => {
    const path = window.location.pathname;
    if (path.includes('/user-secure')) return 'user-secure';
    if (path.includes('/admin-secure')) return 'admin-secure';
    if (path.includes('/profile')) return 'profile';
    return 'register';
  };

  const [currentPage, setCurrentPage] = useState(getPageFromPath());

  const navigateTo = (page) => {
    setCurrentPage(page);
    const paths = {
      register: '/',
      profile: '/profile',
      'user-secure': '/user-secure',
      'admin-secure': '/admin-secure'
    };
    window.history.pushState({}, '', paths[page] || '/');
  };

  const register = async (userData) => {
    try {
      console.log('📤 Sending register request...');
      const { data } = await apiClient.post('/auth/signup', userData);
      
      console.log('📥 Register response received');
      authService.setTokens(data.accessToken, data.refreshToken);
      
      setUser(userData);
      navigateTo('profile');
      return data;
    } catch (error) {
      console.error('❌ Registration error:', error);
      throw error;
    }
  };

  const login = async (credentials) => {
    try {
      console.log('📤 Sending login request for:', credentials.email);
      const { data } = await apiClient.post('/auth/login', credentials);
      
      console.log('📥 Login response received:', data);
      authService.setTokens(data.accessToken, data.refreshToken, data.userId, data.role);
      
      console.log('✅ Login successful, role:', data.role);
      
      setUser({ 
        email: credentials.email,
        userId: data.userId,
        role: data.role,
        firstName: data.firstName
      });
      
      navigateTo('profile');
      return data;
    } catch (error) {
      console.error('❌ Login error:', error);
      throw error;
    }
  };

  const logout = async () => {
    try {
      await apiClient.logout();
    } catch (e) {
      console.warn('⚠️ Logout backend failed, continuing client logout');
    } finally {
      authService.clearTokens();
      setUser(null);
      navigateTo('register');
    }
  };

  const toggleAuthMode = () => {
    setIsLoginMode(!isLoginMode);
  };

  React.useEffect(() => {
    const handlePopState = () => {
      setCurrentPage(getPageFromPath());
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  return (
    <AuthContext.Provider value={{ user, register, login, logout, currentPage, navigateTo, isLoginMode, toggleAuthMode }}>
      {children}
    </AuthContext.Provider>
  );
};

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

const InputField = ({ icon: Icon, label, name, type = 'text', placeholder, value, onChange, error }) => (
  <div className="space-y-2">
    <label className="block text-sm font-medium text-cyan-300">{label}</label>
    <div className="relative">
      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
        <Icon className="h-5 w-5 text-cyan-500" />
      </div>
      <input
        type={type}
        name={name}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        className={`w-full pl-10 pr-4 py-3 bg-gray-900/50 border ${
          error ? 'border-red-500' : 'border-cyan-500/30'
        } rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/20 transition-all duration-300`}
        style={{ boxShadow: error ? '0 0 20px rgba(239, 68, 68, 0.3)' : '0 0 20px rgba(6, 182, 212, 0.1)' }}
      />
    </div>
    {error && (
      <p className="text-red-400 text-xs mt-1 flex items-center gap-1">
        <AlertCircle className="h-3 w-3" /> {error}
      </p>
    )}
  </div>
);

// ==================== USER SECURE PAGE ====================
const UserSecurePage = () => {
  const { logout, navigateTo } = useAuth();
  const [secureData, setSecureData] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  React.useEffect(() => {
    const fetchSecureData = async () => {
      if (!authService.isAuthenticated()) {
        setError('NOT_AUTHENTICATED');
        setIsLoading(false);
        return;
      }

      try {
        const { data } = await apiClient.get('/user/secure');
        setSecureData(data);
      } catch (err) {
        setError('FORBIDDEN');
      } finally {
        setIsLoading(false);
      }
    };

    fetchSecureData();
  }, [navigateTo]);

  if (isLoading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="w-16 h-16 border-4 border-gray-800 border-t-cyan-400 rounded-full animate-spin"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center p-4">
        <div className="max-w-md w-full bg-gray-900/80 backdrop-blur-xl p-8 rounded-2xl border border-red-500/30 shadow-2xl text-center">
          <div className="w-20 h-20 bg-red-600/20 rounded-full flex items-center justify-center mx-auto mb-6 animate-pulse">
            <AlertCircle className="h-10 w-10 text-red-400" />
          </div>
          <h1 className="text-3xl font-bold text-white mb-4 animate-pulse">Restricted Access</h1>
          <p className="text-gray-300 mb-2">You cannot access this secure USER page.</p>
          <p className="text-cyan-400 font-semibold mb-6">Please log in to continue.</p>
          
          <button
            onClick={() => navigateTo('register')}
            className="w-full py-3 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold rounded-lg transition-all duration-300 shadow-md hover:shadow-cyan-500/50"
          >
           Back to Login
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen relative flex flex-col items-center justify-center overflow-hidden bg-black">
      {/* Neon Floating Orbs */}
      <div className="absolute inset-0 -z-10">
        <div className="absolute top-1/4 left-1/5 w-96 h-96 bg-gradient-to-tr from-cyan-500/50 to-blue-500/50 rounded-full blur-3xl animate-[float_12s_ease-in-out_infinite]"></div>
        <div className="absolute top-1/2 right-1/4 w-80 h-80 bg-gradient-to-tr from-purple-500/40 to-pink-500/40 rounded-full blur-3xl animate-[float_15s_ease-in-out_infinite]"></div>
        <div className="absolute bottom-1/5 left-2/3 w-72 h-72 bg-gradient-to-tr from-indigo-500/40 to-cyan-500/40 rounded-full blur-3xl animate-[float_18s_ease-in-out_infinite]"></div>
        <div className="absolute inset-0 bg-gradient-to-br from-black via-transparent to-black opacity-40"></div>
      </div>

      {/* Floating Card */}
      <motion.div
        initial={{ y: -20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ duration: 1, type: "spring", stiffness: 60 }}
        className="relative max-w-2xl w-full bg-gradient-to-tr from-gray-900/60 to-gray-800/60 backdrop-blur-2xl rounded-3xl p-12 shadow-[0_0_50px_rgba(0,255,255,0.3)] border border-cyan-400/20 text-center"
      >
        <div className="w-24 h-24 mx-auto mb-6 flex items-center justify-center bg-gradient-to-tr from-cyan-500 to-blue-500 rounded-full shadow-lg animate-pulse">
          <Users className="h-12 w-12 text-white drop-shadow-[0_0_20px_rgba(0,255,255,0.7)]" />
        </div>

        <motion.h1
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ duration: 0.8 }}
          className="text-5xl font-extrabold text-white mb-4 drop-shadow-[0_0_20px_rgba(0,255,255,0.6)]"
        >
          User Secure Page
        </motion.h1>

        <motion.p
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.3, duration: 0.6 }}
          className="text-xl text-cyan-300 mb-8"
        >
          {secureData}
        </motion.p>

        {/* Buttons */}
        <div className="flex gap-8 justify-center">
          <motion.button
            whileHover={{ scale: 1.05, boxShadow: '0 0 20px rgba(0,255,255,0.7)' }}
            className="px-8 py-4 bg-gradient-to-r from-cyan-500 to-blue-500 text-white font-semibold rounded-xl shadow-md transition-all duration-300"
            onClick={() => navigateTo('profile')}
          >
            Back to Main
          </motion.button>

          <motion.button
            whileHover={{ scale: 1.05, boxShadow: '0 0 20px rgba(255,0,0,0.7)' }}
            className="px-8 py-4 bg-gradient-to-r from-red-600 to-red-700 text-white font-semibold rounded-xl shadow-md transition-all duration-300"
            onClick={logout}
          >
            Logout
          </motion.button>
        </div>
      </motion.div>

      {/* Footer Glow */}
      <motion.div
        animate={{ opacity: [0.6, 1, 0.6] }}
        transition={{ repeat: Infinity, duration: 2 }}
        className="absolute bottom-10 text-center text-cyan-400 text-lg font-semibold drop-shadow-[0_0_15px_rgba(0,255,255,0.7)]"
      >
      </motion.div>
    </div>
  );
};

// ==================== ADMIN SECURE PAGE ====================
const AdminSecurePage = () => {
  const { logout, navigateTo } = useAuth();
  const [secureData, setSecureData] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  React.useEffect(() => {
    const fetchSecureData = async () => {
      if (!authService.isAuthenticated()) {
        setError('NOT_AUTHENTICATED');
        setIsLoading(false);
        return;
      }

      if (!authService.hasRole('ADMIN')) {
        setError('FORBIDDEN');
        setIsLoading(false);
        return;
      }

      try {
        const { data } = await apiClient.get('/admin/secure');
        setSecureData(data);
      } catch (err) {
        setError('FORBIDDEN');
      } finally {
        setIsLoading(false);
      }
    };

    fetchSecureData();
  }, [navigateTo]);

  if (isLoading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="w-16 h-16 border-4 border-gray-800 border-t-purple-500 rounded-full animate-spin"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center p-4">
        <div className="max-w-md w-full bg-gray-900/80 backdrop-blur-xl p-8 rounded-2xl border border-red-500/30 shadow-2xl text-center">
          <div className="w-20 h-20 bg-red-600/20 rounded-full flex items-center justify-center mx-auto mb-6 animate-pulse">
            <AlertCircle className="h-10 w-10 text-red-400" />
          </div>
          <h1 className="text-3xl font-bold text-white mb-4 animate-pulse">🚫 Access Denied</h1>
          <p className="text-gray-300 mb-2">You cannot access this secure ADMIN page.</p>
          <p className="text-purple-400 font-semibold mb-6">Only users with the ADMIN role have access.</p>
          
          <button
            onClick={() => navigateTo('profile')}
            className="w-full py-3 bg-gradient-to-r from-purple-600 to-red-600 hover:from-purple-500 hover:to-red-500 text-white font-bold rounded-lg transition-all duration-300 shadow-md hover:shadow-purple-500/50"
          >
            Back to Main Page
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen relative flex flex-col items-center justify-center overflow-hidden bg-black">
      {/* Neon Floating Orbs */}
      <div className="absolute inset-0 -z-10">
        <div className="absolute top-1/4 left-1/5 w-96 h-96 bg-gradient-to-tr from-purple-500/50 to-pink-500/50 rounded-full blur-3xl animate-[float_12s_ease-in-out_infinite]"></div>
        <div className="absolute top-1/2 right-1/4 w-80 h-80 bg-gradient-to-tr from-indigo-500/40 to-purple-500/40 rounded-full blur-3xl animate-[float_15s_ease-in-out_infinite]"></div>
        <div className="absolute bottom-1/5 left-2/3 w-72 h-72 bg-gradient-to-tr from-red-500/40 to-pink-500/40 rounded-full blur-3xl animate-[float_18s_ease-in-out_infinite]"></div>
        <div className="absolute inset-0 bg-gradient-to-br from-black via-transparent to-black opacity-40"></div>
      </div>

      {/* Floating Card */}
      <motion.div
        initial={{ y: -20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ duration: 1, type: "spring", stiffness: 60 }}
        className="relative max-w-2xl w-full bg-gradient-to-tr from-gray-900/60 to-gray-800/60 backdrop-blur-2xl rounded-3xl p-12 shadow-[0_0_50px_rgba(255,0,255,0.3)] border border-purple-400/20 text-center"
      >
        <div className="w-24 h-24 mx-auto mb-6 flex items-center justify-center bg-gradient-to-tr from-purple-500 to-pink-500 rounded-full shadow-lg animate-pulse">
          <Shield className="h-12 w-12 text-white drop-shadow-[0_0_20px_rgba(255,0,255,0.7)]" />
        </div>

        <motion.h1
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ duration: 0.8 }}
          className="text-5xl font-extrabold text-white mb-4 drop-shadow-[0_0_20px_rgba(255,0,255,0.6)]"
        >
          Admin Secure Page
        </motion.h1>

        <motion.p
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.3, duration: 0.6 }}
          className="text-xl text-purple-300 mb-8"
        >
          {secureData}
        </motion.p>

        {/* Buttons */}
        <div className="flex gap-8 justify-center">
          <motion.button
            whileHover={{ scale: 1.05, boxShadow: '0 0 20px rgba(255,0,255,0.7)' }}
            className="px-8 py-4 bg-gradient-to-r from-purple-500 to-pink-500 text-white font-semibold rounded-xl shadow-md transition-all duration-300"
            onClick={() => navigateTo('profile')}
          >
            Back to Main
          </motion.button>

          <motion.button
            whileHover={{ scale: 1.05, boxShadow: '0 0 20px rgba(255,0,0,0.7)' }}
            className="px-8 py-4 bg-gradient-to-r from-red-600 to-red-700 text-white font-semibold rounded-xl shadow-md transition-all duration-300"
            onClick={logout}
          >
            Logout
          </motion.button>
        </div>
      </motion.div>

      {/* Footer Glow */}
      <motion.div
        animate={{ opacity: [0.6, 1, 0.6] }}
        transition={{ repeat: Infinity, duration: 2 }}
        className="absolute bottom-10 text-center text-purple-400 text-lg font-semibold drop-shadow-[0_0_15px_rgba(255,0,255,0.7)]"
      >
     
      </motion.div>
    </div>
  );
};


// ==================== PROFILE PAGE ====================


const LoginPage = () => {
  const { login, toggleAuthMode } = useAuth();
  const [formData, setFormData] = useState({ email: '', password: '' });
  const [errors, setErrors] = useState({});
  const [isLoading, setIsLoading] = useState(false);
  const [submitStatus, setSubmitStatus] = useState(null);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    if (errors[name]) setErrors(prev => ({ ...prev, [name]: '' }));
  };

  const validateForm = () => {
    const newErrors = {};
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) newErrors.email = 'Invalid email format';
    if (!formData.password) newErrors.password = 'Password is required';
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async () => {
    if (!validateForm()) return;
    setIsLoading(true);
    setSubmitStatus(null);
    
    try {
      await login(formData);
    } catch (error) {
      setSubmitStatus({ type: 'error', message: error.message || 'Authentication failed' });
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4 relative overflow-hidden">
      <div className="absolute inset-0 z-0">
        <div className="absolute top-0 left-0 w-full h-full bg-gradient-to-br from-purple-900/20 via-gray-900 to-cyan-900/20" />
      </div>

      <div className="relative z-10 w-full max-w-md bg-gray-900/80 backdrop-blur-xl p-8 rounded-2xl border border-cyan-500/30 shadow-2xl">
        <h1 className="text-3xl font-bold text-white text-center mb-8 bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
          Log in
        </h1>

        {submitStatus && (
          <div className="mb-6 p-4 rounded-lg border bg-red-500/10 border-red-500/50 text-red-400 flex items-center gap-2">
            <AlertCircle className="h-5 w-5" />
            {submitStatus.message}
          </div>
        )}

        <div className="space-y-5">
          <InputField icon={Mail} label="Email" name="email" type="email" value={formData.email} onChange={handleChange} error={errors.email} placeholder="john.doe@email.com" />
          <InputField icon={Lock} label="Parolă" name="password" type="password" value={formData.password} onChange={handleChange} error={errors.password} placeholder="Enter password" />

          <button onClick={handleSubmit} disabled={isLoading} className="w-full py-4 bg-gradient-to-r from-cyan-600 to-purple-600 hover:from-cyan-500 hover:to-purple-500 text-white font-bold rounded-lg transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg hover:shadow-cyan-500/50">
            {isLoading ? <span className="flex items-center justify-center gap-2"><div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />Processing...</span> : 'Log in'}
          </button>
        </div>

        <p className="text-gray-400 text-center mt-6 text-sm">
          Don't have an account? <span onClick={toggleAuthMode} className="text-cyan-400 cursor-pointer hover:underline">Sign up</span>
        </p>
      </div>
    </div>
  );
};

const RegisterPage = () => {
  const { register, toggleAuthMode } = useAuth();
  const [formData, setFormData] = useState({
    firstName: '',
    lastName: '',
    email: '',
    password: '',
    phoneNumber: '',
    address: '',
    city: ''
  });
  const [errors, setErrors] = useState({});
  const [isLoading, setIsLoading] = useState(false);
  const [submitStatus, setSubmitStatus] = useState(null);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    if (errors[name]) setErrors(prev => ({ ...prev, [name]: '' }));
  };

  const validateForm = () => {
    const newErrors = {};
   if (!formData.firstName.trim()) newErrors.firstName = 'First name is required';
  if (!formData.lastName.trim()) newErrors.lastName = 'Last name is required';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) newErrors.email = 'Invalid email format';
  if (formData.password.length < 6) newErrors.password = 'Password must be at least 6 characters';
  if (!formData.phoneNumber.trim()) newErrors.phoneNumber = 'Phone number is required';
  if (!formData.address.trim()) newErrors.address = 'Address is required';
  if (!formData.city.trim()) newErrors.city = 'City is required';
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async () => {
    if (!validateForm()) return;
    setIsLoading(true);
    setSubmitStatus(null);
    
    try {
      await register(formData);
    } catch (error) {
      setSubmitStatus({ type: 'error', message: error.message || 'Signup failed' });
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4 relative overflow-hidden">
      <div className="absolute inset-0 z-0">
        <div className="absolute top-0 left-0 w-full h-full bg-gradient-to-br from-purple-900/20 via-gray-900 to-cyan-900/20" />
      </div>

      <div className="relative z-10 w-full max-w-2xl bg-gray-900/80 backdrop-blur-xl p-8 rounded-2xl border border-cyan-500/30 shadow-2xl">
        <h1 className="text-3xl font-bold text-white text-center mb-8 bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
          Sign up
        </h1>

        {submitStatus && (
          <div className={`mb-6 p-4 rounded-lg border flex items-center gap-2 ${
            submitStatus.type === 'error' 
              ? 'bg-red-500/10 border-red-500/50 text-red-400' 
              : 'bg-green-500/10 border-green-500/50 text-green-400'
          }`}>
            <AlertCircle className="h-5 w-5" />
            {submitStatus.message}
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          <InputField icon={User} label="First name" name="firstName" value={formData.firstName} onChange={handleChange} error={errors.firstName} placeholder="John" />
          <InputField icon={User} label="Last Name" name="lastName" value={formData.lastName} onChange={handleChange} error={errors.lastName} placeholder="Doe" />
          <InputField icon={Mail} label="Email" name="email" type="email" value={formData.email} onChange={handleChange} error={errors.email} placeholder="john.doe@email.com" />
          <InputField icon={Lock} label="Password" name="password" type="password" value={formData.password} onChange={handleChange} error={errors.password} placeholder="Minimum 6 characters" />
          <InputField icon={Phone} label="Phone" name="phoneNumber" value={formData.phoneNumber} onChange={handleChange} error={errors.phoneNumber} placeholder="XXX XXX XX" />
          <InputField icon={MapPin} label="City" name="city" value={formData.city} onChange={handleChange} error={errors.city} placeholder="London" />
        </div>

        <div className="mt-5">
          <InputField icon={Home} label="Address" name="address" value={formData.address} onChange={handleChange} error={errors.address} placeholder="Str. Main Street 23" />
        </div>

        <button onClick={handleSubmit} disabled={isLoading} className="w-full mt-6 py-4 bg-gradient-to-r from-cyan-600 to-purple-600 hover:from-cyan-500 hover:to-purple-500 text-white font-bold rounded-lg transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg hover:shadow-cyan-500/50">
          {isLoading ? <span className="flex items-center justify-center gap-2"><div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />Processing...</span> : 'Sign up'}
        </button>

        <p className="text-gray-400 text-center mt-6 text-sm">
          Do you already have an account? <span onClick={toggleAuthMode} className="text-cyan-400 cursor-pointer hover:underline">Log in</span>
        </p>
      </div>
    </div>
  );
};





const title = 'WELCOME';

const container = {
  hidden: {},
  visible: {
    transition: {
      staggerChildren: 0.12,
    },
  },
};

const letter = {
  hidden: { opacity: 0, y: 40, filter: 'blur(6px)' },
  visible: {
    opacity: 1,
    y: 0,
    filter: 'blur(0px)',
    transition: { duration: 0.8, ease: 'easeOut' },
  },
};

const HomePage = () => {
  const { navigateTo, user, logout } = useAuth();

  return (
    <div className="relative min-h-screen overflow-hidden flex flex-col items-center justify-center">

      {/* ===== BACKGROUND ===== */}
      <div className="absolute inset-0 -z-30 bg-gradient-to-br from-[#050712] via-[#0a1430] to-[#02030a]" />

      {/* Ambient lights */}
      <div className="absolute -top-40 left-1/4 w-[700px] h-[700px] bg-blue-600/20 blur-[260px] rounded-full -z-20" />
      <div className="absolute bottom-0 right-1/4 w-[700px] h-[700px] bg-indigo-500/20 blur-[260px] rounded-full -z-20" />

      {/* Grid */}
      <div
        className="absolute inset-0 opacity-15 -z-10"
        style={{
          backgroundImage: `
            linear-gradient(rgba(255,255,255,0.05) 1px, transparent 1px),
            linear-gradient(90deg, rgba(255,255,255,0.05) 1px, transparent 1px)
          `,
          backgroundSize: '90px 90px',
        }}
      />

      {/* ===== LOGOUT ===== */}
      <button
        onClick={logout}
        className="absolute top-6 right-6 z-20 flex items-center gap-2 px-5 py-3
        bg-blue-700/80 hover:bg-blue-800 text-white font-medium rounded-full
        shadow-[0_0_25px_rgba(0,120,255,0.7)] transition-all"
      >
        <LogOut size={18} />
        Logout
      </button>

      {/* ===== WELCOME ===== */}
      <motion.div
        variants={container}
        initial="hidden"
        animate="visible"
        className="flex mb-4"
      >
        {title.split('').map((char, i) => (
          <motion.span
            key={i}
            variants={letter}
            className="text-6xl md:text-7xl font-extrabold tracking-[0.25em]
            text-white drop-shadow-[0_0_35px_rgba(0,120,255,0.6)]"
            style={{ fontFamily: 'Inter, system-ui' }}
          >
            {char}
          </motion.span>
        ))}
      </motion.div>

      {/* USER NAME */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.2 }}
        className="mb-16 text-lg text-blue-300 tracking-widest"
      >
        {user?.firstName}
      </motion.div>

      {/* ===== CARDS ===== */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-14 z-10">

        {/* USER */}
        {/* USER */}
<motion.div
  whileHover={{ scale: 1.06, rotateX: 5, rotateY: -5 }}
  transition={{ type: 'spring', stiffness: 120 }}
  onClick={() => navigateTo('user-secure')}
  className="
    cursor-pointer 
    w-64 h-44   /* <-- mai mic */
    rounded-2xl
    bg-white/5 backdrop-blur-xl
    border border-emerald-600/30
    shadow-[0_0_25px_rgba(0,180,120,0.4)]
    flex flex-col items-center justify-center gap-4 text-white
  "
>
  <Users
    size={48}  /* micsoreaza iconita */
    className="text-blue-500 drop-shadow-[0_0_30px_rgba(40,90,220,1)]"
  />
  <span className="text-lg font-semibold tracking-wide">User Secure</span>
  <span className="text-sm text-gray-400">Authorized access</span>
</motion.div>

{/* ADMIN */}
<motion.div
  whileHover={{ scale: 1.06, rotateX: 5, rotateY: 5 }}
  transition={{ type: 'spring', stiffness: 120 }}
  onClick={() => navigateTo('admin-secure')}
  className="
    cursor-pointer 
    w-64 h-44   /* <-- mai mic */
    rounded-2xl
    bg-white/5 backdrop-blur-xl
    border border-purple-700/40
    shadow-[0_0_55px_rgba(120,40,120,0.45)]
    flex flex-col items-center justify-center gap-4 text-white
  "
>
  <Shield
    size={48}  /* micsoreaza iconita */
    className="text-purple-400 drop-shadow-[0_0_30px_rgba(160,60,160,1)]"
  />
  <span className="text-lg font-semibold tracking-wide">Admin Secure</span>
  <span className="text-sm text-gray-400">Restricted control</span>
</motion.div>
</div>
</div>
  );
};




// ==================== MAIN APP ====================
const App = () => {
  const { currentPage, isLoginMode } = useAuth();

  const renderPage = () => {
    if (currentPage === 'profile') return <HomePage />;
    if (currentPage === 'user-secure') return <UserSecurePage />;
    if (currentPage === 'admin-secure') return <AdminSecurePage />;
    return isLoginMode ? <LoginPage /> : <RegisterPage />;
  };

  return renderPage();
};

export default function AuthApp() {
  return (
    <AuthProvider>
      <App />
    </AuthProvider>
  );
} 
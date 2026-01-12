import { authService } from './AuthService';

export const requireAuth = (requiredRole = null) => {
  if (!authService.isAuthenticated()) {
    return { allowed: false, reason: 'NOT_AUTHENTICATED' };
  }

  if (requiredRole && authService.getUserRole() !== requiredRole) {
    return { allowed: false, reason: 'FORBIDDEN' };
  }

  return { allowed: true };
};

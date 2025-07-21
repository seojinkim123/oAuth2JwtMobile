// 🔒 JWT 토큰 관리 유틸리티 (HTTP-Only Cookie 기반)
export const TokenStorage = {
  // 🔒 HTTP-Only 쿠키는 JavaScript로 직접 설정할 수 없음
  // 서버에서 설정되므로 이 메서드들은 더 이상 사용되지 않음
  setAccessToken: (token) => {
    console.warn('HTTP-Only 쿠키는 서버에서만 설정할 수 있습니다.');
  },

  setRefreshToken: (token) => {
    console.warn('HTTP-Only 쿠키는 서버에서만 설정할 수 있습니다.');
  },

  // 🔒 HTTP-Only 쿠키는 JavaScript로 직접 읽을 수 없음
  // API 호출을 통해 토큰 유효성을 확인해야 함
  getAccessToken: () => {
    console.warn('HTTP-Only 쿠키는 JavaScript로 직접 읽을 수 없습니다. API 호출로 검증하세요.');
    return null;
  },

  getRefreshToken: () => {
    console.warn('HTTP-Only 쿠키는 JavaScript로 읽을 수 없습니다.');
    return null;
  },

  // 🔒 로그아웃 시 서버 API를 통해 쿠키 삭제
  clearTokens: async () => {
    try {
      const response = await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'include' // 쿠키 포함
      });
      
      if (response.ok) {
        console.log('로그아웃 성공 - 쿠키가 서버에서 삭제되었습니다.');
        return true;
      } else {
        console.error('로그아웃 실패');
        return false;
      }
    } catch (error) {
      console.error('로그아웃 중 오류:', error);
      return false;
    }
  },

  // 🔒 API 호출을 통해 토큰 유효성 확인
  hasTokens: async () => {
    try {
      const response = await fetch('/api/auth/verify', {
        method: 'GET',
        credentials: 'include' // 쿠키 포함
      });
      return response.ok;
    } catch (error) {
      console.error('토큰 검증 중 오류:', error);
      return false;
    }
  },

  // JWT 토큰 파싱 (payload 추출)
  parseJWT: (token) => {
    try {
      const base64Url = token.split('.')[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
      }).join(''));
      return JSON.parse(jsonPayload);
    } catch (error) {
      console.error('JWT 파싱 오류:', error);
      return null;
    }
  },

  // 토큰 만료 확인
  isTokenExpired: (token) => {
    if (!token) return true;
    
    const decoded = TokenStorage.parseJWT(token);
    if (!decoded || !decoded.exp) return true;
    
    const currentTime = Date.now() / 1000;
    return decoded.exp < currentTime;
  }
};
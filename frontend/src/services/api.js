import axios from 'axios';
import { TokenStorage } from '../utils/tokenStorage';

// 🔒 Axios 인스턴스 생성 (쿠키 기반)
const api = axios.create({
  baseURL: 'http://localhost:8080/api',
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // 🔒 쿠키 포함하여 요청
});

// 🔒 요청 인터셉터 - HTTP-Only 쿠키 기반이므로 토큰 헤더 설정 불필요
api.interceptors.request.use(
  (config) => {
    // HTTP-Only 쿠키는 브라우저가 자동으로 포함하므로 별도 처리 불필요
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// 🔒 응답 인터셉터 - 401 오류 시 로그인 페이지로 리다이렉트
api.interceptors.response.use(
  (response) => {
    return response;
  },
  async (error) => {
    // 401 Unauthorized 오류 시 자동 로그아웃 처리
    if (error.response?.status === 401) {
      console.log('인증이 만료되었습니다. 로그인 페이지로 이동합니다.');
      
      // 쿠키 기반이므로 서버에서 토큰 삭제 시도
      try {
        await TokenStorage.clearTokens();
      } catch (logoutError) {
        console.error('로그아웃 처리 중 오류:', logoutError);
      }
      
      // 메인 페이지로 리다이렉트 (로그인 상태 초기화)
      window.location.href = '/';
    }

    return Promise.reject(error);
  }
);

// API 함수들
export const ApiService = {
  // 공개 API
  hello: () => api.get('/hello'),

  // 인증이 필요한 API
  getCurrentUser: () => api.get('/auth/me'),
  getUser: (id) => api.get(`/user/${id}`),

  // 토큰 관련 API (범용)
  refreshToken: (refreshToken) => 
    axios.post('http://localhost:8080/api/auth/refresh', { refreshToken }),
  
  validateToken: (token) => 
    axios.post('http://localhost:8080/api/auth/validate', { token }),

  // 웹용 인증 API (쿠키 기반)
  webVerifyToken: () => api.get('/web/auth/verify'),
  webLogout: () => api.post('/web/auth/logout'),
  webDebugToken: () => api.get('/web/auth/debug/token'),

  // 모바일용 인증 API (헤더 기반) - 참고용
  // 실제로는 Authorization 헤더와 함께 사용
  mobileVerifyToken: (token) => 
    axios.get('http://localhost:8080/api/mobile/auth/verify', {
      headers: { 'Authorization': `Bearer ${token}` }
    }),
  
  mobileLogout: (token) => 
    axios.post('http://localhost:8080/api/mobile/auth/logout', {}, {
      headers: { 'Authorization': `Bearer ${token}` }
    }),
};

export default api;
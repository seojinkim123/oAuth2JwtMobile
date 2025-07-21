import React, { useState, useEffect } from 'react';
import LoginButton from './components/LoginButton';
import UserProfile from './components/UserProfile';
import OAuth2Redirect from './components/OAuth2Redirect';
import { TokenStorage } from './utils/tokenStorage';
import { ApiService } from './services/api';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [helloMessage, setHelloMessage] = useState('');

  useEffect(() => {
    checkAuthentication();
    fetchHelloMessage();
  }, []);

  const checkAuthentication = async () => {
    try {
      // 🔒 쿠키 기반 토큰 검증 API 호출
      const hasValidToken = await TokenStorage.hasTokens();
      setIsAuthenticated(hasValidToken);
    } catch (error) {
      console.error('인증 확인 중 오류:', error);
      setIsAuthenticated(false);
    }
    setLoading(false);
  };

  const fetchHelloMessage = async () => {
    try {
      const response = await ApiService.hello();
      setHelloMessage(response.data);
    } catch (error) {
      console.error('Hello API 호출 실패:', error);
      setHelloMessage('API 연결에 실패했습니다.');
    }
  };

  const handleLoginSuccess = () => {
    setIsAuthenticated(true);
  };

  const handleLogout = async () => {
    try {
      // 🔒 서버 API를 통해 쿠키 삭제
      const success = await TokenStorage.clearTokens();
      if (success) {
        setIsAuthenticated(false);
      }
    } catch (error) {
      console.error('로그아웃 중 오류:', error);
      setIsAuthenticated(false); // 오류가 발생해도 클라이언트 상태는 업데이트
    }
  };

  // 🔒 OAuth2 리다이렉트 처리 (쿠키 기반)
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('success') === 'true') {
    return <OAuth2Redirect onLoginSuccess={handleLoginSuccess} />;
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-100 flex justify-center items-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto"></div>
          <p className="mt-4 text-gray-600">로딩 중...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-100">
      {/* 헤더 */}
      <header className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center">
              <h1 className="text-2xl font-bold text-gray-900">OAuth2 + JWT Demo</h1>
            </div>
            <div className="flex items-center space-x-4">
              {isAuthenticated ? (
                <span className="text-green-600 font-medium">✅ 인증됨</span>
              ) : (
                <span className="text-red-600 font-medium">❌ 미인증</span>
              )}
            </div>
          </div>
        </div>
      </header>

      {/* 메인 컨텐츠 */}
      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          {/* API 연결 상태 */}
          <div className="bg-white overflow-hidden shadow rounded-lg mb-6">
            <div className="px-4 py-5 sm:p-6">
              <h3 className="text-lg leading-6 font-medium text-gray-900 mb-2">
                API 연결 상태
              </h3>
              <div className="text-sm text-gray-600">
                <strong>Hello API 응답:</strong> {helloMessage}
              </div>
              <button
                onClick={fetchHelloMessage}
                className="mt-3 bg-gray-500 hover:bg-gray-600 text-white py-2 px-4 rounded transition duration-200"
              >
                다시 테스트
              </button>
            </div>
          </div>

          {/* 인증 상태에 따른 컨텐츠 */}
          <div className="bg-white overflow-hidden shadow rounded-lg">
            <div className="px-4 py-5 sm:p-6">
              {isAuthenticated ? (
                <div>
                  <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">
                    사용자 프로필
                  </h3>
                  <UserProfile onLogout={handleLogout} />
                </div>
              ) : (
                <div className="text-center">
                  <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">
                    로그인이 필요합니다
                  </h3>
                  <p className="text-gray-600 mb-6">
                    Google 계정으로 로그인하여 JWT 토큰 기반 인증을 체험해보세요.
                  </p>
                  <LoginButton />
                </div>
              )}
            </div>
          </div>

          {/* 🔒 쿠키 기반 인증 정보 (개발용) */}
          {isAuthenticated && (
            <div className="bg-white overflow-hidden shadow rounded-lg mt-6">
              <div className="px-4 py-5 sm:p-6">
                <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">
                  인증 정보 (개발용)
                </h3>
                <div className="space-y-2 text-sm">
                  <div className="bg-green-50 border border-green-200 rounded p-3">
                    <strong className="text-green-800">🔒 보안 강화:</strong>
                    <p className="text-green-700 mt-1">
                      JWT 토큰이 HTTP-Only 쿠키에 안전하게 저장되어 JavaScript로 접근할 수 없습니다.
                    </p>
                  </div>
                  <div className="bg-blue-50 border border-blue-200 rounded p-3">
                    <strong className="text-blue-800">✅ XSS 공격 방지:</strong>
                    <p className="text-blue-700 mt-1">
                      토큰이 더 이상 localStorage나 URL에 노출되지 않습니다.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

export default App;
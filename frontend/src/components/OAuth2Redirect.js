import React, { useEffect } from 'react';
import { TokenStorage } from '../utils/tokenStorage';

const OAuth2Redirect = ({ onLoginSuccess }) => {
  useEffect(() => {
    // 🔒 URL 파라미터에서 성공 여부만 확인 (토큰은 더 이상 URL에 없음)
    const urlParams = new URLSearchParams(window.location.search);
    const success = urlParams.get('success');

    if (success === 'true') {
      // 🔒 HTTP-Only 쿠키에 토큰이 자동으로 설정되어 있음
      // 토큰 존재 여부 확인을 위해 API 호출로 검증
      fetch('/api/auth/verify', {
        method: 'GET',
        credentials: 'include' // 쿠키 포함
      })
      .then(response => {
        if (response.ok) {
          console.log('OAuth2 로그인 성공, 쿠키 기반 인증 설정 완료');
          
          // 부모 컴포넌트에 로그인 성공 알림
          onLoginSuccess();
          
          // URL 정리
          window.history.replaceState({}, document.title, window.location.pathname);
        } else {
          console.error('OAuth2 로그인 실패: 토큰 검증 실패');
        }
      })
      .catch(error => {
        console.error('OAuth2 로그인 검증 중 오류:', error);
      });
    } else {
      console.error('OAuth2 로그인 실패: success 파라미터가 없습니다.');
    }
  }, [onLoginSuccess]);

  return (
    <div className="flex justify-center items-center min-h-screen">
      <div className="text-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto"></div>
        <p className="mt-4 text-gray-600">로그인 처리 중...</p>
      </div>
    </div>
  );
};

export default OAuth2Redirect;
import React, { useEffect } from 'react';

const OAuth2Redirect = ({ onLoginSuccess }) => {
  useEffect(() => {
    // URL 파라미터에서 성공 여부 확인
    const urlParams = new URLSearchParams(window.location.search);
    const success = urlParams.get('success');

    if (success === 'true') {
      // OAuth2 서버에서 이미 HTTP-Only 쿠키에 JWT 토큰 설정 완료
      console.log('OAuth2 로그인 성공, 쿠키 기반 인증 설정 완료');
      
      // 부모 컴포넌트에 로그인 성공 알림
      onLoginSuccess();
      
      // URL 정리
      window.history.replaceState({}, document.title, window.location.pathname);
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
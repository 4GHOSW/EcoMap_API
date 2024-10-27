import requests
import json

########## GOOGLE
from google.oauth2 import id_token
from google.auth.transport import requests as googleRequests

def verify_google_token(token):
    print(f"구글 토큰을 검증합니다...... {token}")
    """
    구글 ID 토큰을 검증하고, 토큰의 클레임을 반환합니다.
    
    :param token: 클라이언트로부터 받은 구글 ID 토큰
    :return: 토큰의 클레임(사용자 정보를 담고 있는 딕셔너리)
    """
    try:
        # 구글 API 클라이언트 ID를 지정합니다. 이 값은 Google Cloud Console에서 생성한 OAuth 2.0 클라이언트 ID입니다.
        # YOUR_GOOGLE_CLIENT_ID를 실제 클라이언트 ID로 대체하세요.
        client_id = "91211062839-ltlmfjf1c63u9umbecheeqo0l5nkcuai.apps.googleusercontent.com"
        # ID 토큰을 검증합니다. 이 과정에서 구글의 공개키를 사용하여 서명을 검증하고, 클라이언트 ID와 일치하는지 확인합니다.
        idinfo = id_token.verify_oauth2_token(token, googleRequests.Request(), client_id)
        # 토큰의 발행자가 'accounts.google.com' 또는 'https://accounts.google.com'인지 확인합니다.
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Wrong issuer.')
        # 검증이 성공하면, 토큰의 클레임(사용자 정보)을 반환합니다.
        return idinfo
        
    except ValueError as e:
        # 토큰 검증 실패 시, 오류를 처리합니다.
        # 여기서는 간단히 오류 메시지를 출력합니다. 실제 애플리케이션에서는 적절한 예외 처리가 필요합니다.
        print(e)
        return None

################## access token 발급
from rest_framework_simplejwt.tokens import RefreshToken

def get_tokens_for_user(user):
    print('액세스 토큰 생성 중....')
    refresh = RefreshToken.for_user(user)
    print(f'REFRESH : {refresh}')
    print(f'REFRESH access token : {refresh.access_token}')
    return {
        'refreshToken': str(refresh),
        'accessToken': str(refresh.access_token),
    }

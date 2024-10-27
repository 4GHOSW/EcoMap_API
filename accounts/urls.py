from django.urls import path
from .api import *

urlpatterns = [
    path('kakao/login/', KakaoLogin.as_view(), name='kakao_login'),
    path('naver/login/', NaverLogin.as_view(), name='naver_login'),
    path('auth/eco/signup/', SignUpView.as_view(), name='signup'),
    path('auth/eco/login/', LoginView.as_view(), name='login'),
    path('auth/eco/refresh/', TokenRefreshView.as_view(), name='refreshToken'),
    path('info/carbon/', UserCarbonView.as_view(), name='user-carbon'),

]
from django.urls import path
from .api import *

urlpatterns = [
    path('kakao/login/', KakaoLogin.as_view(), name='kakao_login'),
    path('naver/login/', NaverLogin.as_view(), name='naver_login'),
    path('auth/signup/', SignUpView.as_view(), name='signup'),
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='login'),

]
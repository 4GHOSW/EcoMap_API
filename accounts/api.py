import requests
from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import User
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from rest_framework.exceptions import ValidationError

class SignUpView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        first_name = request.data.get('first_name', '')
        last_name = request.data.get('last_name', '')

        # 이메일과 비밀번호 필수 검사
        if not email or not password:
            return Response({'error': 'Email and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

        # 비밀번호 유효성 검사
        try:
            validate_password(password)
        except ValidationError as e:
            return Response({'error': e.messages}, status=status.HTTP_400_BAD_REQUEST)

        # 사용자 생성
        try:
            user = User.objects.create_user(
                username=email,  # 이메일을 username으로 사용
                email=email,
                first_name=first_name,
                last_name=last_name,
                sign_up_platform=User.LOGIN_EMAIL
            )
            user.set_password(password)
            user.save()
            return Response({'message': 'User created successfully.'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        # 이메일과 비밀번호 필수 검사
        if not email or not password:
            return Response({'error': 'Email and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

        # 사용자 인증
        user = authenticate(username=email, password=password)

        if user is not None:
            # 인증 성공 시 JWT 토큰 발행
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid email or password.'}, status=status.HTTP_401_UNAUTHORIZED)


class NaverLogin(APIView):
    def post(self, request):
        access_token = request.data.get('access_token')
        if not access_token:
            return Response({'error': 'Access token is required.'}, status=status.HTTP_400_BAD_REQUEST)

        # 네이버 사용자 정보 요청
        naver_user_info_url = "https://openapi.naver.com/v1/nid/me"
        headers = {
            "Authorization": f"Bearer {access_token}",
        }
        naver_response = requests.get(naver_user_info_url, headers=headers)

        if naver_response.status_code != 200:
            return Response({'error': 'Failed to retrieve user information from Naver.'}, status=status.HTTP_400_BAD_REQUEST)

        naver_data = naver_response.json()
        naver_response_code = naver_data.get('resultcode')
        if naver_response_code != "00":
            return Response({'error': 'Naver user information retrieval failed.'}, status=status.HTTP_400_BAD_REQUEST)

        naver_user = naver_data.get('response')
        naver_id = naver_user.get('id')
        email = naver_user.get('email')
        profile_image = naver_user.get('profile_image')
        name = naver_user.get('name')

        # 필수 정보가 없는 경우 처리
        if not naver_id:
            return Response({'error': 'Naver ID is required.'}, status=status.HTTP_400_BAD_REQUEST)

        # 기존에 해당 네이버 ID를 가진 사용자가 있는지 확인
        try:
            user = User.objects.get(naver_id=naver_id)
        except User.DoesNotExist:
            # 해당 네이버 ID로 사용자가 없으면 새로운 사용자 생성
            user = User(
                username=f'naver_{naver_id}',
                email=email,
                naver_id=naver_id,
                first_name=name,
                sign_up_platform=User.LOGIN_NAVER
            )
            user.set_unusable_password()  # 네이버 로그인 사용자는 비밀번호를 사용하지 않음
            if profile_image:
                user.avatar = profile_image
            user.save()

        # JWT 토큰 발행
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, status=status.HTTP_200_OK)

class KakaoLogin(APIView):
    def post(self, request):
        access_token = request.data.get('access_token')
        if not access_token:
            return Response({'error': 'Access token is required.'}, status=status.HTTP_400_BAD_REQUEST)

        # 카카오 사용자 정보 요청
        kakao_user_info_url = "https://kapi.kakao.com/v2/user/me"
        headers = {
            "Authorization": f"Bearer {access_token}",
        }
        kakao_response = requests.get(kakao_user_info_url, headers=headers)

        if kakao_response.status_code != 200:
            return Response({'error': 'Failed to retrieve user information from Kakao.'}, status=status.HTTP_400_BAD_REQUEST)

        kakao_data = kakao_response.json()
        kakao_id = kakao_data.get('id')
        email = kakao_data.get('kakao_account', {}).get('email')
        profile_image = kakao_data.get('kakao_account', {}).get('profile', {}).get('profile_image_url')

        # 필수 정보가 없는 경우 처리
        if not kakao_id:
            return Response({'error': 'Kakao ID is required.'}, status=status.HTTP_400_BAD_REQUEST)

        # 기존에 해당 카카오 ID를 가진 사용자가 있는지 확인
        try:
            user = User.objects.get(kakao_id=kakao_id)
        except User.DoesNotExist:
            # 해당 카카오 ID로 사용자가 없으면 새로운 사용자 생성
            user = User(
                username=f'kakao_{kakao_id}',
                email=email,
                kakao_id=kakao_id,
                sign_up_platform=User.LOGIN_KAKAO
            )
            user.set_unusable_password()  # 카카오 로그인 사용자는 비밀번호를 사용하지 않음
            if profile_image:
                user.avatar = profile_image
            user.save()

        # JWT 토큰 발행
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, status=status.HTTP_200_OK)



# from rest_framework import status
# from rest_framework.response import Response
# from rest_framework.views import APIView
# from .serializers import UserSerializer
# from .models import User
# from .exceptions import KakaoException, SocialLoginException  # Define these exceptions in your code
# from drf_yasg.utils       import swagger_auto_schema
# from drf_yasg             import openapi
# from django.core.exceptions import ObjectDoesNotExist
# import requests
# from django.shortcuts import redirect
# from django.contrib import messages
# from django.contrib import auth
# from django.core.files.base import ContentFile
# from decouple import config
# from .token_handle import *
# from django.contrib.auth import authenticate, login
# from rest_framework.permissions import IsAuthenticated
# from rest_framework.authentication import TokenAuthentication
# from rest_framework_simplejwt.settings import api_settings
# from django.utils import timezone
# import datetime
# from rest_framework.decorators import api_view, permission_classes
# from django.contrib.auth import authenticate
# from .backends import KakaoAuthenticationBackend  # 경로는 프로젝트 설정에 따라 달라질 수 있습니다.
# from django.contrib.auth import login
# from rest_framework_simplejwt.tokens import RefreshToken
# from voc.models import *
# import string
# import random
# from lib2to3.pgen2.tokenize import TokenError

# today = datetime.date.today()

# class GetUser(APIView):
#     permission_classes = [IsAuthenticated]

#     user_id = openapi.Parameter('user_id', openapi.IN_PATH, description='글(UserContent)의 id값입니다.', required=True, type=openapi.TYPE_INTEGER)

#     @swagger_auto_schema(
#         operation_summary="유저가 작성한 글", 
#         operation_description="유저가 작성한 글(답변)을 가져옵니다.", 
#         manual_parameters=[user_id], 
#         responses={200: 'Success'}
#         )
#     def get(self, request, user_id):
#         user = User.objects.get(id=user_id)
#         serializer = UserSerializer(user)
#         print(serializer.data)
#         return Response(serializer.data, status=status.HTTP_200_OK)

# class KakaoLoginAPIView(APIView):
#     def post(self, request):
#         serializer = UserSerializer(data=request.data)
#         if serializer.is_valid():
#             # Extract user data from serializer
#             data = serializer.validated_data

#             if request.user.is_authenticated:
#                 raise SocialLoginException("User already logged in")

#             client_id = config("KAKAO_ID")
#             redirect_uri = "https://heuton.kr/users/login/kakao/callback/"
            
#             return redirect(
#                 f"https://kauth.kakao.com/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code"
#             )
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class KakaoLoginCallbackAPIView(APIView):
#     def post(self, request):
#         access_token = request.data.get('accessToken')
#         if not access_token:
#             return Response({"error": "Access token is required"}, status=status.HTTP_400_BAD_REQUEST)

#         user_info = self.get_kakao_user_info(access_token)
#         if not user_info:
#             return Response({"error": "Failed to retrieve user information"}, status=status.HTTP_400_BAD_REQUEST)

#         user, user_is_new = self.get_or_create_user(user_info)
#         if user:
#             refresh = RefreshToken.for_user(user)

#             # 토큰의 만료 시간을 UTC 기준으로 계산합니다.
#             access_token = refresh.access_token
#             current_time = timezone.now()
#             access_token_expires_in = int(access_token.payload['exp'] - current_time.timestamp())

#             login(request, user, backend='django.contrib.auth.backends.ModelBackend')  # Ensure the user is logged in.
#             return Response({
#                 'refresh': str(refresh),
#                 'access': str(refresh.access_token),
#                 'expires_in': access_token_expires_in,
#                 'user': UserSerializer(user).data,
#             }, status=status.HTTP_200_OK)

#         return Response({"error": "Authentication failed"}, status=status.HTTP_401_UNAUTHORIZED)

#     def get_kakao_user_info(self, token):
#         """ Retrieve user information from Kakao's API """
#         headers = {"Authorization": f"Bearer {token}"}
#         response = requests.get("https://kapi.kakao.com/v2/user/me", headers=headers)
#         if response.status_code == 200:
#             return response.json()
#         return None

#     def get_or_create_user(self, kakao_data):
#         """ Retrieve or create a user based on Kakao's data """
#         kakao_account = kakao_data.get("kakao_account")
#         email = kakao_account.get("email")
#         kakao_id = kakao_data.get("id")
#         gender = kakao_data.get("gender")
#         profile = kakao_account.get("profile", {})
#         nickname = profile.get("nickname", None)
#         avatar_url = profile.get("profile_image_url", None)
#         user, created = User.objects.get_or_create(
#             kakao_id=kakao_id,
#             defaults={
#                 'email': email,
#                 'username': email or f"kakao_{kakao_id}",  # Use email or a default username
#                 'first_name': nickname,
#                 'gender': gender,
#                 'sign_up_platform' : User.LOGIN_KAKAO,
#             }
#         )
#         if avatar_url and created:  # 이미지가 있고, 사용자가 새로 생성되었을 때만 이미지를 다운로드
#             response = requests.get(avatar_url)
#             user.avatar.save(f"{nickname}-avatar.jpg", ContentFile(response.content), save=True)
#         return user, created

# class KakaoLoginRegister(APIView):
#     post_params = openapi.Schema(
#         type=openapi.TYPE_OBJECT, 
#         properties={
#             'id': openapi.Schema(type=openapi.TYPE_INTEGER, description='Kakao id'),
#             'nickname' : openapi.Schema(type=openapi.TYPE_STRING, description='nickname 값'),
#             'profile_image' : openapi.Schema(type=openapi.TYPE_STRING, description='profile_image 값'),
#             'email' : openapi.Schema(type=openapi.TYPE_STRING, description='email 값'),
#             'age_range' : openapi.Schema(type=openapi.TYPE_STRING, description='age_range 값'),
#             'birthday' : openapi.Schema(type=openapi.TYPE_STRING, description='birthday 값'),
#             'gender' : openapi.Schema(type=openapi.TYPE_STRING, description='gender 값'),
#         }
#     )
#     @swagger_auto_schema(
#         operation_summary="카카오 로그인 또는 가입", 
#         operation_description="카카오로 로그인 또는 가입을 진행합니다.", 
#         responses={200: 'Success'},
#         request_body=post_params
#         )
#     def post(self, request):
#         request_data = request.data
#         kakao_id = request_data['id']
#         print('KAKAO ID : ', kakao_id)
#         if not kakao_id:
#             return Response({'error': 'kakao_id is required'}, status=status.HTTP_BAD_REQUEST)

#         try:
#             current_user = User.objects.get(kakao_id=kakao_id)
#             user = current_user.user
#             auth.login(request, user)
#             return Response({"message": "카카오로 로그인되었습니다.", "user_id" : user.id}, status=status.HTTP_200_OK)
#         except ObjectDoesNotExist:
#             user = User.objects.create(
#                 username= request_data['email'],
#                 kakao_id=kakao_id,
#                 first_name = request_data['nickname'],
#                 gender = request_data['gender'],
#                 avatar = request_data['profile_image'],
#                 sign_up_platform = "Kakao",
#             )
#             auth.login(request, user)
#             return Response({"message": "카카오로 가입했습니다.", "user_id" : user.id}, status=status.HTTP_200_OK)

# class TokenRefreshAndVerifyView(APIView):
#     """
#     리프레시 토큰을 사용하여 새로운 액세스 토큰과 리프레시 토큰을 발급합니다.
#     """

#     def post(self, request, *args, **kwargs):
#         print('validating....')
#         refresh_token = request.data.get('refresh')

#         if not refresh_token:
#             print('here')
#             return Response({"error": "Refresh token is required"}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             print('there', refresh_token)
#             # 리프레시 토큰 검증 및 새로운 토큰 쌍 생성
#             refresh = RefreshToken(refresh_token)
            
#             # 새로운 액세스 토큰 발급
#             new_access_token = refresh.access_token
#             print(f'NEW ACCESS : {new_access_token}')
#             # 새로운 리프레시 토큰 생성을 위해 기존 리프레시 토큰 갱신
#             refresh.blacklist()
#             new_refresh_token = RefreshToken.for_user(refresh.user)

#             # 액세스 토큰의 만료 시간을 계산합니다.
#             expires_at = datetime.datetime.fromtimestamp(new_access_token['exp'], tz=timezone.utc)

#             return Response({
#                 'access_token': str(new_access_token),
#                 'refresh_token': str(new_refresh_token),
#                 'expires_at' : expires_at.isoformat()
#             })

#         except TokenError as e:
#             print('where')
#             return Response({"error": "Token is invalid or expired"}, status=status.HTTP_401_UNAUTHORIZED)

# class GoogleLogin(APIView):
#     def post(self, request, *args, **kwargs):
#         print("구글로 시작하기를 클릭했습니다.")
#         id_token = request.data.get('idToken')  # 구글 로그인 시 클라이언트로부터 받은 ID 토큰
#         if not id_token:
#             print(f'토큰이 없어요..!')
#             return Response({'error': 'ID token is required.'}, status=status.HTTP_400_BAD_REQUEST)
#         try:
#             decoded_token = verify_google_token(id_token)
#             google_id = decoded_token['sub']
#             email = decoded_token.get('email', '')
#             first_name = decoded_token.get('given_name', '')
#             last_name = decoded_token.get('family_name', '')
            
#             try:
#                 user = User.objects.get(google_id=google_id)
#                 print(f'User가 이미 존재해요 --> {user}')
#             except User.DoesNotExist:
#                 user_is_new = True
#                 # 새로운 사용자를 생성하는 로직
#                 user = User.objects.create(
#                     email=email,
#                     first_name=first_name,
#                     last_name=last_name,
#                     google_id=google_id,
#                     sign_up_platform="Google",
#                     username=f"google_{google_id}",
#                 )
                
#                 print(f'User가 구글로 새로 가입했어요! --> {user}')
#         except Exception as e:
#             print(e)
#             return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
#         # 사용자 인증 및 로그인
#         login(request, user, backend='django.contrib.auth.backends.ModelBackend')

#         # JWT 토큰 생성 및 반환 (여기에 더 많은 정보를 포함할 수 있습니다.)
#         token = get_tokens_for_user(user)
#         access_token_lifetime = api_settings.ACCESS_TOKEN_LIFETIME.total_seconds()
        
#         ## 유저가 온보딩을 마쳤는지 체크

#         return Response({
#             'refresh_token': token['refresh'],
#             'access_token': token['access'], 
#             'expires_in': int(access_token_lifetime),
#             'user': UserSerializer(user).data,
#         }, status=status.HTTP_200_OK)

   
# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
# def validate_token(request):
#     print(f'validating token....')
#     # 사용자가 인증되었을 경우, 간단한 사용자 정보를 반환합니다.
#     return Response({
#         'user_id': request.user.id,
#         'name': request.user.first_name,
#         'email': request.user.email
#     })

#     auth_type = openapi.Parameter('auth_type', openapi.IN_PATH, description='로그인 방법입니다.', required=True, type=openapi.TYPE_STRING)
#     auth_id = openapi.Parameter('auth_id', openapi.IN_PATH, description='로그인 방식에 따른 id 또는 토큰입니다.', required=True, type=openapi.TYPE_STRING)

#     @swagger_auto_schema(
#         operation_summary="로그인 후 user_id를 가져옵니다.", 
#         operation_description="로그인 시 사용한 id/토큰으로 user id를 가져옵니다.", 
#         manual_parameters=[auth_type, auth_id], 
#         responses={200: 'Success'}
#         )
#     def get(self, request, auth_type, auth_id):
#         if auth_type == 'Kakao' or auth_type == 'kakao':
#             try:
#                 owner = User.objects.get(kakao_id=auth_id)
#                 user_id = owner.id
#                 message = '카카오로 가입했습니다.'
#             except ObjectDoesNotExist:
#                 owner = []
#                 user_id = []
#                 message = 'kakao_id {}를 가진 유저가 없습니다!'.format(auth_id)
#         elif auth_type == "Apple" or auth_type == 'apple' :
#             try:
#                 owner = User.objects.get(apple_id=auth_id)
#                 user_id = owner.id
#                 message = '애플로 가입했습니다.'
#             except ObjectDoesNotExist:
#                 owner = []
#                 user_id = []
#                 message = 'apple_id {}를 가진 유저가 없습니다!'.format(auth_id)
#         elif auth_type == "Email" or auth_type == 'email':
#             user_id = []
#             message = '이메일 로그인!'
        
#         ## Create API
#         result = {
#             'user_id' : user_id,
#             'message' : message
#         }
        
#         return Response(result)
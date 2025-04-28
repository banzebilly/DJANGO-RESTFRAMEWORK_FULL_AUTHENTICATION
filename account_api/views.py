from django.shortcuts import render, redirect
from .models import Account
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import RegisterSerializer, LoginSerializer, ForgotPasswordSerializer, ResetPasswordSerializer
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes


from .serializers import ForgotPasswordSerializer
from .utils import send_verification_email  # Make sure you import this if it's in a utils.py
from django.contrib.sites.shortcuts import get_current_site

class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = serializer.save()

            # After saving the user, send verification email
            mail_subject = 'Please activate your account'
            mail_template = 'accounts/account_verification_email.html'  # Path to your email template
            send_verification_email(request, user, mail_subject, mail_template)

            return Response({'detail': 'We have sent you a verification email.'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




User = get_user_model()

def activate(request, uidb64, token):
    try:
        # Decode the user id
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        return HttpResponse('Your account has been activated successfully! You can now login.')  # Or redirect to login page
    else:
        return HttpResponse('Activation link is invalid!', status=400)



# class LoginView(APIView):
#     def post(self, request):
#         serializer = LoginSerializer(data=request.data)
#         if serializer.is_valid():
#             user = serializer.validated_data['user']
#             return Response({'detail': 'Login successful'}, status=status.HTTP_200_OK)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
from rest_framework_simplejwt.tokens import RefreshToken

class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            
            # Create JWT tokens
            refresh = RefreshToken.for_user(user)

            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'detail': 'Login successful'
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



# views.py



Account = get_user_model()  # This will reference your custom Account model
class ForgotPasswordView(APIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = Account.objects.get(email=email)  # Change User to Account
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)

            # Send reset password email
            mail_subject = 'Reset your password'
            mail_template = 'accounts/reset_password_email.html'
            send_verification_email(request, user, mail_subject, mail_template)
            return Response({'detail': 'Password reset link has been sent to your email address.'},
                             status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# views.py

class ResetPasswordValidateView(APIView):
    def get(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = Account.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, Account.DoesNotExist):
            return Response({'detail': 'Invalid link or user not found'}, status=status.HTTP_400_BAD_REQUEST)

        if default_token_generator.check_token(user, token):
            return Response({'detail': 'Valid reset link, please enter a new password.'}, status=status.HTTP_200_OK)
        return Response({'detail': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordView(APIView):
    def post(self, request):
        uidb64 = request.data.get('uidb64')
        token = request.data.get('token')
        password = request.data.get('password')
        confirm_password = request.data.get('confirm_password')

        if not uidb64 or not token:
            return Response({'error': 'Missing uidb64 or token.'}, status=status.HTTP_400_BAD_REQUEST)

        if password != confirm_password:
            return Response({'error': 'Passwords do not match.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = Account.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, Account.DoesNotExist):
            return Response({'error': 'Invalid user or invalid link.'}, status=status.HTTP_400_BAD_REQUEST)

        if user is not None and default_token_generator.check_token(user, token):
            user.set_password(password)
            user.save()
            return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)


# class CustomLoginView(TokenObtainPairView):
#     serializer_class = CustomTokenObtainPairSerializer


# # Logout View (Blacklist refresh token)
# class LogoutView(APIView):
#     permission_classes = [IsAuthenticated]

#     def post(self, request):
#         try:
#             refresh_token = request.data["refresh"]
#             token = RefreshToken(refresh_token)
#             token.blacklist()
#             return Response(status=205)
#         except Exception as e:
#             return Response(status=400)





# from rest_framework.decorators import api_view
# from rest_framework.response import Response
# from .models import People
# from .serializers import PeopleSerializer

# @api_view(['GET', 'POST'])
# def people(request):
#     if request.method == 'GET':
#         names_ages = People.objects.all()
#         serializer = PeopleSerializer(names_ages, many=True)
#         return Response(serializer.data)

#     elif request.method == 'POST':
#         serializer = PeopleSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data, status=201)  # 201 Created
#         return Response(serializer.errors, status=400)    # 400 Bad Request

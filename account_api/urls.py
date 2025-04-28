from django.urls import path
from .views import RegisterView, LoginView, ForgotPasswordView, ResetPasswordValidateView, ResetPasswordView, activate

from rest_framework_simplejwt.views import TokenRefreshView 

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('activate/<uidb64>/<token>/', activate, name='activate'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    path('forgot_password/', ForgotPasswordView.as_view(), name='forgot_password'),

    path('reset_password_validate/<uidb64>/<token>/', ResetPasswordValidateView.as_view(), name='reset_password_validate'),

    path('reset_password/', ResetPasswordView.as_view(), name='reset_password'),
]

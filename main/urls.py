from django.urls import path
from .views import UserCreate, CustomTokenObtainPairView, PasswordResetRequestView, \
    PasswordResetConfirmView, UserProfileUpdateView, LogoutView, UserListView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView


urlpatterns = [
    path('register/', UserCreate.as_view(), name='register'),
    path('login/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('profile/update/', UserProfileUpdateView.as_view(), name='profile-update'),
    path('users/', UserListView.as_view(), name='user-list'),
    path('logout/', LogoutView.as_view(), name='logout'),
  
    # reset password
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('password/reset/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('password/reset/confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
]
from django.contrib.auth import authenticate, login
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str

from .models import User
from .serializers import UserRegistrationSerializer, LoginSerializer, \
PasswordResetRequestSerializer, PasswordResetConfirmSerializer, UserProfileUpdateSerializer, UserSerializer
from .custom_permissions import IsAdminUserType

from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework import generics
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework import status


# Create your views here.
class UserCreate(generics.CreateAPIView):
    authentication_classes = ()
    permission_classes = ()
    serializer_class = UserRegistrationSerializer

    def perform_create(self, serializer):
        user = serializer.save()
        refresh = RefreshToken.for_user(user) 


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        print('validated_data here: ', serializer.validated_data)

        # Obtain the access token
        user_data = serializer.validated_data.get('user')
        #print(f"user_data in views is now {user_data}")

        if user_data:
            user = get_user_model().objects.get(id=user_data['id'])
            refresh = RefreshToken.for_user(user)
            print(f'#####Refresh token obtained for {user.user_type} user in views here!######')
            refresh_token = str(refresh)
            #print('Generated Refresh Token from views:', refresh_token)
            access_token = str(refresh.access_token)
            print('Generated Access Token from views:', access_token)
            # Include the access token in the response data
            response.data['access_token'] = access_token
            response.data['refresh_token'] = refresh_token

        return response


class UserProfileUpdateView(generics.UpdateAPIView):
    serializer_class = UserProfileUpdateSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user


class UserListView(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = (IsAdminUserType,)


# class LogoutView(APIView):
#     permission_classes = (IsAuthenticated,)

#     def post(self, request, *args, **kwargs):
#         # Delete the refresh token associated with the user
#         request.user.auth_token.delete()
#         return Response(status=status.HTTP_204_NO_CONTENT)


class LogoutView(APIView):
    def post(self, request):
        try:
            # Extract the refresh token from the request
            refresh_token = request.data.get('refresh_token')
            if refresh_token:
                # Blacklist the refresh token
                token = RefreshToken(refresh_token)
                token.blacklist()
                logout(request)
                return Response({'detail': 'Successfully logged out.'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Refresh token is required.'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PasswordResetRequestView(GenericAPIView):
    serializer_class = PasswordResetRequestSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        user = User.objects.get(email=email)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        # Here, you would send the password reset email containing the link with uid and token

        return Response({"message": "Password reset email has been sent."}, status=status.HTTP_200_OK)



class PasswordResetConfirmView(GenericAPIView):
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']
        password = serializer.validated_data['password']

        # Set the new password for the user
        user.set_password(password)
        user.save()

        return Response({"message": "Password has been successfully reset."}, status=status.HTTP_200_OK)



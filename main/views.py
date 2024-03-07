from django.contrib.auth import authenticate, login
from django.contrib.auth import get_user_model
from .models import User
from .serializers import UserRegistrationSerializer, LoginSerializer

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import generics
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView



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
        print(f"user_data in views is now {user_data}")

        if user_data:
            user = get_user_model().objects.get(id=user_data['id'])
            refresh = RefreshToken.for_user(user)
            print('Refresh token obtained in views here!')
            access_token = str(refresh.access_token)
            print('Generated Access Token from views:', access_token)
            # Include the access token in the response data
            response.data['access_token'] = access_token

        return response




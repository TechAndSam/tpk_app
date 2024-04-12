from django.contrib.auth import authenticate, login
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.shortcuts import get_object_or_404

from django.core.mail import send_mail
from django.template.loader import render_to_string 
from django.conf import settings


from .models import User, UniqueRegistrationCode
from .serializers import UserRegistrationSerializer, LoginSerializer, \
PasswordResetRequestSerializer, PasswordResetConfirmSerializer, UserProfileUpdateSerializer, \
UserSerializer, UniqueRegistrationCodeSerializer
from .custom_permissions import IsAdminUserType

from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework import generics
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.decorators import api_view
from rest_framework import status


# Create your views here.
class User1Create(generics.CreateAPIView):
    authentication_classes = ()
    permission_classes = ()
    serializer_class = UserRegistrationSerializer

    # def perform_create(self, serializer):
    #     user = serializer.save()
    #     refresh = RefreshToken.for_user(user)

    def perform_create(self, serializer):
        user = serializer.save()

        # Generate activation token
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        # Construct activation link
        activation_link = f"{settings.FRONTEND_URL}/activate/{uid}/{token}/"

        # Render email template
        email_subject = "Activate Your Account"
        email_message = render_to_string('email/activation_email.html', {'activation_link': activation_link})

        # Send activation email
        send_mail(
            email_subject,
            email_message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )

        # Optionally, you can also generate JWT tokens for immediate login after registration
        refresh = RefreshToken.for_user(user)

        return Response({"message": "Account created. Please check your email for activation instructions."}, status=status.HTTP_201_CREATED)



@api_view(['POST'])
def UserCreate(request):
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()

        # Generate activation token
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        # Construct activation link
        activation_link = f"{settings.FRONTEND_URL}/activate/{uid}/{token}/"

        # Render email template
        email_subject = "Activate Your Account"
        email_message = render_to_string('email/activation_email.html', {'activation_link': activation_link})

        # Send activation email
        send_mail(
            email_subject,
            email_message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )

        return Response({"message": "Account created. Please check your email for activation instructions."}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def activate_user(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = get_user_model().objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        return redirect('login')  # Redirect to login page after activation
    else:
        raise Http404("Invalid activation link")



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


class UniqueRegistrationCodeListView(generics.ListAPIView):
    queryset = UniqueRegistrationCode.objects.all()
    serializer_class = UniqueRegistrationCodeSerializer


class UserProfileUpdateView(generics.UpdateAPIView):
    serializer_class = UserProfileUpdateSerializer
    #permission_classes = [IsAuthenticated]

    def get_object(self):
        user_id = self.kwargs['user_id'] 
        return get_object_or_404(User, pk=user_id)
        

class UserListView(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    #permission_classes = (IsAdminUserType,)


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


class Password1ResetRequestView(GenericAPIView):
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


class Password2ResetRequestView(GenericAPIView):
    serializer_class = PasswordResetRequestSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        user = User.objects.get(email=email)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        # Construct the reset password link
        reset_link = f"http://example.com/reset-password/{uid}/{token}/"

        # Construct the email message
        subject = "Reset your password"
        message = render_to_string('password_reset_email.html', {'reset_link': reset_link})
        from_email = "your@example.com"
        to_email = [email]

        # Send the password reset email
        send_mail(subject, message, from_email, to_email)

        return Response({"message": "Password reset email has been sent."}, status=status.HTTP_200_OK)



class PasswordResetRequestView(GenericAPIView):
    serializer_class = PasswordResetRequestSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        user = User.objects.get(email=email)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        # Construct the reset password link
        reset_link = f"{settings.FRONTEND_URL}/reset-password/{uid}/{token}/"

        # Render the email template with the reset link
        email_subject = "Reset your password"
        email_message = render_to_string('email/password_reset_email.html', {'reset_link': reset_link})
        # Render email template using Django templating engine
        #email_message = render_to_template('email/password_reset_email.html', context)


        # Send the email
        send_mail(
            email_subject,
            email_message,
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )

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



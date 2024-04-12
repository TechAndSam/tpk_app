from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework.exceptions import ValidationError

from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from .models import User, UniqueRegistrationCode, UserType



# serializers
class UserTypeSerializer(serializers.ModelSerializer):
	class Meta:
		model = UserType 
		fields = '__all__'


class UniqueRegistrationCodeSerializer(serializers.ModelSerializer):
	class Meta:
		model = UniqueRegistrationCode
		fields = '__all__'


class User1RegistrationSerializer(serializers.ModelSerializer):
	password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
	password2 = serializers.CharField(write_only=True, required=True)
	code = serializers.CharField(required=True)
	#user_type = UserTypeSerializer()
	
	class Meta:
		#model = User
		model = get_user_model()
		fields = ('username', 'email',  'code', 'password', 'password2')

	def create(self, validated_data):
		password = validated_data.pop('password')
		password2 = validated_data.pop('password2')
		code = validated_data.pop('code')
		print(f"code is {code}")
		
		# check passwords
		if password != password2:
			raise serializers.ValidationError({'password': 'Passwords must match!'})

		# check if code is available
		registration_code = UniqueRegistrationCode.objects.filter(code=code).first()
		if not registration_code or registration_code.status != 'AVAILABLE':
			raise serializers.ValidationError({'code':'Invalid or used registration code!'})

		# mark the code as used
		registration_code.status = 'USED'
		registration_code.save()

		# Create the user instance without 'code'
		user = get_user_model().objects.create(**validated_data)
		print(f'user created after successful serializeration; expect code to be removed!')
		user.set_password(password)
		user.save()

		# user = User(**validated_data)
		# user.set_password(password)
		# user.save()

		# add refresh token for user
		refresh = RefreshToken.for_user(user)
		return user


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)
    code = serializers.CharField(required=True)

    class Meta:
        model = get_user_model()
        fields = ('username', 'email', 'code', 'password', 'password2')

    def validate_code(self, value):
        # Check if code is available
        registration_code = UniqueRegistrationCode.objects.filter(code=value).first()
        if not registration_code or registration_code.status != 'AVAILABLE':
            raise serializers.ValidationError('Invalid or used registration code!')
        return value

    def save(self, **kwargs):
        validated_data = dict(self.validated_data)
        code = validated_data.pop('code')
        validated_data.pop('password2', None)
        
        # Create the user instance without 'code'
        user = get_user_model().objects.create(**validated_data)
        user.set_unusable_password()
        user.save()

        # Mark the code as used
        registration_code = UniqueRegistrationCode.objects.get(code=code)
        registration_code.status = 'USED'
        registration_code.save()

        return user


class LoginSerializer(serializers.Serializer):
	username = serializers.CharField(max_length=255)
	password = serializers.CharField(max_length=128, write_only=True)
	token = serializers.CharField(allow_blank=True, read_only=True)

	class Meta:
		fields = ['username', 'password']

	def validate(self, attrs):
		username = attrs.get('username')
		password = attrs.get('password')

		if username and password:
			user = authenticate(username=username, password=password)
			print(f'first authentication passed!')

			if not user:
				raise serializers.ValidationError({'message':'Invalid credentials!'})

			if not user.check_password(password):
				raise serializers.ValidationError({'message': 'Invalid password!'})

			# Generate access token and include relevant details in response
			refresh = RefreshToken.for_user(user)
			access_token = str(refresh.access_token)

			user_data = {
				'id': user.id,
            	'username': user.username
            	}

			attrs['user'] = user_data  # Include user object (optional)
			attrs['access_token'] = access_token
			print(f"user_data returned: {user_data}")
			print(f"user attrs here ==> {attrs}")

			return attrs
		else:
			raise serializers.ValidationError({'username': 'Username and password are required!'})


class UniqueRegistrationCodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = UniqueRegistrationCode
        fields = ['code', 'status']


class UserProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'profile_picture']
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def update(self, instance, validated_data):
        instance.username = validated_data.get('username', instance.username)
        instance.email = validated_data.get('email', instance.email)
        instance.profile_picture = validated_data.get('profile_picture', instance.profile_picture)
        password = validated_data.get('password')
        if password:
            instance.set_password(password)
        instance.save()
        return instance



class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'user_type', 'profile_picture', 'is_active', 'is_staff')


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise ValidationError("No account with this email address exists.")
        return value


class PasswordResetConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField()
    token = serializers.CharField()
    password = serializers.CharField(min_length=6)

    def validate(self, attrs):
        email = attrs['email']
        token = attrs['token']
        password = attrs['password']

        user = User.objects.filter(email=email).first()
        if not user:
            raise ValidationError("Invalid email address.")

        if not default_token_generator.check_token(user, token):
            raise ValidationError("Invalid or expired token.")

        attrs['user'] = user
        return attrs
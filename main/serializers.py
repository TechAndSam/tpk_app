from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from .models import User, UniqueRegistrationCode, UserType


class UserTypeSerializer(serializers.ModelSerializer):
	class Meta:
		model = UserType 
		fields = '__all__'


class UniqueRegistrationCodeSerializer(serializers.ModelSerializer):
	class Meta:
		model = UniqueRegistrationCode
		fields = '__all__'


class UserRegistrationSerializer(serializers.ModelSerializer):
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


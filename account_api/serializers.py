
from rest_framework import serializers
from .models import Account
from django.contrib.auth.password_validation import validate_password
from .utils import send_verification_email  # Assume you move send_verification_email to utils.py

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = Account
        fields = ['email', 'username', 'first_name', 'last_name', 'password', 'confirm_password']

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return attrs

    def create(self, validated_data):
        request = self.context.get('request')  # Get request from serializer context
        
        validated_data.pop('confirm_password')
        user = Account.objects.create_user(**validated_data)
        user.is_active = False  # Important: user should be inactive until email verification
        user.save()

        # Send verification email
        mail_subject = 'Please activate your account'
        mail_template = 'accounts/account_verification_email.html'
        send_verification_email(request, user, mail_subject, mail_template)

        return user

# Login Serializer (SimpleJWT handles it)
from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import Account

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            user = authenticate(username=email, password=password)

            if not user:
                raise serializers.ValidationError('Invalid email or password.')
            if not user.is_active:
                raise serializers.ValidationError('Account is not active, please verify your email.')

            attrs['user'] = user
            return attrs
        else:
            raise serializers.ValidationError('Must include "email" and "password".')



from django.contrib.auth import get_user_model

Account = get_user_model()
class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Account does not exist with this email.")
        return value


# serializers.py

class ResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return attrs


from .models import People

class PeopleSerializer(serializers.ModelSerializer):
    class Meta:
        model = People
        fields = '__all__'

    def validate(self, data):
        special_characters = '!@#$%&*()-++_=<>/,'
        if any(c in special_characters for c in data['name']):
            raise serializers.ValidationError('Name cannot contain special characters.')

        if data['age'] < 18:
            raise serializers.ValidationError('Age must be 18 or above.')

        return data




# serializers.py

from rest_framework import serializers
from django.contrib.auth import get_user_model

User = get_user_model()

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Account does not exist with this email.")
        return value

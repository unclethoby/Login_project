from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password

User = get_user_model()

# ---------------------- Register Serializer ----------------------
class RegisterSerializer(serializers.ModelSerializer):
    """
    Handles user registration:
    - Validates email uniqueness.
    - Creates an inactive user until email is verified.
    Returns: newly created user instance.
    """
    email = serializers.EmailField(
        required=True,
        validators=[
            UniqueValidator(
                queryset=User.objects.all(),
                message="A user with this email already exists."
            )
        ]
    )

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'password']
        extra_kwargs = {
            'password': {'write_only': True, 'min_length': 3},
        }

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
        )
        user.set_password(validated_data['password'])
        user.is_active = False  # Email verification required
        user.save()
        return user

# ---------------------- Login Serializer ----------------------
class LoginSerializer(serializers.Serializer):
    """
    Accepts user credentials:
    - Email
    - Password
    Used for authentication and JWT generation.
    """
    email = serializers.EmailField()
    password = serializers.CharField()

# ---------------------- Forgot Password (Email) Serializer ----------------------
class EmailSerializer(serializers.Serializer):
    """
    Accepts user's email:
    - Used to initiate password reset flow.
    """
    email = serializers.EmailField()

# ---------------------- Reset Password Serializer ----------------------
class ResetPasswordSerializer(serializers.Serializer):
    """
    Accepts data for password reset:
    - uidb64: Encoded user ID.
    - token: Password reset token.
    - new_password: Validated new password.
    """
    uidb64 = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True, validators=[validate_password])

# ---------------------- Email Verification Serializer ----------------------
class EmailVerificationSerializer(serializers.Serializer):
    """
    Accepts data for email verification:
    - uidb64: Encoded user ID.
    - token: Email verification token.
    """
    uidb64 = serializers.CharField()
    token = serializers.CharField()

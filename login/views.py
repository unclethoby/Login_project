import threading
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.tokens import default_token_generator, PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework import status, generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import (
    RegisterSerializer, EmailSerializer, LoginSerializer,
    ResetPasswordSerializer, EmailVerificationSerializer
)

User = get_user_model()


class RegisterView(APIView):
    """
    User Registration Endpoint.

    POST:
    Accepts: username, email, first_name, last_name, password  
    Creates a new user and sends an email verification link.  
    Returns: 201 Created on success, 400 Bad Request on error.
    """
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        activation_url = request.build_absolute_uri(
            reverse('verify-email') + f'?uidb64={uid}&token={token}'
        )

        threading.Thread(
            target=self.send_verification_email,
            args=(user.email, activation_url)
        ).start()

        return Response(
            {"message": "Registration successful. Check your email to verify."},
            status=status.HTTP_201_CREATED
        )

    def send_verification_email(self, email, activation_url):
        """Send account verification email with activation link."""
        send_mail(
            subject="Verify Your Email",
            message=f"Click the link to verify your account:\n{activation_url}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=True
        )


class VerifyEmailView(APIView):
    """
    Email Verification Endpoint.

    GET:
    Accepts: uidb64, token  
    Activates the user account if token is valid.  
    Returns: 200 OK on success, 400 Bad Request if invalid/expired.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        serializer = EmailVerificationSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)

        try:
            uid = force_str(urlsafe_base64_decode(serializer.validated_data['uidb64']))
            user = User.objects.get(pk=uid)
        except Exception:
            return Response({"error": "Invalid user"}, status=status.HTTP_400_BAD_REQUEST)

        if default_token_generator.check_token(user, serializer.validated_data['token']):
            user.is_active = True
            user.is_verified = True
            user.save()
            return Response({"message": "Email successfully verified"}, status=status.HTTP_200_OK)

        return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    """
    User Login Endpoint.

    POST:
    Accepts: email, password  
    Returns: JWT access and refresh tokens if credentials are valid.  
    Returns: 401 Unauthorized if credentials are invalid or user inactive.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = authenticate(
            email=serializer.validated_data['email'],
            password=serializer.validated_data['password']
        )

        if user and user.is_active:
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token)
            }, status=status.HTTP_200_OK)

        return Response(
            {'error': 'Invalid credentials or inactive user'},
            status=status.HTTP_401_UNAUTHORIZED
        )


class ForgotPasswordView(generics.GenericAPIView):
    """
    Forgot Password Endpoint.

    POST:
    Accepts: email  
    Sends a password reset link to the given email if user exists.  
    Returns: 200 OK if email sent, 404 if user not found.
    """
    serializer_class = EmailSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        try:
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = PasswordResetTokenGenerator().make_token(user)

            reset_url = request.build_absolute_uri(
                reverse('reset-password')
            ) + f"?uidb64={uid}&token={token}"

            threading.Thread(
                target=self.send_reset_email,
                args=(email, reset_url)
            ).start()

            return Response(
                {"message": "Password reset link sent successfully."},
                status=status.HTTP_200_OK
            )
        except User.DoesNotExist:
            return Response(
                {"error": "User with this email does not exist."},
                status=status.HTTP_404_NOT_FOUND
            )

    def send_reset_email(self, email, reset_url):
        """Send password reset email with tokenized reset link."""
        send_mail(
            subject="Password Reset Request",
            message=f"Click here to reset your password:\n{reset_url}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=True
        )


class ResetPasswordView(generics.GenericAPIView):
    """
    Password Reset Endpoint.

    POST:
    Accepts: uidb64, token, new_password  
    Verifies token and resets password.  
    Returns: 200 OK on success, 400 Bad Request on failure.
    """
    serializer_class = ResetPasswordSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        uidb64 = serializer.validated_data['uidb64']
        token = serializer.validated_data['token']
        new_password = serializer.validated_data['new_password']

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response(
                {"error": "Invalid or expired password reset link."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not PasswordResetTokenGenerator().check_token(user, token):
            return Response(
                {"error": "Token is invalid or expired."},
                status=status.HTTP_400_BAD_REQUEST
            )

        user.set_password(new_password)
        user.save()
        return Response(
            {"message": "Password has been reset."},
            status=status.HTTP_200_OK
        )

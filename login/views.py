from rest_framework import status, generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .serializers import RegisterSerializer, EmailSerializer, ResetPasswordSerializer


User = get_user_model()

# User registration view
class RegisterView(APIView):
    permission_classes = [AllowAny]  # Allow any user to access this view

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            # Send welcome/confirmation email
            subject = "Welcome to Our Platform!"
            message = f"Hi {user.username},\n\nThank you for registering at our site."
            recipient_list = [user.email]

            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,  # Make sure to edit email in settings.py
                recipient_list=recipient_list,
                fail_silently=False,
            )
            return Response(
                {"message": "User registered successfully. A welcome email has been sent.", "user": serializer.data},
                status=status.HTTP_201_CREATED
            )
        return Response(
            {"errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )
# View to request password reset link
class ForgotPasswordView(generics.GenericAPIView):
    serializer_class = EmailSerializer
    permission_classes = [AllowAny] # Public endpoint

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True) # Validate email input
        email = serializer.validated_data['email']

        try:
            user = User.objects.get(email=email) # Check if user exits
            uid = urlsafe_base64_encode(force_bytes(user.pk)) # Encode user ID
            token = PasswordResetTokenGenerator().make_token(user) # Generate token

            # Build password reset URL
            reset_url = request.build_absolute_uri(
                reverse('reset-password') # Ensure this name exits in urls.py
            ) + f"?uidb64={uid}&token={token}"

            # Send email
            send_mail(
                subject="Password Reset Request",
                message=f"Click here to reset your password:\n{reset_url}",
                from_email=None, # Uses DEFAULT_FROM_EMAIL
                recipient_list=[email]
            )
            return Response({"message": "Password reset link sent successfully."}, 
                            status=status.HTTP_200_OK
                            )
        except User.DoesNotExist:
            return Response({"error": "User with this email does not exit."},
                             status=status.HTTP_404_NOT_FOUND
                             )

# View to reset password
class ResetPasswordView(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer
    permission_classes = [AllowAny]  # Public access to reset password with valid token

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        uidb64 = serializer.validated_data['uidb64']
        token = serializer.validated_data['token']
        new_password = serializer.validated_data['new_password']

        try:
            # Decode the User ID
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"error": "Invalid or expired password rest link."},
                             status=status.HTTP_400_BAD_REQUEST
                             )

        # Check if the token is valid
        if not PasswordResetTokenGenerator().check_token(user, token):
            return Response({"error": "Token is invalid or expired."},
                             status=status.HTTP_400_BAD_REQUEST
                             )
        # Set new password and save the user
        user.set_password(new_password)
        user.save()
        return Response({"message": "Password has been reset."},
                        status=status.HTTP_200_OK
                        )

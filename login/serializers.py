from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

User = get_user_model()

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ['id','username', 'email','first_name','last_name' ,'password']
        extra_kwargs = {
            'password': {'write_only': True, 'min_length': 3},
        }

    def create(self, validated_data):
            username=validated_data['username']
            email=validated_data['email']
            password=validated_data['password']
            first_name=validated_data['first_name']
            last_name = validated_data['last_name']

            user = get_user_model()
            new_user = user.objects.create_user(username=username, email=email,
                                                 first_name=first_name,last_name=last_name)
            new_user.set_password(password)
            new_user.save()
    
            return new_user

class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField()

class ResetPasswordSerializer(serializers.Serializer):
    uidb64 = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True, validators=[validate_password])

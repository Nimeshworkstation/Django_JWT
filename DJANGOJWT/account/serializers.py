from rest_framework import serializers
from .models import MyUser
from xml.dom import ValidationErr
from django.utils.encoding import smart_str,force_bytes,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.exceptions import ValidationError



class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type':'password'},write_only=True)
    class Meta:
        model = MyUser
        fields = ['email','name','password','password2','tc']
        extra_kwargs={
            'password':{'write_only':True}
        }

    def validate(self,attrs):
        password = attrs.get('password')
        password2 =  attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError("Password dont match")
        return attrs

    def create(self,validate_data):
        return MyUser.objects.create_user(**validate_data)
    

class UserLoginSerializer(serializers.ModelSerializer):
  email = serializers.EmailField(max_length=255)
  class Meta:
    model = MyUser
    fields = ['email', 'password']

class UserProfileSerializer(serializers.ModelSerializer):
  class Meta:
    model = MyUser
    fields = ['id', 'email', 'name']

class UserchangePasswordSerializer(serializers.Serializer):
   password = serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)
   password2 = serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)
   class Meta:
      fields = ['password','password2']

      def validate(self,attrs):
        password = attrs.get('password')
        password2 =  attrs.get('password2')
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError("Password dont match")
        user.set_password(password)
        user.save()
        return attrs
      
class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=100)
    class Meta:
      fields = ['email']
    def validate(self,attrs):
       email = attrs.get('email')
       if  MyUser.objects.filter(email=email).exists():
          user = MyUser.objects.get(email=email)
          uid = urlsafe_base64_encode(force_bytes(user.id))
          token = PasswordResetTokenGenerator().make_token(user )
          link = 'http://localhost:3000/api/user/reset/'+uid+'/'+token
          print(link)
          body = 'Click Following Link to Reset Your Password '+link
          data = {
        'subject':'Reset Your Password',
        'body':body,
        'to_email':user.email
      }
          return attrs
       
       else:
          raise ValidationErr('Your are not registered user')

  
      
class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)
    password2 = serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)
    class Meta:
        fields = ['password','password2']
        def validate(self,attrs):
            try:
                password = attrs.get('password')
                password2 =  attrs.get('password2')
                uid = self.context.get('uid')
                token = self.context.get('token')
                if password != password2:
                    raise serializers.ValidationError("Password dont match")
                id = smart_str(urlsafe_base64_decode(uid))
                user = MyUser.objects.get(id=id)
                if not PasswordResetTokenGenerator().check_token(user,token):
                 raise ValidationError('Token Expired')
                user.set_password(password)
                user.save()
                return attrs
            except DjangoUnicodeDecodeError as identifier:
               PasswordResetTokenGenerator().check_token(user,token)
               raise ValidationError('Token is expired')

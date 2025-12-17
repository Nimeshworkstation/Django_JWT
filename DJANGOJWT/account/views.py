from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from .serializers import UserRegistrationSerializer,UserLoginSerializer,UserProfileSerializer,UserchangePasswordSerializer,SendPasswordResetEmailSerializer,UserPasswordResetSerializer
from django.contrib.auth import authenticate
from .renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]
    def post(self,request,format=None):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response({'msg': 'Registration Succesful','token': token},status=status.HTTP_201_CREATED)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    # renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.validated_data.get('email') 
            password = serializer.validated_data.get('password')  
            user = authenticate(request, email=email, password=password) 
            if user is not None:
                token = get_tokens_for_user(user)
                return Response({'msg': 'Login Successful','token': token}, status=status.HTTP_200_OK)
        return Response({'errors': {'non_field_errors': ['Email or password not valid']}}, status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self,request, format=None):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ChangePasswordView(APIView):
    # permission_classes = [IsAuthenticated] 
    def post(self,request,format=None):
        serializer = UserchangePasswordSerializer(data=request.data,context={'user':request.user})   
        if serializer.is_valid(raise_exception=True):
            return Response({'msg': 'Password changed'}, status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

class SendPasswordResetEmailView(APIView):
    def post(self,request,format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'Password Reset Link sent.Please check you email'},status=status.HTTP_200_OK,)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
    

class PasswordReset(APIView):
    def post(self,request,uid,token,format=None):
        serializer = UserPasswordResetSerializer(data=request.data,context={'token':token,'uid':uid})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'password changed'},status=status.HTTP_100_CONTINUE)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


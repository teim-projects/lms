from django.contrib import admin
from django.urls import path , include
from lmsapp import views

urlpatterns = [
    path('signup/', views.signup, name='signup'),
    path('logout/', views.logout_view, name='logout'),
    path('', views.login, name='login'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('password-reset/', views.password_reset, name='password_reset'),
    path('reset-password-verify/', views.reset_password_verify, name='reset_password_verify'),
    path('reset-password-confirm/', views.reset_password_confirm, name='reset_password_confirm'),
    path('student_dashboard', views.student_dashboard , name='student_dashboard'),

]
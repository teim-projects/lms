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
    path('student_dashboard/', views.student_dashboard , name='student_dashboard'),
    path('admin_dashboard/', views.admin_dashboard , name='admin_dashboard'),
    path('create-free-course/', views.create_free_course, name='create_free_course'),
    path('free-course/', views.free_course, name='free_course'),
    path('paid-course/', views.paid_course, name='paid_course'),
    path('create-paid-course/', views.create_paid_course, name='create_paid_course'),


]



from django.conf import settings
from django.conf.urls.static import static

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

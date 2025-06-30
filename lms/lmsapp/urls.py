from django.contrib import admin
from django.urls import path , include
from lmsapp import views




urlpatterns = [
    path('signup/', views.signup, name='signup'),
    path('logout/', views.logout_view, name='logout'),
    path('login/', views.login, name='login'),
    path('', views.index, name='index'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('password-reset/', views.password_reset, name='password_reset'),
    path('reset-password-verify/', views.reset_password_verify, name='reset_password_verify'),
    path('reset-password-confirm/', views.reset_password_confirm, name='reset_password_confirm'),
    path('student_dashboard/', views.student_dashboard , name='student_dashboard'),
    path('admin_dashboard/', views.admin_dashboard , name='admin_dashboard'),
    path('create-free-course/', views.create_free_course, name='create_free_course'),
    path('free-course/', views.free_courses, name='free_course'),
    path('paid-course/', views.paid_course, name='paid_course'),
    path('create-paid-course/', views.create_paid_course, name='create_paid_course'),
    path('view_paid_course/', views.view_paid_course, name='view_paid_course'),
    path('course/<int:course_id>/upload-content/', views.upload_content, name='upload_content'),
    path('course/<int:course_id>/view-content/', views.view_content, name='view_content'),
    path('delete-course/<int:course_id>/', views.delete_free_course, name='delete_free_course'),
    path('update-course/<int:course_id>/', views.update_free_course, name='update_free_course'),
    path('delete_paid_course/<int:course_id>/', views.delete_paid_course, name='delete_paid_course'),
    path('update_paid_course/<int:course_id>/', views.update_paid_course, name='update_paid_course'),
    path('manage_subadmins/', views.manage_subadmins, name='manage_subadmins'),
    path('subadmin_dashboard/', views.subadmin_dashboard, name='subadmin_dashboard'),
    path('subadmin-login/', views.subadmin_login_view, name='subadmin_login'),

    

    path('send_notification/', views.send_notification, name='send_notification'),
    path('course/<int:course_id>/view_content/<int:content_id>/complete/', views.mark_content_completed, name='mark_content_completed'),
    path('get-progress/<int:course_id>/', views.get_course_progress, name='get_course_progress'),
    path("tickets/", views.ticket_list, name="ticket_list"),
    path("ticket_to_admin/", views.ticket_to_admin, name="ticket_to_admin"),
    path("tickets/raise/", views.raise_ticket, name="raise_ticket"),
    path("tickets/close/<int:ticket_id>/", views.close_ticket, name="close_ticket"),
    path('admin_user_list/', views.user_list, name='admin_user_list'),
    path('export-users/', views.export_users_to_excel, name='export_users'),

    path('captcha/', include('captcha.urls')),


    # start

    path('paid-courses/', views.student_paid_courses, name='student_paid_courses'),
    path('display_paid_content/<int:course_id>/', views.display_paid_content, name='display_paid_content'),
    

# payment
    
    # path("payment/<int:course_id>/", views.initiate_payment, name="initiate_payment"),
    # path("payment/success/", views.payment_success, name="payment_success"),
    # path("payment/failure/", views.payment_failure, name="payment_failure"),
    


    path('course/<int:course_id>/pay/', views.initiate_payment, name='initiate_payment'),
    path('payment/success/', views.payment_success, name='payment_success'),
    path('payment/failure/', views.payment_failure, name='payment_failure'),


    # access to paid course
    path('grant-access/', views.grant_course_access, name='grant_course_access'),

    path('mark-complete/', views.mark_content_complete, name='mark_content_complete'),

    path('enrollment_tracking/', views.enrollment_tracking, name='enrollment_tracking'),

    path('course-list/', views.paid_course_list, name='paid_course_list'),
    
    path('paid-students/', views.paid_students_list, name='paid_students_list'),

    path('user-detail/<int:user_id>/', views.user_detail_view, name='user_detail'),

    path('invoice/<int:payment_id>/', views.generate_invoice_view, name='generate_invoice'),
    path('invoice/<int:invoice_id>/cancel/', views.cancel_invoice_view, name='cancel_invoice'),
    path('invoice/<int:invoice_id>/toggle/', views.toggle_invoice_status_view, name='toggle_invoice'),

    path('dashboard/', views.invoice_dashboard_view, name='invoice_dashboard'),


    


    

    

    
    

]





from django.conf import settings
from django.conf.urls.static import static

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# Create your views here.
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password



def student_dashboard(request):
    # Render a simple dashboard with a header
    return render(request, 'student_dashboard.html')


def admin_dashboard(request):
    # Get admin email from session
    admin_email = request.session.get('admin_email', 'Admin Email')
    return render(request, 'admin_dashboard.html', {'admin_email': admin_email})

def signup(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        # Validation
        if not email or not mobile or not password or not confirm_password:
            messages.error(request, 'All fields are required.')
            return render(request, 'lmsapp/signup.html')

        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'lmsapp/signup.html')

        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already registered.')
            return render(request, 'lmsapp/signup.html')

        # Create User
        user = User.objects.create_user(
            username=email,  # Use email as username
            email=email,
            password=make_password(password),
        )
        user.profile.mobile = mobile  # Assuming you extend User with a Profile model
        user.save()

        messages.success(request, 'Signup successful. Please login.')
        return redirect('login')  # Adjust the name of your login URL as needed

    return render(request, 'lmsapp/signup.html')




import re
from django.core.exceptions import ValidationError
from django.core.mail import send_mail, BadHeaderError
from django.contrib import messages
from django.shortcuts import render, redirect
from twilio.rest import Client
from lmsapp.models import OTP, CustomUser  # Assuming CustomUser model is in the same app

# Validate phone number in E.164 format
def validate_phone_number(phone):
    pattern = re.compile(r'^\+\d{10,15}$')  # E.164 format
    if not pattern.match(phone):
        raise ValidationError("Invalid phone number format. Use E.164 format (e.g., +1234567890).")
    return phone

def send_otp_email(email, otp_code):
    try:
        send_mail(
            'Account Verification',
            f'Your OTP for signup is: {otp_code}',
            'noreply@myapp.com',
            [email]
        )
    except BadHeaderError:
        raise ValidationError("Invalid email header found.")
    except Exception as e:
        raise ValidationError(f"Error sending email: {e}")
    

from twilio.rest import Client
import os

def send_otp_sms(mobile, otp_code):
    try:
        account_sid = os.getenv("TWILIO_ACCOUNT_SID")
        auth_token = os.getenv("TWILIO_AUTH_TOKEN")
        client = Client(account_sid, auth_token)

        message = client.messages.create(
            body=f"Your OTP for signup is: {otp_code}",
            from_=os.getenv("TWILIO_PHONE_NUMBER"),
            to=mobile
        )
    except Exception as e:
        raise ValidationError(f"Error sending SMS: {e}")




def signup(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        country_code = request.POST.get('country_code')  # Get the selected country code
        mobile = request.POST.get('mobile')  # Get the mobile number
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        # Combine the country code and mobile number
        full_mobile_number = f"{country_code}{mobile}"

        # Validate the phone number format (e.g., E.164)
        try:
            full_mobile_number = validate_phone_number(full_mobile_number)
        except ValidationError as e:
            messages.error(request, str(e))
            return redirect('signup')

        # Check for existing email or mobile
        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, f"User with email ({email}) already exists.")
            return redirect('signup')

        if CustomUser.objects.filter(mobile=full_mobile_number).exists():
            messages.error(request, f"User with mobile number ({full_mobile_number}) already exists.")
            return redirect('signup')

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect('signup')

        # Create user and send OTP
        user = CustomUser.objects.create_user(email=email, mobile=full_mobile_number, password=password)
        user.is_active = False
        user.save()

        otp_code = OTP.generate_otp()
        OTP.objects.create(user=user, code=otp_code)

        # Send OTP via Email
        try:
            send_otp_email(email, otp_code)
        except ValidationError as e:
            messages.error(request, str(e))
            return redirect('signup')
               
               
        # # Send OTP via Voice Call


        # try:
        #     send_otp_call(full_mobile_number, otp_code)
        #     messages.success(request, "An OTP call has been made to your mobile. Please listen to the OTP.")
        # except Exception as e:
        #     messages.error(request, f"Error sending OTP call: {e}")
        #     return redirect('signup')

        # Send OTP via SMS using Twilio
        try:
            send_otp_sms(full_mobile_number, otp_code)
        except ValidationError as e:
            messages.error(request, str(e))
            return redirect('signup')

        messages.success(request, "Signup successful. Please verify your email and mobile.")
        request.session['user_id'] = user.id
        return redirect('verify_otp')

    return render(request, 'signup.html')



from django.core.mail import send_mail, BadHeaderError
from django.utils.timezone import now, timedelta

def verify_otp(request):
    if request.method == 'POST':
        user_id = request.session.get('user_id')
        user = CustomUser.objects.get(id=user_id)
        entered_otp = request.POST['otp']

        # Retrieve OTP and check for time validity
        otp = OTP.objects.filter(user=user, code=entered_otp).first()
        
        # Get the count of OTP attempts from session
        otp_attempts = request.session.get('otp_attempts', 0)

        if otp and otp.created_at >= now() - timedelta(minutes=10):
            # Successful OTP validation
            user.is_active = True
            user.is_verified = True
            user.save()
            OTP.objects.filter(user=user).delete()  # Delete OTP after use
            
            # Send a welcome email
            try:
                send_mail(
                    'Welcome to Our Institute!',
                    f'Hi {user.email},\n\nWelcome to our institute! We are excited to have you with us.',
                    'welcome@myapp.com',
                    [user.email],
                )
            except BadHeaderError:
                messages.error(request, "Invalid header found while sending welcome email.")
            except Exception as e:
                messages.error(request, f"Error sending welcome email: {e}")

            # Clear session data for OTP attempts
            request.session.pop('otp_attempts', None)
            
            messages.success(request, "Signup successful and welcome email sent.")
            return redirect('/')
        else:
            # Increment OTP attempts
            otp_attempts += 1
            request.session['otp_attempts'] = otp_attempts
            messages.error(request, "Invalid OTP. Please try again.")
            
            # Check if attempts exceeded the limit
            if otp_attempts >= 2:
                OTP.objects.filter(user=user).delete()
                request.session.pop('otp_attempts', None)  # Reset attempts
                return redirect('signup')
    return render(request, 'verify_otp.html')



from django.contrib.auth import login as auth_login  # Ensure proper login function import
from django.shortcuts import redirect, render
from django.contrib import messages
from .models import CustomUser


def login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        # Clear any existing session data
        request.session.pop('admin_email', None)
        request.session.pop('user_email', None)

        # Admin login logic
        if email == 'admin@gmail.com' and password == 'admin':
            request.session['admin_email'] = email
            return redirect('admin_dashboard')  # Redirect to admin dashboard

        # Regular user login logic
        try:
            user = CustomUser.objects.get(email=email)
            if user.check_password(password):  # Validate the password
                auth_login(request, user)  # Log the user in
                request.session['user_email'] = user.email
                return redirect('student_dashboard')  # Redirect to the user's dashboard
            else:
                # Incorrect password
                messages.error(request, "Incorrect password. Please try again.")
        except CustomUser.DoesNotExist:
            # Email not found in the system
            messages.error(request, "User with this email does not exist. Please register.")

    # Render login page with potential error messages
    return render(request, 'login.html')



from django.shortcuts import redirect
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required

def logout_view(request):
    logout(request)  # Logs out the user
    return redirect('login')


def password_reset(request):
    if request.method == 'POST':
        email = request.POST['email']
        user = CustomUser.objects.filter(email=email).first()
        if user:
            otp_code = OTP.generate_otp()
            OTP.objects.create(user=user, code=otp_code)
            send_mail(
                'Password Reset Request',
                f'Your password reset OTP is: {otp_code}',
                'noreply@myapp.com',
                [email]
            )
            request.session['reset_user_id'] = user.id
            return redirect('reset_password_verify')
        messages.error(request, "Email not found")
    return render(request, 'password_reset.html')



from django.utils import timezone

def reset_password_verify(request):
    if request.method == 'POST':
        reset_user_id = request.session.get('reset_user_id')
        user = CustomUser.objects.get(id=reset_user_id)
        entered_otp = request.POST['otp']

        otp = OTP.objects.filter(user=user, code=entered_otp).first()

        if otp and otp.created_at >= timezone.now() - timedelta(minutes=10):
            return redirect('reset_password_confirm')
        messages.error(request, "Invalid OTP")
    return render(request, 'reset_password_verify.html')


def reset_password_confirm(request):
    if request.method == 'POST':
        reset_user_id = request.session.get('reset_user_id')
        user = CustomUser.objects.get(id=reset_user_id)
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if password == confirm_password:
            user.set_password(password)
            user.save()
            messages.success(request, "Password reset successful")
            return redirect('login')
        messages.error(request, "Passwords do not match")
    return render(request, 'reset_password_confirm.html')





from .models import FreeCourse

def create_free_course(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        youtube_link = request.POST.get('youtube_link')
        description = request.POST.get('description')
        thumbnail = request.FILES.get('thumbnail')

        if title and youtube_link and thumbnail and description:
            FreeCourse.objects.create(
                title=title,
                youtube_link=youtube_link,
                thumbnail=thumbnail,
                description=description
            )
            return redirect('create_free_course')

    courses = FreeCourse.objects.all()  # Fetch all courses to display
    return render(request, 'create_free_course.html', {'courses': courses})


def free_course(request):
    courses = FreeCourse.objects.all()  # Fetch all courses to display
    return render(request, 'free_course.html', {'courses': courses})

def paid_course(request):
    # Render a simple dashboard with a header
    return render(request, 'paid_course.html')


def view_paid_course(request):
    courses = PaidCourse.objects.all()
    return render(request, 'view_paid_course.html',{'courses': courses})




from django.shortcuts import render, redirect
from .models import PaidCourse
from django.core.files.storage import FileSystemStorage
def create_paid_course(request):
    if request.method == 'POST':
        course_title = request.POST.get('course_title')
        duration = request.POST.get('duration')
        description = request.POST.get('description')
        instructor_name = request.POST.get('instructor_name')
        course_level = request.POST.get('course_level')
        course_price = request.POST.get('course_price')
        thumbnail = request.FILES.get('thumbnail')

        # Save thumbnail file if provided
        if thumbnail:
            fs = FileSystemStorage()
            filename = fs.save(thumbnail.name, thumbnail)
            thumbnail_url = fs.url(filename)
        else:
            thumbnail_url = None

        # Save data to database
        PaidCourse.objects.create(
            course_title=course_title,
            duration=duration,
            description=description,
            instructor_name=instructor_name,
            course_level=course_level,
            course_price=course_price,
            thumbnail=thumbnail
        )
        return redirect('create_paid_course')  # Redirect to avoid form resubmission

    # Fetch all courses
    courses = PaidCourse.objects.all()

    return render(request, 'paid_course.html', {'courses': courses})





from django.shortcuts import render, get_object_or_404, redirect
from .models import PaidCourse, CourseContent

def upload_content(request, course_id):
    course = get_object_or_404(PaidCourse, id=course_id)
    if request.method == 'POST':
        title = request.POST.get('title')
        subtitles = request.POST.getlist('subtitle')
        resource_files = request.FILES.getlist('resource_file')

        if len(subtitles) != len(resource_files):
            # Handle mismatch between subtitles and files
            return render(request, 'upload_content.html', {'course': course, 'error': 'Each subtitle must have a corresponding file.'})

        # Save content entries
        for subtitle, resource in zip(subtitles, resource_files):
            CourseContent.objects.create(course=course, title=title, subtitle=subtitle, resource_file=resource)

        return redirect('create_paid_course')

    return render(request, 'upload_content.html', {'course': course})




from django.shortcuts import render, get_object_or_404
from .models import PaidCourse, CourseContent

def view_content(request, course_id):
    course = get_object_or_404(PaidCourse, id=course_id)
    contents = course.contents.all()

    # Annotate each content with its type
    annotated_contents = []
    for content in contents:
        file_url = content.resource_file.url
        print(f"Resource File URL: {file_url}")  # Debugging the file URL
        
        # Determine the content type based on the file extension
        if file_url.endswith('.pdf'):
            content_type = 'pdf'
        elif file_url.endswith(('.jpg', '.jpeg', '.png', '.gif')):
            content_type = 'image'
        elif file_url.endswith(('.mp4', '.webm', '.ogg')):
            content_type = 'video'
        # elif file_url.endswith('.docx'):
        #     content_type = 'word'
        else:
            content_type = 'unknown'

        annotated_contents.append({
            'title': content.title,
            'subtitle': content.subtitle,
            'resource_file': file_url,
            'type': content_type,
        })

    return render(request, 'view_content.html', {
        'course': course,
        'contents': annotated_contents,
        
    })



from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from .models import FreeCourse

# Delete Free Course
def delete_free_course(request, course_id):
    if request.method == 'POST':
        course = get_object_or_404(FreeCourse, id=course_id)
        course.delete()
        return redirect('create_free_course')
    

# Update Free Course
def update_free_course(request, course_id):
    course = get_object_or_404(FreeCourse, id=course_id)
    if request.method == 'POST':
        course.title = request.POST.get('title', course.title)
        course.description = request.POST.get('description', course.description)
        course.youtube_link = request.POST.get('youtube_link', course.youtube_link)

        if 'thumbnail' in request.FILES:
            course.thumbnail = request.FILES['thumbnail']

        course.save()
        return redirect('create_free_course')  # Redirect to the course list page

    return render(request, 'update_free_course.html', {'course': course})




from django.shortcuts import render, get_object_or_404, redirect
from .models import PaidCourse

# Delete Paid Course
from django.shortcuts import get_object_or_404, redirect
from django.db import transaction
from lmsapp.models import PaidCourse , CourseContent

def delete_paid_course(request, course_id):
    if request.method == 'POST':
        course = get_object_or_404(PaidCourse, id=course_id)

        # Atomic transaction to ensure consistency
        with transaction.atomic():
            course.contents.all().delete()  # Delete all related CourseContent records
            course.delete()  # Delete the PaidCourse record

        return redirect('paid_course')  # Redirect to the course list
    return redirect('paid_course')  # Fallback for non-POST requests


# Update Paid Course
def update_paid_course(request, course_id):
    course = get_object_or_404(PaidCourse, id=course_id)
    if request.method == 'POST':
        course.course_title = request.POST.get('course_title', course.course_title)
        course.duration = request.POST.get('duration', course.duration)
        course.description = request.POST.get('description', course.description)
        course.instructor_name = request.POST.get('instructor_name', course.instructor_name)
        course.course_level = request.POST.get('course_level', course.course_level)
        course.course_price = request.POST.get('course_price', course.course_price)

        if 'thumbnail' in request.FILES:
            course.thumbnail = request.FILES['thumbnail']

        course.save()
        return redirect('create_paid_course')  # Redirect to the paid course list page

    return render(request, 'update_paid_course.html', {'course': course})

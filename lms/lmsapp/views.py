# Create your views here.
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password



def index(request):
    # Render a simple dashboard with a header
    return render(request, 'index.html')



from django.contrib.auth.decorators import login_required


from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required

def student_dashboard(request):
    return render(request, 'student_dashboard.html')


def admin_dashboard(request):
    admin_email = request.session.get('admin_email', 'Admin Email')
    courses = FreeCourse.objects.all()
    return render(request, 'admin_dashboard.html', {'admin_email': admin_email, 'courses': courses})


def signup(request):
    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        # Validation
        if not email or not password or not confirm_password or not mobile:
            messages.error(request, 'All fields are required.')
            return render(request, 'lmsapp/signup.html')

        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'lmsapp/signup.html')

        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already registered.')
            return render(request, 'lmsapp/signup.html')

        # Create user
        user = User.objects.create_user(
            username=email,
            email=email,
            password=make_password(password),
            first_name=first_name,
            last_name=last_name,
        )
        user.save()

        # Send email
        subject = 'New LMS Signup'
        message = f'''New user signed up:

First Name: {first_name}
Last Name: {last_name}
Email: {email}
Mobile: {mobile}
'''
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, ['lmsprofitmaxacademy@gmail.com'])

        messages.success(request, 'Signup successful. Please login.')
        return redirect('login')

    return render(request, 'lmsapp/signup.html')





import re
from django.core.exceptions import ValidationError
from django.core.mail import send_mail, BadHeaderError
from django.contrib import messages
from django.shortcuts import render, redirect
from twilio.rest import Client
from lmsapp.models import OTP, CustomUser  # Assuming CustomUser model is in the same app

# Validate phone number in E.164 format
# def validate_phone_number(phone):
#     pattern = re.compile(r'^\+\d{10,15}$')  # E.164 format
#     if not pattern.match(phone):
#         raise ValidationError("Invalid phone number format. Use E.164 format (e.g., +1234567890).")
#     return phone

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
        mobile = request.POST.get('mobile')

        first_name = request.POST.get('first_name')  # Get the first name
        last_name = request.POST.get('last_name')  # Get the last name
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        # Check if user already exists by email
        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, f"User with email ({email}) already exists.")
            return redirect('signup')

        # Check if passwords match
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect('signup')

        # Create user
        user = CustomUser.objects.create_user(
            email=email,
            mobile=mobile,
            first_name=first_name,  # Pass first name
            last_name=last_name,    # Pass last name
            password=password
        )
        user.is_active = False  # The user will need to verify their email before they can log in
        user.save()

        otp_code = OTP.generate_otp()
        OTP.objects.create(user=user, code=otp_code)

        # Send OTP via Email
        try:
            send_otp_email(email, otp_code)
        except ValidationError as e:
            messages.error(request, str(e))
            return redirect('signup')

        messages.success(request, "Signup successful. Please verify your email.")
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

        otp = OTP.objects.filter(user=user, code=entered_otp).first()
        otp_attempts = request.session.get('otp_attempts', 0)

        if otp and otp.created_at >= now() - timedelta(minutes=10):
            user.is_active = True
            user.is_verified = True
            user.save()
            OTP.objects.filter(user=user).delete()

            # ✅ Send welcome email to the user
            try:
                send_mail(
                    'Welcome to Our Institute!',
                    f'Hi {user.first_name},\n\nWelcome to our institute! We are excited to have you with us.',
                    'welcome@myapp.com',
                    [user.email],
                )
            except BadHeaderError:
                messages.error(request, "Invalid header found while sending welcome email.")
            except Exception as e:
                messages.error(request, f"Error sending welcome email: {e}")

            # ✅ Notify Admin via email
            try:
                send_mail(
                    subject='New User Signup Notification',
                    message=(
                        f'New user signed up:\n\n'
                        f'First Name: {user.first_name}\n'
                        f'Last Name: {user.last_name}\n'
                        f'Email: {user.email}\n'
                        f'Mobile: {user.mobile}\n'
                    ),
                    from_email='welcome@myapp.com',
                    recipient_list=['lmsprofitmaxacademy@gmail.com'],
                )
            except Exception as e:
                messages.error(request, f"Failed to notify admin: {e}")

            # ✅ Clear OTP attempts
            request.session.pop('otp_attempts', None)

            # ✅ Add success message for popup
            messages.success(request, "Signup successful. Please login.")
            return render(request, 'verify_otp.html', {'show_popup': True})

        else:
            otp_attempts += 1
            request.session['otp_attempts'] = otp_attempts
            messages.error(request, "Invalid OTP. Please try again.")

            if otp_attempts >= 2:
                OTP.objects.filter(user=user).delete()
                request.session.pop('otp_attempts', None)
                return redirect('signup')

    return render(request, 'verify_otp.html')


from django.contrib.auth import login as auth_login, logout as auth_logout
from django.contrib.sessions.models import Session
from django.utils.timezone import now
from django.shortcuts import redirect, render
from django.contrib import messages
from .models import CustomUser
import hashlib


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
                
                # Check if the user has exceeded the session limit
                if not manage_user_sessions(user, request):
                    messages.error(request, "You have reached the maximum number of active sessions. Please log out from another device to log in.")
                    return render(request, 'login.html')

                # Log the user in
                auth_login(request, user)
                request.session['user_email'] = user.email
                return redirect('student_dashboard')

            else:
                messages.error(request, "Incorrect password. Please try again.")
        except CustomUser.DoesNotExist:
            messages.error(request, "User with this email does not exist. Please register.")

    return render(request, 'login.html')


def manage_user_sessions(user, request):
    """
    Ensures that a user can log in on a maximum of **2 devices/browsers**.
    If they exceed this limit, the oldest session is removed.
    """
    max_sessions = 2  # User can be logged in on 2 devices/browsers

    # Generate a unique browser/device identifier
    browser_identifier = hashlib.md5(request.META.get('HTTP_USER_AGENT', '').encode('utf-8')).hexdigest()

    # Retrieve all active sessions for this user
    user_sessions = []
    sessions = Session.objects.all()

    for session in sessions:
        session_data = session.get_decoded()
        if session_data.get('_auth_user_id') == str(user.id):
            user_sessions.append(session)

    # If user already has 2 active sessions, delete the oldest one
    if len(user_sessions) >= max_sessions:
        user_sessions.sort(key=lambda s: s.expire_date)  # Sort by expiry date
        user_sessions[0].delete()  # Delete the oldest session

    return True  # Allow login



from django.contrib.auth import logout as auth_logout
from django.contrib.sessions.models import Session
from django.shortcuts import redirect

def logout_view(request):
    if request.user.is_authenticated:
        # Delete the user's session from the database
        Session.objects.filter(session_key=request.session.session_key).delete()

    # Clear the session
    auth_logout(request)
    request.session.flush()  # Remove all session data

    return redirect('login')  # Redirect to login page




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





from .models import FreeCourse,CourseChapter

def create_free_course(request):
    if request.method == "POST":
        title = request.POST.get("title")
        description = request.POST.get("description")
        thumbnail = request.FILES.get("thumbnail")
        youtube_links = request.POST.getlist("youtube_links[]")

        # Create the course
        course = FreeCourse.objects.create(title=title, description=description, thumbnail=thumbnail)

        # Save each YouTube link as a chapter
        for index, link in enumerate(youtube_links, start=1):
            CourseChapter.objects.create(course=course, title=f"Chapter {index}", youtube_link=link)

        return redirect("create_free_course")

    return render(request, "create_free_course.html")



from django.shortcuts import render, redirect
from .models import FreeCourse, CourseChapter

def create_free_course(request):
    if request.method == "POST":
        title = request.POST.get("title")
        description = request.POST.get("description")
        thumbnail = request.FILES.get("thumbnail")
        youtube_links = request.POST.getlist("youtube_links[]")  # ✅ Correct name

        if title and description and thumbnail:
            course = FreeCourse.objects.create(
                title=title,
                description=description,
                thumbnail=thumbnail
            )

            for link in youtube_links:
                if link.strip():
                    CourseChapter.objects.create(
                        course=course,
                        title=f"Chapter {course.chapters.count() + 1}",
                        youtube_link=link
                    )

            return redirect("create_free_course")

    courses = FreeCourse.objects.prefetch_related("chapters").all()
    return render(request, "create_free_course.html", {"courses": courses})


def update_free_course(request, course_id):
    course = FreeCourse.objects.get(id=course_id)

    if request.method == 'POST':
        course.title = request.POST.get('title')
        course.description = request.POST.get('description')
        # Thumbnail logic if any
        course.save()

        # Example: Update chapter links
        for chapter in course.chapters.all():
            print(chapter.youtube_link)  # ✅ Works if you need it

        return redirect('create_free_course')


def free_courses(request):
    courses = FreeCourse.objects.prefetch_related("chapters").all()
    
    # Debugging Output
    print("Courses:", courses)
    for course in courses:
        print(f"Course: {course.title}, Thumbnail: {course.thumbnail}, Chapters: {course.chapters.all()}")

    return render(request, "free_course.html", {"courses": courses})



def paid_course(request):
    # Render a simple dashboard with a header
    return render(request, 'paid_course.html')

from django.shortcuts import render
from .models import PaidCourse, CourseProgress

from django.shortcuts import render
from .models import PaidCourse, CourseProgress
from django.shortcuts import render
from .models import PaidCourse, CourseProgress

def view_paid_course(request):
    courses = PaidCourse.objects.all()

    for course in courses:
        # Get total contents of the course
        total_contents = course.contents.count()
        
        # Get the number of completed contents for the current user
        completed_contents = CourseProgress.objects.filter(user=request.user, course=course, completed=True).count()

        # Calculate progress percentage
        progress_percentage = (completed_contents / total_contents) * 100 if total_contents > 0 else 0

        # Store progress percentage in the course object
        course.progress_percentage = round(progress_percentage, 2)

    return render(request, 'view_paid_course.html', {'courses': courses})




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
from django.urls import reverse

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
        'contents': contents,  # This must be passed correctly!
    })



from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponse, JsonResponse
from .models import FreeCourse

# Delete Free Course
def delete_free_course(request, course_id):
    if request.method == 'POST':
        course = get_object_or_404(FreeCourse, id=course_id)
        course.delete()
        return redirect('create_free_course')
    

# Update Free Course
from .models import CourseChapter  # Import your chapter model

from django.shortcuts import get_object_or_404, redirect, render
from .models import FreeCourse, CourseChapter

def update_free_course(request, course_id):
    course = get_object_or_404(FreeCourse, id=course_id)

    if request.method == 'POST':
        course.title = request.POST.get('title', course.title)
        course.description = request.POST.get('description', course.description)

        if 'thumbnail' in request.FILES:
            course.thumbnail = request.FILES['thumbnail']
        course.save()

        # Get chapter fields
        chapter_ids = request.POST.getlist('chapter_id')
        chapter_titles = request.POST.getlist('chapter_title')
        youtube_links = request.POST.getlist('youtube_link')



        

        for i in range(len(chapter_ids)):
            cid = chapter_ids[i]
            title = chapter_titles[i]
            link = youtube_links[i]

            if cid == "new":
                if title and link:
                    CourseChapter.objects.create(course=course, title=title, youtube_link=link)
            else:
                try:
                    chapter = CourseChapter.objects.get(id=cid, course=course)
                    chapter.title = title
                    chapter.youtube_link = link
                    chapter.save()
                except CourseChapter.DoesNotExist:
                    continue

        return redirect('create_free_course')

    chapters = course.chapters.all()
    return render(request, 'update_free_course.html', {'course': course, 'chapters': chapters})


    




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

from django.shortcuts import render, redirect
from .models import SubAdmin
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.hashers import make_password

def is_admin(user):
    return user.is_superuser

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from .models import SubAdmin
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from .models import SubAdmin

def manage_subadmins(request):
    if request.method == 'POST':
        # Extract form data
        email = request.POST.get('email')
        password = request.POST.get('password')
        phone_number = request.POST.get('phone_number')

        # Ensure no duplicate emails for SubAdmin
        if SubAdmin.objects.filter(email=email).exists():
            messages.error(request, "A SubAdmin with this email already exists.")
        else:
            # Save new SubAdmin
            subadmin = SubAdmin.objects.create(
                email=email,
                password=make_password(password),  # Hash the password
                plain_password=password,  # Store plain-text password
                phone_number=phone_number,
                is_subadmin=True  # Ensure subadmin role
            )
            messages.success(request, "SubAdmin created successfully!")

        return redirect('manage_subadmins')

    # Retrieve all SubAdmins
    subadmins = SubAdmin.objects.filter(is_subadmin=True)
    return render(request, 'manage_subadmin.html', {'subadmins': subadmins})


from django.shortcuts import render
from django.contrib.auth.decorators import login_required, user_passes_test

# Function to check if user is a sub-admin
def is_subadmin(user):
    return user.is_authenticated and user.is_subadmin


def subadmin_dashboard(request):
    return render(request, 'subadmin_dashboard.html', {})


from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login
from django.contrib import messages
from .models import SubAdmin

from django.contrib.auth import authenticate, login as auth_login
from django.shortcuts import render, redirect
from django.contrib import messages

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login
from django.contrib import messages
from .models import SubAdmin

def subadmin_login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        # Authenticate as SubAdmin using email and password
        try:
            user = SubAdmin.objects.get(email=email)
            if user.check_password(password) and user.is_subadmin:
                auth_login(request, user)
                request.session['subadmin_email'] = user.email
                return redirect('admin_dashboard')  # Redirect to subadmin dashboard
            else:
                messages.error(request, "Invalid credentials or SubAdmin access denied.")
        except SubAdmin.DoesNotExist:
            messages.error(request, "SubAdmin with this email does not exist.")

    return render(request, 'subadmin_login.html')

import hashlib
import requests
from django.conf import settings
from django.shortcuts import render, redirect
from django.http import JsonResponse

def generate_hash_key(data_dict):
    """Generate hash key for Easebuzz payment"""
    hash_sequence = "|".join(str(data_dict[key]) for key in sorted(data_dict.keys()))
    hash_string = settings.EASEBUZZ_SALT + "|" + hash_sequence + "|" + settings.EASEBUZZ_SALT
    return hashlib.sha512(hash_string.encode()).hexdigest()

from .models import Payment
import uuid  # To generate unique transaction IDs

from django.contrib.auth.models import AnonymousUser

import uuid
import uuid
import hashlib
import requests
from django.shortcuts import render, redirect
from django.conf import settings
from django.contrib.auth.decorators import login_required
from .models import Payment, PaidCourse

def generate_hash_key(data):
    """Generates a hash for the Easebuzz transaction request"""
    hash_sequence = "|".join([data[key] for key in sorted(data.keys())]) + "|" + settings.EASEBUZZ_SALT
    return hashlib.sha512(hash_sequence.encode()).hexdigest()

from django.views.decorators.csrf import csrf_exempt

@login_required
def initiate_payment(request, course_id):
    try:
        course = get_object_or_404(PaidCourse, id=course_id)
    except PaidCourse.DoesNotExist:
        return JsonResponse({"error": "Course not found."})

    txnid = f"Txn{uuid.uuid4().hex[:10]}"  # Generate a unique transaction ID
    first_name = request.user.first_name.strip() if request.user.first_name else "User"

    if not hasattr(settings, "EASEBUZZ_MERCHANT_KEY") or not settings.EASEBUZZ_MERCHANT_KEY:
        return JsonResponse({"error": "Invalid merchant key. Please check your settings."})

    phone_number = getattr(request.user, 'mobile', '')
    if not phone_number:
        return JsonResponse({"error": "Phone number is required for payment."})

    payment = Payment.objects.create(
        user=request.user,
        course=course,
        transaction_id=txnid,
        amount=course.course_price,
        status="Pending"
    )

    # Construct payment data for Easebuzz
    data = {
        "key": settings.EASEBUZZ_MERCHANT_KEY,
        "txnid": txnid,
        "amount": str(course.course_price),
        "productinfo": course.course_title,
        "firstname": first_name,
        "email": request.user.email,
        "phone": phone_number,
        "surl": request.build_absolute_uri("/payment/success/"),  # Success URL
        "furl": request.build_absolute_uri("/payment/failure/"),  # Failure URL
    }

    # Generate hash (if required by Easebuzz)
    data["hash"] = generate_hash_key(data)  # Ensure you have a function to generate the hash

    return render(request, "payment_redirect.html", {"data": data, "easebuzz_url": settings.EASEBUZZ_BASE_URL,'course':course})



# views.py
from django.shortcuts import render
from .models import Payment

def payment_success(request):
    txnid = request.GET.get('txnid')  # Get transaction ID from Easebuzz
    try:
        payment = Payment.objects.get(transaction_id=txnid)
        payment.status = "Success"
        payment.save()
    except Payment.DoesNotExist:
        pass  # Handle error properly in production

    return render(request, "payment_success.html", {"txnid": txnid})

def payment_failure(request):
    txnid = request.GET.get('txnid')
    try:
        payment = Payment.objects.get(transaction_id=txnid)
        payment.status = "Failed"
        payment.save()
    except Payment.DoesNotExist:
        pass

    return render(request, "payment_failed.html", {"txnid": txnid})

from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Notification
from django.core.files.storage import default_storage

def send_notification(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        image = request.FILES.get('image')

        # Save the notification to the database
        notification = Notification(title=title, description=description)

        if image:
            notification.image = image  # Django handles file saving automatically

        notification.save()

        messages.success(request, 'Notification saved successfully!')
        return redirect('admin_dashboard')  # Change this to the correct URL name

    return render(request, 'send_notification.html')

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from .models import Notification


from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from .models import Notification


from django.shortcuts import render
from .models import Notification

from django.shortcuts import render
from .models import Notification

from django.shortcuts import render
from .models import Notification

def student_dashboard(request):
    # Fetch all notifications ordered by newest first
    notifications = Notification.objects.all().order_by('-created_at')

    return render(request, 'student_dashboard.html', {'notifications': notifications})

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from .models import PaidCourse, CourseContent, CourseProgress


from django.shortcuts import get_object_or_404, redirect
from .models import CourseProgress, CourseContent

from django.urls import reverse
from django.shortcuts import get_object_or_404, redirect
from .models import PaidCourse, CourseContent

from django.shortcuts import get_object_or_404, redirect
from django.http import HttpResponse
from lmsapp.models import PaidCourse, CourseContent, CourseProgress  # Ensure models are imported

from django.shortcuts import get_object_or_404, redirect
from django.http import JsonResponse, HttpResponse
from .models import PaidCourse, CourseContent, CourseProgress

from django.shortcuts import get_object_or_404, redirect
from django.http import JsonResponse
from .models import PaidCourse, CourseContent, CourseProgress

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse

 # Only if you can't use CSRF tokens in JS
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from .models import PaidCourse, CourseContent, CourseProgress
  # Required for AJAX POST requests without Django's default CSRF setup
@login_required
def mark_content_completed(request, course_id, content_id):
    if request.method == "POST":
        course = get_object_or_404(PaidCourse, id=course_id)
        content = get_object_or_404(CourseContent, id=content_id)

        progress, created = CourseProgress.objects.get_or_create(
            user=request.user,
            course=course,
            content=content
        )

        if not progress.completed:
            progress.completed = True
            progress.save()

        # Calculate updated progress percentage
        total_contents = course.contents.count()
        completed_contents = CourseProgress.objects.filter(user=request.user, course=course, completed=True).count()
        progress_percentage = (completed_contents / total_contents) * 100 if total_contents > 0 else 0

        return JsonResponse({
            "message": "Marked as completed",
            "completed": True,
            "progress_percentage": round(progress_percentage, 2),
            "course_id": course.id
        })

    return JsonResponse({"error": "Invalid request"}, status=400)


from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from .models import CourseProgress, PaidCourse

@login_required
def get_course_progress(request, course_id):
    course = get_object_or_404(PaidCourse, id=course_id)
    progress = CourseProgress.objects.filter(user=request.user, course=course, completed=True).count()
    total_contents = course.contents.count()
    progress_percentage = (progress / total_contents) * 100 if total_contents > 0 else 0
    
    return JsonResponse({"percentage": round(progress_percentage, 2)})



from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Ticket
from .forms import TicketForm

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import HttpResponse
from .models import Ticket

# Check if the user is an admin or sub-admin
def is_admin(user):
    return user.is_subadmin or user.is_superuser

@login_required
def raise_ticket(request):
    """Allow students to raise a ticket without using Django forms."""
    if request.method == "POST":
        subject = request.POST.get("subject")
        description = request.POST.get("description")

        if subject and description:
            Ticket.objects.create(user=request.user, subject=subject, description=description)
            return redirect("ticket_list")
        else:
            return HttpResponse("All fields are required.", status=400)

    return render(request, "raise_ticket.html")



@login_required
def ticket_list(request):
    """Students see their tickets, Admins see all tickets."""
    if request.user.is_staff or request.user.is_superuser:
        tickets = Ticket.objects.all().order_by("-created_at")  # Admins/Sub-Admins see all
    else:
        tickets = Ticket.objects.filter(user=request.user).order_by("-created_at")  # Students see only their own
    return render(request, "ticket_list.html", {"tickets": tickets})

from django.shortcuts import render

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Ticket
def ticket_to_admin(request):
    """View all tickets (accessible to everyone)."""
    tickets = Ticket.objects.all().order_by("-created_at")  # Fetch all tickets
    return render(request, "ticket_to_admin.html", {"tickets": tickets})


from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Ticket
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt  # REMOVE this in production
from django.contrib.auth.decorators import login_required
from .models import Ticket



def close_ticket(request, ticket_id):
    """ Close the ticket and update the database. """
    ticket = get_object_or_404(Ticket, id=ticket_id)
    
    if request.method == "POST":
        ticket.status = "closed"
        ticket.save()
        messages.success(request, "Ticket closed successfully.")
    
    return redirect("ticket_to_admin")  # Change to your actual view name

from django.contrib.auth import get_user_model

User = get_user_model()


def user_list(request):
    users = CustomUser.objects.all()  # Only superadmins see users
    return render(request, 'admin_user_list.html', {'users': users})
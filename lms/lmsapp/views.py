# Create your views here.
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password



from django.contrib.auth.decorators import login_required, user_passes_test

# Function to check if user is a sub-admin
def is_subadmin(user):
    return user.is_authenticated and user.is_subadmin

# if you wnat both subadmin and admin to acces same functionality 
def is_admin_or_subadmin(user):
    return user.is_authenticated and (user.is_superuser or user.is_subadmin)    


def is_admin(user):
    return user.is_superuser




def index(request):
    # Render a simple dashboard with a header
    return render(request, 'index.html')



from django.contrib.auth.decorators import login_required


from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required

@login_required
def student_dashboard(request):
    return render(request, 'student_dashboard.html')


from django.db.models import Sum, Count
from .models import Invoice, NewPayment
from django.db.models import F


from django.db.models import Count, F, Sum
from django.shortcuts import render

from django.db.models import Q

@login_required
@user_passes_test(is_admin_or_subadmin)
def admin_dashboard(request):
    # Get filter parameters
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    specific_date = request.GET.get('specific_date')
    course_id = request.GET.get('course')
    
    # Base querysets
    invoice_qs = Invoice.objects.all()
    payment_qs = NewPayment.objects.all()
    
    # Apply date filters
    if specific_date:
        # Filter for a specific single date
        invoice_qs = invoice_qs.filter(date_created__date=specific_date)
        payment_qs = payment_qs.filter(created_at__date=specific_date)
    else:
        # Apply date range filters if no specific date
        if date_from:
            invoice_qs = invoice_qs.filter(date_created__gte=date_from)
            payment_qs = payment_qs.filter(created_at__gte=date_from)
        if date_to:
            invoice_qs = invoice_qs.filter(date_created__lte=date_to)
            payment_qs = payment_qs.filter(created_at__lte=date_to)
    
    # Apply course filter if selected
    if course_id:
        invoice_qs = invoice_qs.filter(course_id=course_id)
        payment_qs = payment_qs.filter(course_id=course_id)
    
    # Calculate totals with filters applied
    active_total = invoice_qs.filter(is_canceled=False).aggregate(Sum('paid_amount'))['paid_amount__sum'] or 0
    canceled_total = invoice_qs.filter(is_canceled=True).aggregate(Sum('paid_amount'))['paid_amount__sum'] or 0
    total_amount = active_total + canceled_total
    
    unpaid_invoice_amount = payment_qs.filter(invoice_created=False).aggregate(
        total=Sum('amount')
    )['total'] or 0

    # Get top courses with filters applied
    top_courses = (
        payment_qs
        .values('course_id')
        .annotate(
            course_title=F('course__course_title'),
            course_code=F('course__course_code'),
            purchase_count=Count('id')
        )
        .order_by('-purchase_count')[:5]
    )

    course_labels = [f"{item['course_title']} ({item['course_code']})" for item in top_courses]
    course_data = [item['purchase_count'] for item in top_courses]
    
    # Get all courses for filter dropdown
    all_courses = PaidCourse.objects.all()

    return render(request, 'admin_dashboard.html', {
        'active_total': active_total,
        'canceled_total': canceled_total,
        'total_amount': total_amount,
        'unpaid_invoice_amount': unpaid_invoice_amount,
        'course_labels': course_labels,
        'course_data': course_data,
        'all_courses': all_courses,
        'filter_params': request.GET,
    })








import re




from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.conf import settings
import re
from .forms import CaptchaForm

from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.conf import settings
import re
from .forms import CaptchaForm  # Make sure this import is correct

def signup(request):
    if request.method == 'POST':
        form = CaptchaForm(request.POST)
        
        if form.is_valid():  # This validates the CAPTCHA first
            # Get form data
            first_name = request.POST.get('first_name')
            last_name = request.POST.get('last_name')
            email = request.POST.get('email')
            mobile = request.POST.get('mobile')
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')

            # Check for required fields
            if not all([first_name, last_name, email, mobile, password, confirm_password]):
                messages.error(request, 'All fields are required.')
                return render(request, 'lmsapp/signup.html', {'form': form})

            # Validate mobile number
            if not re.fullmatch(r'^[6-9]\d{9}$', mobile):
                messages.error(request, 'Enter a valid 10-digit mobile number starting with 6-9.')
                return render(request, 'lmsapp/signup.html', {'form': form})

            # Check password match
            if password != confirm_password:
                messages.error(request, 'Passwords do not match.')
                return render(request, 'lmsapp/signup.html', {'form': form})

            # Check for existing user
            if User.objects.filter(email=email).exists():
                messages.error(request, 'Email already registered.')
                return render(request, 'lmsapp/signup.html', {'form': form})

            # Create user
            user = User.objects.create_user(
                username=email,
                email=email,
                password=make_password(password),
                first_name=first_name,
                last_name=last_name,
            )
            user.save()

            # Email notification
            subject = 'New LMS Signup'
            message = f'''New user signed up:

First Name: {first_name}
Last Name: {last_name}
Email: {email}
Mobile: {mobile}
'''
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, ['lmstechmax@gmail.com'])

            messages.success(request, 'Signup successful. Please login.')
            return redirect('login')
        else:
            messages.error(request, 'Invalid CAPTCHA. Please try again.')
    else:
        form = CaptchaForm()
    
    return render(request, 'lmsapp/signup.html', {'form': form})




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
            f'Your OTP for signup is: {otp_code}\n\n'
            f'Your OTP is: {otp_code} 🧾\n'
            f'Use this pin to unlock the door to your stock market training journey! 🚪📈\n'
            f'It’s valid for 10 minutes.\n'
            f'Never share this code with anyone.\n\n'
            f'Let the learning begin! 🚀',
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
            body=(
                f"Your OTP for signup is: {otp_code}\n\n"
                f"Your OTP is: {otp_code} 🧾\n"
                f"Use this pin to unlock the door to your stock market training journey! 🚪📈\n"
                f"It’s valid for 10 minutes.\n"
                f"Never share this code with anyone.\n\n"
                f"Let the learning begin! 🚀"
            ),
            from_=os.getenv("TWILIO_PHONE_NUMBER"),
            to=mobile
        )
    except Exception as e:
        raise ValidationError(f"Error sending SMS: {e}")

    

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




# 2nd signup

from .forms import SignupForm


# if you dont enter otp then alos the data of user will be saved but he will be not verified user 

# def signup(request):
#     if request.method == 'POST':
#         form = SignupForm(request.POST)
#         if form.is_valid():
#             # Extract cleaned form data
#             email = form.cleaned_data['email']
#             mobile = form.cleaned_data['mobile']
#             first_name = form.cleaned_data['first_name']
#             last_name = form.cleaned_data['last_name']
#             password = form.cleaned_data['password']
#             confirm_password = form.cleaned_data['confirm_password']

#             # (You can keep your validations here or customize clean methods)

#             if password != confirm_password:
#                 messages.error(request, "Passwords do not match.")
#                 return redirect('signup')

#             if CustomUser.objects.filter(email=email).exists():
#                 messages.error(request, f"User with email ({email}) already exists.")
#                 return redirect('signup')

#             if CustomUser.objects.filter(mobile=mobile).exists():
#                 messages.error(request, f"Mobile number ({mobile}) already registered.")
#                 return redirect('signup')

#             user = CustomUser.objects.create_user(
#                 email=email,
#                 mobile=mobile,
#                 first_name=first_name,
#                 last_name=last_name,
#                 password=password
#             )
#             user.is_active = False
#             user.save()

#             otp_code = OTP.generate_otp()
#             OTP.objects.create(user=user, code=otp_code)

#             send_otp_email(email, otp_code)

#             messages.success(request, "Signup successful. Please verify your email.")
#             request.session['user_id'] = user.id
#             return redirect('verify_otp')

#         else:
#             messages.error(request, "Invalid form. Please check errors below.")
#     else:
#         form = SignupForm()

#     return render(request, 'signup.html', {'form': form})


def signup(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            mobile = form.cleaned_data['mobile']
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            password = form.cleaned_data['password']
            confirm_password = form.cleaned_data['confirm_password']

            if password != confirm_password:
                messages.error(request, "Passwords do not match.")
                return redirect('signup')

            if CustomUser.objects.filter(email=email).exists():
                messages.error(request, f"User with email ({email}) already exists.")
                return redirect('signup')

            if CustomUser.objects.filter(mobile=mobile).exists():
                messages.error(request, f"Mobile number ({mobile}) already registered.")
                return redirect('signup')

            # Temporarily store user data in session
            request.session['signup_data'] = {
                'email': email,
                'mobile': mobile,
                'first_name': first_name,
                'last_name': last_name,
                'password': password,
            }

            # Generate and send OTP
            otp_code = OTP.generate_otp()
            request.session['otp_code'] = otp_code
            send_otp_email(email, otp_code)

            messages.success(request, "Signup successful. Please verify your email.")
            return redirect('verify_otp')
        else:
            messages.error(request, "Invalid form. Please check errors below.")
    else:
        form = SignupForm()

    return render(request, 'signup.html', {'form': form})




from django.core.mail import send_mail, BadHeaderError
from django.utils.timezone import now, timedelta

from django.core.mail import send_mail, BadHeaderError
from django.utils.timezone import now
from datetime import timedelta
from django.contrib import messages
from django.shortcuts import render, redirect
from .models import CustomUser, OTP



# if you dont enter otp then alos the data of user will be saved but he will be not verified user 

# def verify_otp(request):
#     if request.method == 'POST':
#         user_id = request.session.get('user_id')
#         user = CustomUser.objects.get(id=user_id)
#         entered_otp = request.POST['otp']

#         otp = OTP.objects.filter(user=user, code=entered_otp).first()
#         otp_attempts = request.session.get('otp_attempts', 0)

#         if otp and otp.created_at >= now() - timedelta(minutes=10):
#             user.is_active = True
#             user.is_verified = True
#             user.save()
#             OTP.objects.filter(user=user).delete()

#             # ✅ Send personalized welcome email to the user
#             try:
#                 welcome_message = (
#                     f"✅ Sign-Up Successful! Welcome Aboard, {user.first_name}! 🎉\n\n"
#                     f"Your journey to mastering the stock market starts NOW!\n"
#                     f"You’ve just unlocked powerful courses designed to turn knowledge into confidence and action. 📈🔥\n\n"
#                     f"Stay focused. Stay curious. Stay profitable.\n"
#                     f"Let’s dive in and make every trade count!\n\n"
#                     f"“The market rewards the prepared mind.” – Start strong, finish stronger! 💪\n\n"
#                     f"📞 Need Help? If you have any queries, feel free to contact us at 7722082020.\n"
#                     f"We're always happy to serve you! 😊"
#                 )

#                 send_mail(
#                     subject='Welcome to ProfitMax Academy! 🚀',
#                     message=welcome_message,
#                     from_email='welcome@myapp.com',
#                     recipient_list=[user.email],
#                 )
#             except BadHeaderError:
#                 messages.error(request, "Invalid header found while sending welcome email.")
#             except Exception as e:
#                 messages.error(request, f"Error sending welcome email: {e}")

#             # ✅ Notify Admin via email
#             try:
#                 send_mail(
#                     subject='New User Signup Notification',
#                     message=(
#                         f'New user signed up:\n\n'
#                         f'First Name: {user.first_name}\n'
#                         f'Last Name: {user.last_name}\n'
#                         f'Email: {user.email}\n'
#                         f'Mobile: {user.mobile}\n'
#                     ),
#                     from_email='welcome@myapp.com',
#                     recipient_list=['lmsprofitmaxacademy@gmail.com'],
#                 )
#             except Exception as e:
#                 messages.error(request, f"Failed to notify admin: {e}")

#             # ✅ Clear OTP attempts
#             request.session.pop('otp_attempts', None)

#             # ✅ Add success message for popup
#             messages.success(request, "Signup successful. Please login.")
#             return render(request, 'verify_otp.html', {'show_popup': True})

#         else:
#             otp_attempts += 1
#             request.session['otp_attempts'] = otp_attempts
#             messages.error(request, "Invalid OTP. Please try again.")

#             if otp_attempts >= 2:
#                 OTP.objects.filter(user=user).delete()
#                 request.session.pop('otp_attempts', None)
#                 return redirect('signup')

#     return render(request, 'verify_otp.html')


def verify_otp(request):
    if request.method == 'POST':
        entered_otp = request.POST['otp']
        otp_code = request.session.get('otp_code')
        signup_data = request.session.get('signup_data')
        otp_attempts = request.session.get('otp_attempts', 0)

        if not signup_data:
            messages.error(request, "Session expired. Please sign up again.")
            return redirect('signup')

        if entered_otp == otp_code:
            # Create the user now
            user = CustomUser.objects.create_user(
                email=signup_data['email'],
                mobile=signup_data['mobile'],
                first_name=signup_data['first_name'],
                last_name=signup_data['last_name'],
                password=signup_data['password']
            )
            user.is_active = True
            user.is_verified = True
            user.save()

            # Send welcome email
            try:
                welcome_message = (
                    f"✅ Sign-Up Successful! Welcome Aboard, {user.first_name}! 🎉\n\n"
                    f"Your journey to mastering the stock market starts NOW!..."
                )
                send_mail(
                    subject='Welcome to ProfitMax Academy! 🚀',
                    message=welcome_message,
                    from_email='welcome@myapp.com',
                    recipient_list=[user.email],
                )
            except Exception as e:
                messages.error(request, f"Email error: {e}")

            # Notify admin
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

            # Clear session
            request.session.pop('signup_data', None)
            request.session.pop('otp_code', None)
            request.session.pop('otp_attempts', None)

            messages.success(request, "Signup successful. Please login.")
            return render(request, 'verify_otp.html', {'show_popup': True})
        else:
            otp_attempts += 1
            request.session['otp_attempts'] = otp_attempts
            messages.error(request, "Invalid OTP. Please try again.")

            if otp_attempts >= 2:
                request.session.flush()  # Clear all signup session data
                return redirect('signup')

    return render(request, 'verify_otp.html')




from django.contrib.auth import login as auth_login, logout as auth_logout
from django.contrib.sessions.models import Session
from django.utils.timezone import now
from django.shortcuts import redirect, render
from django.contrib import messages
from .models import CustomUser
import hashlib


from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login as auth_login
from .models import CustomUser
from .forms import LoginForm


# def login(request):
#     form = LoginForm(request.POST or None)
    
#     if request.method == 'POST':
#         if form.is_valid():
#             email = form.cleaned_data['email']
#             password = form.cleaned_data['password']

#             request.session.pop('admin_email', None)
#             request.session.pop('user_email', None)

#             if email == 'admin@gmail.com' and password == 'admin':
#                 request.session['admin_email'] = email
#                 return redirect('admin_dashboard')

#             try:
#                 user = CustomUser.objects.get(email=email)
#                 if user.check_password(password):
#                     # if not manage_user_sessions(user, request):
#                     #     messages.error(request, "Maximum sessions reached.")
#                     #     return render(request, 'login.html', {'form': form})

#                     auth_login(request, user)
#                     request.session['user_email'] = user.email
#                     return redirect('student_dashboard')
#                 else:
#                     messages.error(request, "Incorrect password.")
#             except CustomUser.DoesNotExist:
#                 messages.error(request, "User does not exist.")
#         else:
#             messages.error(request, "Invalid captcha.")
    
#     return render(request, 'login.html', {'form': form})



import re
from django.contrib.auth import login as auth_login
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import CustomUser
from .forms import LoginForm

from django.contrib.auth import authenticate, login as auth_login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User  # or CustomUser if you're using it
import re

def login(request):
    form = LoginForm(request.POST or None)
    
    if request.method == 'POST':
        if form.is_valid():
            identifier = form.cleaned_data['identifier']
            password = form.cleaned_data['password']

            user = None
            try:
                if re.match(r"[^@]+@[^@]+\.[^@]+", identifier):
                    user = CustomUser.objects.get(email=identifier)
                else:
                    user = CustomUser.objects.get(mobile=identifier)
            except CustomUser.DoesNotExist:
                messages.error(request, "User does not exist.")
                return render(request, 'login.html', {'form': form})

            user = authenticate(request, username=user.username, password=password)
            if user:
                auth_login(request, user)
                if user.is_superuser:
                    return redirect('admin_dashboard')
                else:
                    return redirect('student_dashboard')
            else:
                messages.error(request, "Incorrect password.")
        else:
            messages.error(request, "Invalid captcha.")
    
    return render(request, 'login.html', {'form': form})








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





# from .models import FreeCourse,CourseChapter

# def create_free_course(request):
#     if request.method == "POST":
#         title = request.POST.get("title")
#         description = request.POST.get("description")
#         thumbnail = request.FILES.get("thumbnail")
#         chapter_titles = request.POST.getlist("chapter_titles[]")  # Get chapter titles
#         youtube_links = request.POST.getlist("youtube_links[]")   # Get YouTube links

#         # Create the course
#         course = FreeCourse.objects.create(
#             title=title, 
#             description=description, 
#             thumbnail=thumbnail
#         )

#         # Save each chapter with its title and YouTube link
#         for title, link in zip(chapter_titles, youtube_links):
#             CourseChapter.objects.create(
#                 course=course, 
#                 title=title,  # Use the actual title from form
#                 youtube_link=link
#             )

#         return redirect("create_free_course")


from django.shortcuts import render, redirect
from .models import FreeCourse, CourseChapter

from .models import FreeCourse, CourseChapter, Category

def create_free_course(request):
    categories = Category.objects.all()

    if request.method == "POST":
        title = request.POST.get("title")
        description = request.POST.get("description")
        thumbnail = request.FILES.get("thumbnail")
        category_id = request.POST.get("category_id")
        chapter_titles = request.POST.getlist("chapter_titles[]")
        youtube_links = request.POST.getlist("youtube_links[]")

        if title and description and thumbnail:
            category = Category.objects.filter(id=category_id).first()
            course = FreeCourse.objects.create(
                title=title,
                description=description,
                thumbnail=thumbnail,
                category=category
            )

            for i in range(len(chapter_titles)):
                if youtube_links[i].strip():
                    CourseChapter.objects.create(
                        course=course,
                        title=chapter_titles[i],
                        youtube_link=youtube_links[i]
                    )

            return redirect("create_free_course")

    courses = FreeCourse.objects.prefetch_related("chapters").all()
    return render(request, "create_free_course.html", {"courses": courses, "categories": categories})


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


from django.shortcuts import get_object_or_404

def free_course_detail(request, course_id):
    course = get_object_or_404(FreeCourse.objects.prefetch_related("chapters"), id=course_id)
    return render(request, "free_course_detail.html", {"course": course})


def paid_course(request):
    # Render a simple dashboard with a header
    return render(request, 'paid_course.html')

from django.shortcuts import render
from .models import PaidCourse, CourseProgress

from django.shortcuts import render
from .models import PaidCourse, CourseProgress
from django.shortcuts import render
from .models import PaidCourse, CourseProgress

@user_passes_test(is_admin_or_subadmin)
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



from datetime import datetime

def generate_unique_course_code():
    

    while True:
        unique_number = random.randint(1000, 9999)  # Or use UUID if needed
        code = f"PMAX-{unique_number}"
        if not PaidCourse.objects.filter(course_code=code).exists():
            return code




from django.shortcuts import render, redirect
from .models import PaidCourse
from django.core.files.storage import FileSystemStorage

@user_passes_test(is_admin_or_subadmin)
def create_paid_course(request):
    if request.method == 'POST':
        course_title = request.POST.get('course_title')
        duration = request.POST.get('duration')
        description = request.POST.get('description')
        about = request.POST.get('about')  # ✅ new
        benefits = request.POST.get('benefits')  # ✅ new
        instructor_name = request.POST.get('instructor_name')
        course_level = request.POST.get('course_level')
        original_price = float(request.POST.get('original_price'))
        course_price = float(request.POST.get('course_price'))
        discount_amount = original_price - course_price
        
        thumbnail = request.FILES.get('thumbnail')

        course_name = request.POST.get('course_name')

        course_code = generate_unique_course_code()

        category_id = request.POST.get('category')

        category = Category.objects.get(id=category_id) if category_id else None



        # Save thumbnail file if provided
        if thumbnail:
            fs = FileSystemStorage()
            filename = fs.save(thumbnail.name, thumbnail)
            thumbnail_url = fs.url(filename)
        else:
            thumbnail_url = None

        # Save to database
        PaidCourse.objects.create(
            course_title=course_title,
            duration=duration,
            description=description,
            about=about,  
            benefits=benefits,  
            instructor_name=instructor_name,
            course_level=course_level,
            course_price=course_price,
            original_price=original_price,
            discount_amount=discount_amount,

            
            thumbnail=thumbnail,

            course_name=course_name,
            course_code=course_code,

            category=category
            

            

        )
        return redirect('create_paid_course')
    categories = Category.objects.all()
    courses = PaidCourse.objects.all()
    return render(request, 'paid_course.html', {'courses': courses, 'categories': categories})






from django.shortcuts import render, get_object_or_404, redirect
from .models import PaidCourse, CourseContent

@user_passes_test(is_admin_or_subadmin)
def upload_content(request, course_id):
    course = get_object_or_404(PaidCourse, id=course_id)

    if request.method == 'POST':
        titles = request.POST.getlist('title[]')
        subtitles = request.POST.getlist('subtitle[]')
        resource_files = request.FILES.getlist('resource_file[]')

        if not (titles and subtitles and resource_files):
            return render(request, 'upload_content.html', {'course': course, 'error': 'Missing inputs.'})

        # Logic: Assume N subtitle+file for each title, grouped sequentially
        # JS should store counts per title so we can split subtitles/files accordingly.
        # You can pass `subtitle_counts` from JS as a hidden input.

        subtitle_counts = request.POST.getlist('subtitle_count[]')  # Hidden input from JS
        subtitle_counts = [int(x) for x in subtitle_counts]

        sub_idx = 0
        for title, count in zip(titles, subtitle_counts):
            for _ in range(count):
                if sub_idx >= len(subtitles) or sub_idx >= len(resource_files):
                    break
                CourseContent.objects.create(
                    course=course,
                    title=title,
                    subtitle=subtitles[sub_idx],
                    resource_file=resource_files[sub_idx]
                )
                sub_idx += 1

        return redirect('view_paid_course')

    return render(request, 'upload_content.html', {'course': course})








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

        # Update or create chapters
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

        # Delete chapters if marked
        delete_ids = request.POST.get('delete_chapter_ids', '')
        if delete_ids:
            ids_to_delete = [int(id) for id in delete_ids.split(',') if id.isdigit()]
            CourseChapter.objects.filter(id__in=ids_to_delete, course=course).delete()

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

        return redirect('view_paid_course')  # Redirect to the course list
    return redirect('view_paid_course')  # Fallback for non-POST requests


# Update Paid Course
def update_paid_course(request, course_id):
    course = get_object_or_404(PaidCourse, id=course_id)

    if request.method == 'POST':
        course.course_title = request.POST.get('course_title', course.course_title)
        course.duration = request.POST.get('duration', course.duration)
        course.description = request.POST.get('description', course.description)
        course.about = request.POST.get('about', course.about)
        course.benefits = request.POST.get('benefits', course.benefits)
        course.instructor_name = request.POST.get('instructor_name', course.instructor_name)
        course.course_level = request.POST.get('course_level', course.course_level)
        course.original_price = float(request.POST.get('original_price', course.original_price))
        course.course_price = float(request.POST.get('course_price', course.course_price))
        course.discount_amount = course.original_price - course.course_price

        if 'thumbnail' in request.FILES:
            course.thumbnail = request.FILES['thumbnail']

        course.save()
        return redirect('view_paid_course')

    return render(request, 'update_paid_course.html', {'course': course})


from django.shortcuts import render, redirect
# from .models import SubAdmin
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.hashers import make_password




def is_admin(user):
    return user.is_superuser

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.hashers import make_password
# from .models import SubAdmin
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from django.db import IntegrityError

# from .models import SubAdmin

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password

User = get_user_model()

def manage_subadmins(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        phone_number = request.POST.get('phone_number') or None

        if User.objects.filter(email=email).exists():
            messages.error(request, "A SubAdmin with this email already exists.")
        else:
            try:
                user = User.objects.create_user(
                    email=email,
                    password=password,
                    plain_password=password,
                    phone_number=phone_number,
                    is_subadmin=True
                )
                messages.success(request, "SubAdmin created successfully!")
            except IntegrityError as e:
                messages.error(request, f"Error creating SubAdmin: {e}")

        return redirect('manage_subadmins')

    subadmins = User.objects.filter(is_subadmin=True)
    return render(request, 'manage_subadmin.html', {'subadmins': subadmins})



from django.shortcuts import render
from django.contrib.auth.decorators import login_required, user_passes_test

# Function to check if user is a sub-admin
def is_subadmin(user):
    return user.is_authenticated and user.is_subadmin

# if you wnat both subadmin and admin to acces same functionality 
def is_admin_or_subadmin(user):
    return user.is_authenticated and (user.is_superuser or user.is_subadmin)    


def subadmin_dashboard(request):
    is_subadmin = getattr(request.user, 'is_subadmin', False)
    return render(request, 'subadmin_dashboard.html', {
        'is_subadmin': is_subadmin
    })



from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login
from django.contrib import messages
# from .models import SubAdmin

from django.contrib.auth import authenticate, login as auth_login
from django.shortcuts import render, redirect
from django.contrib import messages

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login
from django.contrib import messages
# from .models import SubAdmin

from django.contrib.auth import authenticate, login as auth_login
from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model

User = get_user_model()

def subadmin_login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        user = authenticate(request, email=email, password=password)

        if user and user.is_subadmin:
            auth_login(request, user)
            request.session['subadmin_email'] = user.email
            return redirect('subadmin_dashboard')
        else:
            messages.error(request, "Invalid credentials or not a SubAdmin.")
            return redirect('subadmin_login')

    return render(request, 'subadmin_login.html')


import hashlib
import requests
from django.conf import settings
from django.shortcuts import render, redirect
from django.http import JsonResponse

# def generate_hash_key(data_dict):
#     """Generate hash key for Easebuzz payment"""
#     hash_sequence = "|".join(str(data_dict[key]) for key in sorted(data_dict.keys()))
#     hash_string = settings.EASEBUZZ_SALT + "|" + hash_sequence + "|" + settings.EASEBUZZ_SALT
#     return hashlib.sha512(hash_string.encode()).hexdigest()

# from .models import Payment
# import uuid  # To generate unique transaction IDs

from django.contrib.auth.models import AnonymousUser

# import uuid
# import uuid
# import hashlib
import requests
from django.shortcuts import render, redirect
from django.conf import settings
from django.contrib.auth.decorators import login_required
# from .models import Payment, PaidCourse

# def generate_hash_key(data):
#     """Generates a hash for the Easebuzz transaction request"""
#     hash_sequence = "|".join([data[key] for key in sorted(data.keys())]) + "|" + settings.EASEBUZZ_SALT
#     return hashlib.sha512(hash_sequence.encode()).hexdigest()

# from django.views.decorators.csrf import csrf_exempt

# @login_required
# def initiate_payment(request, course_id):
#     try:
#         course = get_object_or_404(PaidCourse, id=course_id)
#     except PaidCourse.DoesNotExist:
#         return JsonResponse({"error": "Course not found."})

#     txnid = f"Txn{uuid.uuid4().hex[:10]}"  # Generate a unique transaction ID
#     first_name = request.user.first_name.strip() if request.user.first_name else "User"

#     if not hasattr(settings, "EASEBUZZ_MERCHANT_KEY") or not settings.EASEBUZZ_MERCHANT_KEY:
#         return JsonResponse({"error": "Invalid merchant key. Please check your settings."})

#     phone_number = getattr(request.user, 'mobile', '')
#     if not phone_number:
#         return JsonResponse({"error": "Phone number is required for payment."})

#     payment = Payment.objects.create(
#         user=request.user,
#         course=course,
#         transaction_id=txnid,
#         amount=course.course_price,
#         status="Pending"
#     )

#     # Construct payment data for Easebuzz
#     data = {
#         "key": settings.EASEBUZZ_MERCHANT_KEY,
#         "txnid": txnid,
#         "amount": str(course.course_price),
#         "productinfo": course.course_title,
#         "firstname": first_name,
#         "email": request.user.email,
#         "phone": phone_number,
#         "surl": request.build_absolute_uri("/payment/success/"),  # Success URL
#         "furl": request.build_absolute_uri("/payment/failure/"),  # Failure URL
#     }

#     # Generate hash (if required by Easebuzz)
#     data["hash"] = generate_hash_key(data)  # Ensure you have a function to generate the hash

#     return render(request, "payment_redirect.html", {"data": data, "easebuzz_url": settings.EASEBUZZ_BASE_URL,'course':course})



# views.py
from django.shortcuts import render
# from .models import Payment

# def payment_success(request):
#     txnid = request.GET.get('txnid')  # Get transaction ID from Easebuzz
#     try:
#         payment = Payment.objects.get(transaction_id=txnid)
#         payment.status = "Success"
#         payment.save()
#     except Payment.DoesNotExist:
#         pass  # Handle error properly in production

#     return render(request, "payment_success.html", {"txnid": txnid})

# def payment_failure(request):
#     txnid = request.GET.get('txnid')
#     try:
#         payment = Payment.objects.get(transaction_id=txnid)
#         payment.status = "Failed"
#         payment.save()
#     except Payment.DoesNotExist:
#         pass

#     return render(request, "payment_failed.html", {"txnid": txnid})

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
    courses = FreeCourse.objects.prefetch_related("chapters").all()

    return render(request, 'student_dashboard.html', {'notifications': notifications,"courses": courses})

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


from django.core.paginator import Paginator
from django.shortcuts import render
from .models import CustomUser

from django.core.paginator import Paginator
from django.db.models import Q
from .models import CustomUser


   




from datetime import datetime

def user_list(request):
    query = request.GET.get('q', '')
    sort = request.GET.get('sort', '')
    status = request.GET.get('status', '')
    date_str = request.GET.get('created_at', '')

    user_list = CustomUser.objects.all()

    # 🔍 Query Filter
    if query:
        user_list = user_list.filter(
            Q(email__icontains=query) |
            Q(mobile__icontains=query)
        )

    # 📅 Date Filter
    if date_str:
        try:
            date_obj = datetime.strptime(date_str, '%Y-%m-%d').date()
            start_datetime = datetime.combine(date_obj, datetime.min.time())
            end_datetime = datetime.combine(date_obj, datetime.max.time())
            user_list = user_list.filter(created_at__range=(start_datetime, end_datetime))
        except ValueError:
            pass

    # ✅ Status Filter (Separate)
    if status == 'verified':
        user_list = user_list.filter(is_verified=True)
    elif status == 'not_verified':
        user_list = user_list.filter(is_verified=False)

    # ✅ Sort Logic (Separate)
    if sort == 'first_name_asc':
        user_list = user_list.order_by('first_name')
    elif sort == 'first_name_desc':
        user_list = user_list.order_by('-first_name')
    elif sort == 'last_name_asc':
        user_list = user_list.order_by('last_name')
    elif sort == 'last_name_desc':
        user_list = user_list.order_by('-last_name')
    elif sort == 'created_newest':
        user_list = user_list.order_by('-created_at')
    elif sort == 'created_oldest':
        user_list = user_list.order_by('created_at')
    else:
        user_list = user_list.order_by('-created_at')  # Default sort

    paginator = Paginator(user_list, 10)
    page_number = request.GET.get('page')
    users = paginator.get_page(page_number)

    return render(request, 'admin_user_list.html', {
        'users': users,
        'query': query,
        'sort': sort,
        'status': status,
    })





import openpyxl
from django.http import HttpResponse
from .models import NewPayment

def export_users_to_excel(request):
    # Get unique users who made a payment
    seen_emails = set()
    unique_payments = []

    all_payments = NewPayment.objects.select_related('user').all()

    for payment in all_payments:
        email = payment.user.email
        if email not in seen_emails:
            unique_payments.append(payment)
            seen_emails.add(email)

    # Create Excel workbook
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Paid Students"

    # Headers
    headers = ['Sr. No.', 'Email', 'First Name', 'Last Name', 'Mobile']
    ws.append(headers)

    # Data rows
    for index, payment in enumerate(unique_payments, start=1):
        user = payment.user
        ws.append([
            index,
            user.email,
            user.first_name or 'N/A',
            user.last_name or 'N/A',
            user.mobile or 'N/A',
        ])

    # Create HTTP response
    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = 'attachment; filename=paid_students.xlsx'
    wb.save(response)
    return response


# start

@login_required
def student_paid_courses(request):
    courses = PaidCourse.objects.all().order_by('-id')
    return render(request, 'student_paid_courses.html', {'courses': courses})





from collections import defaultdict
from django.shortcuts import render, get_object_or_404
from .models import PaidCourse






from .models import UserCourseAccess  # Add this import


from django.db.models import Q
from collections import defaultdict
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render
from .models import PaidCourse, NewPayment, UserCourseAccess, CourseContent, CourseProgress

# @login_required
# def display_paid_content(request, course_id):
#     course = get_object_or_404(PaidCourse, id=course_id)
#     payment = NewPayment.objects.filter(user=request.user, course=course, status="success").first()
#     manual_access = UserCourseAccess.objects.filter(user=request.user, course=course).exists()
    
#     contents = course.contents.all()
#     grouped_contents = defaultdict(list)
#     for content in contents:
#         grouped_contents[content.title].append(content)

#     has_access = bool(payment) or manual_access

#     # ✅ Fetch from DB, not recalculate
#     progress = CourseProgress.objects.filter(user=request.user, course=course).first()
#     progress_percentage = progress.progress_percentage if progress else 0

#     return render(request, 'display_paid_content.html', {
#         'course': course,
#         'grouped_contents': dict(grouped_contents),
#         'has_access': has_access,
#         'progress_percentage': progress_percentage
#     })



from django.shortcuts import render, redirect, get_object_or_404
from collections import defaultdict
from .models import PaidCourse, CourseReview, NewPayment, UserCourseAccess, CourseProgress
from django.contrib.auth.decorators import login_required
from django.db.models import Avg

from django.contrib.auth.models import AnonymousUser

def display_paid_content(request, course_id):
    from collections import defaultdict
    from .models import PaidCourse, CourseReview, NewPayment, UserCourseAccess, CourseProgress, CourseContent, CompletedContent
    from django.db.models import Avg
    from django.shortcuts import render, get_object_or_404, redirect

    course = get_object_or_404(PaidCourse, id=course_id)
    contents = course.contents.all()
    grouped_contents = defaultdict(list)
    for content in contents:
        grouped_contents[content.title].append(content)

    is_logged_in = request.user.is_authenticated
    has_access = False
    progress_percentage = 0
    completed_ids = []

    if is_logged_in:
        # Check if user has access
        has_access = (
            NewPayment.objects.filter(user=request.user, course=course, status="success").exists() or
            UserCourseAccess.objects.filter(user=request.user, course=course).exists()
        )

        # Progress
        progress = CourseProgress.objects.filter(user=request.user, course=course).first()
        if progress:
            progress_percentage = progress.progress_percentage

        # Completed content
        completed_ids = CompletedContent.objects.filter(user=request.user, course=course).values_list('content_id', flat=True)

        # Handle POST review actions
        if request.method == "POST":
            if "submit_review" in request.POST:
                review_text = request.POST.get("review", "").strip()
                rating = int(request.POST.get("rating", 0))
                if 1 <= rating <= 5 and review_text:
                    CourseReview.objects.create(
                        course=course,
                        user=request.user,
                        review=review_text,
                        rating=rating
                    )
                return redirect('display_paid_content', course_id=course.id)

            elif "update_review" in request.POST:
                review_id = request.POST.get("review_id")
                review_obj = get_object_or_404(CourseReview, id=review_id, user=request.user)
                review_text = request.POST.get("review", "").strip()
                rating = int(request.POST.get("rating", 0))
                if 1 <= rating <= 5 and review_text:
                    review_obj.review = review_text
                    review_obj.rating = rating
                    review_obj.save()
                return redirect('display_paid_content', course_id=course.id)

            elif "delete_review" in request.POST:
                review_id = request.POST.get("review_id")
                CourseReview.objects.filter(id=review_id, user=request.user).delete()
                return redirect('display_paid_content', course_id=course.id)

    reviews = CourseReview.objects.filter(course=course).order_by('-created_at')
    title_count = CourseContent.objects.filter(course=course).values('title').distinct().count()
    average_rating = CourseReview.objects.filter(course=course).aggregate(avg_rating=Avg('rating'))['avg_rating'] or 0

    return render(request, 'display_paid_content.html', {
        'course': course,
        'grouped_contents': dict(grouped_contents),
        'has_access': has_access,
        'progress_percentage': progress_percentage,
        'reviews': reviews,
        'title_count': title_count,
        'average_rating': round(average_rating, 1),
        'completed_ids': list(completed_ids),
        'is_logged_in': is_logged_in,
    })




# payment


    
    
# go
 

import hashlib, random, string
from django.conf import settings
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from .models import PaidCourse, NewPayment
from collections import defaultdict

def generate_txnid():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))




@login_required
def initiate_payment(request, course_id):
    course = get_object_or_404(PaidCourse, id=course_id)
    user = request.user

    txnid = generate_txnid()
    amount = str(course.course_price)
    productinfo = course.course_title
    firstname = user.first_name or user.username
    email = user.email
    phone = "9999999999"
    # keep above phone filed in comment if you working on live and for local keep below uncommented
    # phone = user.mobile  # Or from user profile

    key = settings.EASEBUZZ_MERCHANT_KEY
    salt = settings.EASEBUZZ_SALT

    hash_string = f"{key}|{txnid}|{amount}|{productinfo}|{firstname}|{email}|||||||||||{salt}"
    hashh = hashlib.sha512(hash_string.encode('utf-8')).hexdigest().lower()


    # payment = NewPayment.objects.create(
    #     user=user,
    #     course=course,
    #     amount=amount,
    #     txnid=txnid,
    #     status="initiated"
    # )

    context = {
        "payment_url": "https://testpay.easebuzz.in/pay/secure" if settings.EASEBUZZ_USE_SANDBOX else "https://pay.easebuzz.in/pay/secure",
        "MERCHANT_KEY": key,
        "txnid": txnid,
        "amount": amount,
        "productinfo": productinfo,
        "firstname": firstname,
        "email": email,
        "phone": phone,
        "surl": request.build_absolute_uri('/payment/success/'),
        "furl": request.build_absolute_uri('/payment/failure/'),
        # this below should be in comment if you want to make payment on local
        # "surl": "https://profitmaxacademy.in/payment/success/",
        # "furl": "https://profitmaxacademy.in/payment/failure/",

        "hashh": hashh
    }
    return render(request, "initiate_payment.html", context)






@csrf_exempt
def payment_success(request):
    txnid = request.POST.get("txnid")
    status = request.POST.get("status")
    amount = request.POST.get("amount")
    email = request.POST.get("email")
    productinfo = request.POST.get("productinfo")

    user = CustomUser.objects.filter(email=email).first()
    course = PaidCourse.objects.filter(course_title=productinfo).first()

    if status == "success" and user and course:
        # Only save successful payment
        NewPayment.objects.create(
            user=user,
            course=course,
            amount=amount,
            txnid=txnid,
            status=status,
            invoice_created=True,  # Always True for online
            created_at=timezone.now()
        )

        UserCourseAccess.objects.get_or_create(user=user, course=course)



        return redirect('display_paid_content', course_id=course.id)
    else:
        return render(request, 'payment_failed.html')


@csrf_exempt
def payment_failure(request):
    txnid = request.POST.get("txnid")
    try:
        payment = NewPayment.objects.get(txnid=txnid)
        payment.status = "failed"
        payment.save()
    except NewPayment.DoesNotExist:
        pass
    return render(request, 'payment_failed.html')








# use user pass test to know weather the login is of admin or user
import uuid  # Add this at the top
from django.utils import timezone
from django.shortcuts import get_object_or_404

from django.utils import timezone
import uuid

import uuid
from django.utils import timezone
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.mail import send_mail
from django.conf import settings
from .models import CustomUser, PaidCourse, NewPayment, Invoice, UserCourseAccess

@login_required
@user_passes_test(lambda u: u.is_superuser)
def grant_course_access(request):
    if request.method == "POST":
        user_id = request.POST.get("user_id")
        course_id = request.POST.get("course_id")
        create_invoice = request.POST.get("create_invoice") == "on"

        user = get_object_or_404(CustomUser, id=user_id)
        course = get_object_or_404(PaidCourse, id=course_id)

        # Create payment record
        txn_id = f"MANUAL-{uuid.uuid4().hex[:8]}"
        payment = NewPayment.objects.create(
            user=user,
            course=course,
            amount=course.course_price,
            txnid=txn_id,
            status="manual",
            invoice_created=create_invoice
        )

        # Create invoice if requested
        if create_invoice:
            invoice = Invoice.objects.create(
                user=user,
                course=course,
                course_title=course.course_title,
                course_fee=course.original_price,
                discount=course.discount_amount,
                paid_amount=course.course_price,
                first_name=user.first_name,
                last_name=user.last_name,
                mobile=user.mobile,
                email=user.email,
            )
            # Link invoice to payment if applicable
            if hasattr(Invoice, 'payment'):
                invoice.payment = payment
                invoice.save()

        # Grant course access
        UserCourseAccess.objects.get_or_create(user=user, course=course)

        # ========== ✅ Send Email to Admin ==========
        full_name = f"{user.first_name} {user.last_name}".strip() or user.username
        subject_admin = f"✔️ Course Access Granted to {full_name}"
        message_admin = f"""
Hello Admin,

The following user has been granted course access manually:

👤 Name: {full_name}
📧 Email: {user.email}
📱 Mobile: {user.mobile}
📘 Course: {course.course_title}

This was done through the admin grant access panel.

Regards,  
System Notification
"""
        send_mail(
            subject_admin,
            message_admin,
            settings.DEFAULT_FROM_EMAIL,
            [settings.DEFAULT_FROM_EMAIL],
            fail_silently=True,
        )

        # ========== ✅ Send Congratulations Email to User ==========
        subject_user = f"🎉 Course Access Granted for {course.course_title}"
        message_user = f"""
Hi {full_name},

Congratulations! You have been granted access to the course:

📘 Course: {course.course_title}
💰 Price: ₹{course.course_price}

You can now log in to your dashboard and start learning.

Best regards,  
{settings.DEFAULT_FROM_EMAIL}
"""
        send_mail(
            subject_user,
            message_user,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=True,
        )

        return redirect('grant_course_access')

    # GET request — render form
    return render(request, "grant_course_access.html", {
        "users": CustomUser.objects.filter(is_staff=False, is_superuser=False),
        "courses": PaidCourse.objects.all(),
        "user_query": request.GET.get('user_search', '').strip(),
        "course_query": request.GET.get('course_search', '').strip(),
    })

# from django.db.models import Count, Q
from django.shortcuts import get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from .models import CourseProgress, PaidCourse, CourseContent,CompletedContent

@login_required
def mark_content_complete(request):
    if request.method == "POST":
        user = request.user
        course_id = request.POST.get("course_id")
        content_id = request.POST.get("content_id")

        course = get_object_or_404(PaidCourse, id=course_id)
        content = get_object_or_404(CourseContent, id=content_id)

        # ✅ Store completed content in the database
        CompletedContent.objects.get_or_create(user=user, course=course, content=content)

        # ✅ Calculate progress
        total_content = CourseContent.objects.filter(course=course).count()
        completed_count = CompletedContent.objects.filter(user=user, course=course).count()
        percentage = int((completed_count / total_content) * 100) if total_content > 0 else 0

        # ✅ Update progress
        progress, created = CourseProgress.objects.get_or_create(user=user, course=course)
        progress.progress_percentage = percentage
        progress.completed = (percentage == 100)
        progress.save()

        return redirect('display_paid_content', course_id=course.id)




# views.py
from django.shortcuts import render, get_object_or_404
from .models import PaidCourse, CourseProgress, NewPayment, UserCourseAccess
from django.contrib.auth.decorators import login_required, user_passes_test
from .models import CustomUser  # Make sure this is correctly imported

@login_required
# @user_passes_test(lambda u: u.is_superuser)
@user_passes_test(is_admin_or_subadmin)
def enrollment_tracking(request):
    courses = PaidCourse.objects.all()
    selected_course = None
    completed_students = []
    ongoing_students = []
    total_students = 0
    search_code = ""

    if request.method == "POST":
        action = request.POST.get("action")  # "search" or "view"
        search_code = request.POST.get("search_code", "").strip()
        course_id = request.POST.get("course_id")

        # 🔍 Search Action
        if action == "search" and search_code:
            matched_courses = PaidCourse.objects.filter(course_code__icontains=search_code)
            courses = matched_courses  # Filtered list in dropdown
            if matched_courses.count() == 1:
                selected_course = matched_courses.first()
                course_id = selected_course.id  # Prepare for progress fetch

        # 📊 View Progress Action (also triggered after successful search)
        if (action == "view" and course_id) or (action == "search" and selected_course):
            if not selected_course:
                selected_course = get_object_or_404(PaidCourse, id=course_id)

            paid_users = NewPayment.objects.filter(course=selected_course, status="success").values_list('user', flat=True)
            manual_users = UserCourseAccess.objects.filter(course=selected_course).values_list('user', flat=True)
            all_user_ids = set(list(paid_users) + list(manual_users))
            users = CustomUser.objects.filter(id__in=all_user_ids)

            for user in users:
                progress = CourseProgress.objects.filter(user=user, course=selected_course).first()
                if progress and progress.progress_percentage == 100:
                    completed_students.append(user)
                else:
                    ongoing_students.append(user)

            total_students = len(users)

    return render(request, "enrollment_tracking.html", {
        "courses": courses,
        "selected_course": selected_course,
        "completed_students": completed_students,
        "ongoing_students": ongoing_students,
        "total_students": total_students,
        "search_code": search_code,
    })


from django.shortcuts import render, get_object_or_404
from .models import PaidCourse, CourseContent
from django.urls import reverse

from collections import defaultdict

from django.shortcuts import render, get_object_or_404


# paid course view for admin



from django.shortcuts import render, get_object_or_404, redirect
from .models import PaidCourse, CourseContent, CourseReview
from django.contrib.admin.views.decorators import staff_member_required

# def view_content(request, course_id):
#     course = get_object_or_404(PaidCourse, id=course_id)

#     # Optional: Delete review if GET param is passed
#     if 'delete_review' in request.GET:
#         review_id = request.GET.get('delete_review')
#         CourseReview.objects.filter(id=review_id).delete()
#         return redirect('view_content', course_id=course.id)

#     contents = CourseContent.objects.filter(course=course).order_by('title')
#     grouped_contents = {}
#     for content in contents:
#         grouped_contents.setdefault(content.title, []).append(content)

#     reviews = CourseReview.objects.filter(course=course).order_by('-created_at')

#     context = {
#         'course': course,
#         'grouped_contents': grouped_contents,
#         'reviews': reviews,
#         'is_admin_view': True,
#     }
#     return render(request, 'view_content.html', context)


from django.contrib.auth.decorators import login_required
from .models import PaidCourse, CourseContent, CourseReview, CustomUser

@user_passes_test(is_admin_or_subadmin)
def view_content(request, course_id):
    course = get_object_or_404(PaidCourse, id=course_id)
    title_count = CourseContent.objects.filter(course=course).values('title').distinct().count()
    average_rating = CourseReview.objects.filter(course=course).aggregate(avg_rating=Avg('rating'))['avg_rating'] or 0

    # ✅ Handle deletion
    if 'delete_review' in request.GET:
        review_id = request.GET.get('delete_review')
        CourseReview.objects.filter(id=review_id).delete()
        return redirect('view_content', course_id=course.id)

    # ✅ Handle Fake Review Form
    if request.method == "POST" and "submit_fake_review" in request.POST:
        display_name = request.POST.get("display_name")
        rating = int(request.POST.get("rating"))
        review_text = request.POST.get("review")
       

        CourseReview.objects.create(
            course=course,
            user=request.user,  # required field, but won't be shown
            review=review_text,
            rating=rating,
            display_name=display_name,
            is_admin_generated=True,
        )
        return redirect('view_content', course_id=course.id)

    contents = CourseContent.objects.filter(course=course).order_by('title')
    grouped_contents = {}
    for content in contents:
        grouped_contents.setdefault(content.title, []).append(content)

    reviews = CourseReview.objects.filter(course=course).order_by('-created_at')

    context = {
        'course': course,
        'grouped_contents': grouped_contents,
        'reviews': reviews,
        'is_admin_view': True,
        'title_count': title_count,
        'average_rating': round(average_rating, 1),
    }
    return render(request, 'view_content.html', context)



from django.shortcuts import render
from .models import PaidCourse


def paid_course_list(request):
    courses = PaidCourse.objects.all()
    return render(request, 'course_list.html', {'courses': courses})


from django.shortcuts import render
from .models import NewPayment


def paid_students_list(request):
    seen_emails = set()
    unique_payments = []

    all_payments = NewPayment.objects.select_related('user').all()

    for payment in all_payments:
        email = payment.user.email
        if email not in seen_emails:
            unique_payments.append(payment)
            seen_emails.add(email)

    return render(request, 'paid_students_list.html', {'payments': unique_payments})



from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from .models import UserCourseAccess, CustomUser, PaidCourse, RevokedAccess, NewPayment

# @require_POST
def revoke_course_access(request, payment_id):
    payment = get_object_or_404(NewPayment, id=payment_id)
    
    if not payment.is_revoked:
        payment.is_revoked = True
        payment.save()
        
        # Create revocation record
        RevokedAccess.objects.create(
            user=payment.user,
            course=payment.course,
            payment=payment
        )
        
        # Remove access if using UserCourseAccess
        UserCourseAccess.objects.filter(user=payment.user, course=payment.course).delete()
        
        messages.success(request, "Course access revoked successfully")
    else:
        messages.warning(request, "Access was already revoked")
    
    return redirect('user_detail', user_id=payment.user.id)




# @require_POST
def restore_course_access_view(request, payment_id):
    payment = get_object_or_404(NewPayment, id=payment_id)
    
    if payment.is_revoked:
        payment.is_revoked = False
        payment.save()
        
        # Restore access
        UserCourseAccess.objects.get_or_create(
            user=payment.user,
            course=payment.course
        )
        
        # Remove revocation record
        RevokedAccess.objects.filter(payment=payment).delete()
        
        messages.success(request, "Course access restored successfully")
    else:
        messages.warning(request, "Access was not revoked")
    
    return redirect('user_detail', user_id=payment.user.id)



from .models import CustomUser, NewPayment, Invoice, UserCourseAccess

from .models import CustomUser, NewPayment, Invoice, UserCourseAccess, RevokedAccess

def user_detail_view(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    payments = NewPayment.objects.filter(user=user).select_related('course').order_by('-created_at')
    
    # Get all invoices for this user
    invoices = Invoice.objects.filter(user=user)
    
    # Create mapping of payment IDs to invoices
    invoice_map = {}
    for invoice in invoices:
        # For online payments, match by course and amount
        if invoice.payment:
            invoice_map[invoice.payment_id] = invoice
        else:
            # For manual payments without direct payment reference
            key = (invoice.course_id, float(invoice.paid_amount))
            invoice_map[key] = invoice
    
    for payment in payments:
        # Find invoice - check direct payment reference first
        payment.invoice = None
        
        # Check for direct payment reference in invoice
        if hasattr(Invoice, 'payment'):
            payment.invoice = Invoice.objects.filter(payment=payment).first()
        
        # If not found, try matching by course and amount
        if not payment.invoice:
            payment.invoice = invoice_map.get((payment.course_id, float(payment.amount)))
        
        # Set flags for template
        payment.invoice_exists = bool(payment.invoice)
        payment.access_revoked = payment.is_revoked
    
    return render(request, 'user_detail.html', {
        'user': user,
        'payments': payments,
    })

from .models import Invoice, PaidCourse, CustomUser, NewPayment

def generate_invoice_view(request, payment_id):
    payment = get_object_or_404(NewPayment, id=payment_id)
    
    # Check for existing invoice for THIS payment
    invoice = Invoice.objects.filter(payment=payment).first()
    
    if invoice:
        return render(request, 'invoice_detail.html', {'invoice': invoice})
    
    try:
        invoice = Invoice.objects.create(
            payment=payment,  # Critical link
            user=payment.user,
            course=payment.course,
            course_title=payment.course.course_title,
            course_fee=payment.course.original_price,
            discount=payment.course.discount_amount,
            paid_amount=payment.amount,
            first_name=payment.user.first_name,
            last_name=payment.user.last_name,
            mobile=payment.user.mobile,
            email=payment.user.email,
        )
        
        payment.invoice_created = True
        payment.save()
        
        return render(request, 'invoice_detail.html', {'invoice': invoice})
    
    except Exception as e:
        messages.error(request, f"Error generating invoice: {str(e)}")
        return redirect('user_detail', user_id=payment.user.id)




# single device login
from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver
from django.contrib.sessions.models import Session
from lmsapp.models import UserSession  # adjust as needed

@receiver(user_logged_in)
def enforce_single_session(sender, request, user, **kwargs):
    if request.session.session_key is None:
        request.session.save()

    session_key = request.session.session_key

    try:
        existing_session = UserSession.objects.get(user=user)
        if existing_session.session_key != session_key:
            # Delete the old session
            Session.objects.filter(session_key=existing_session.session_key).delete()
    except UserSession.DoesNotExist:
        existing_session = UserSession(user=user)

    # Save the new session key
    existing_session.session_key = session_key
    existing_session.save()



from django.views.decorators.http import require_POST
from django.shortcuts import get_object_or_404, redirect
from .models import Invoice

@require_POST
def cancel_invoice_view(request, invoice_id):
    invoice = get_object_or_404(Invoice, id=invoice_id)
    if not invoice.is_canceled:
        invoice.is_canceled = True
        invoice.save()
    return redirect('user_detail', user_id=invoice.user.id)


@require_POST
def toggle_invoice_status_view(request, invoice_id):
    invoice = get_object_or_404(Invoice, id=invoice_id)
    invoice.is_canceled = not invoice.is_canceled
    invoice.save()

    # Sync with NewPayment model
    payment = NewPayment.objects.filter(user=invoice.user, course=invoice.course, amount=invoice.paid_amount).first()
    if payment:
        payment.canceled_invoice = invoice.is_canceled
        payment.save()

    return redirect('user_detail', user_id=invoice.user.id)


from django.db.models import Sum
from .models import Invoice

# this is invoice calculation page which is not shifted to admin_dashboard page
def invoice_dashboard_view(request):
    active_total = Invoice.objects.filter(is_canceled=False).aggregate(Sum('paid_amount'))['paid_amount__sum'] or 0
    canceled_total = Invoice.objects.filter(is_canceled=True).aggregate(Sum('paid_amount'))['paid_amount__sum'] or 0
    total_amount = active_total + canceled_total

    return render(request, 'dashboard.html', {
        'active_total': active_total,
        'canceled_total': canceled_total,
        'total_amount': total_amount
    })



from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render
from .models import CourseContent  # adjust if your model name differs

@login_required
def view_file(request, content_id):
    content = get_object_or_404(CourseContent, id=content_id)
    user = request.user

    return render(request, 'view_file.html', {
        'content': content,
        'user': user,
    })


def certificate(request):
    return render(request,'certificate.html')


from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from .models import NewPayment

@login_required
def your_course(request):
    # Fetch only successful or manual payments
    purchased_payments = NewPayment.objects.filter(
        user=request.user,
        status__in=["success", "manual"]
    ).select_related('course')  # To avoid extra queries

    # Get unique courses by using a dictionary to eliminate duplicates
    unique_courses = {}
    for payment in purchased_payments:
        if payment.course.id not in unique_courses:
            unique_courses[payment.course.id] = payment.course

    # Convert dictionary values to list
    purchased_courses = list(unique_courses.values())

    return render(request, 'your_course.html', {'courses': purchased_courses})



# views.py
import json
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from lmsapp.models import NewPayment, UserCourseAccess  # adjust as needed

@csrf_exempt
@require_POST
def easebuzz_webhook(request):
    try:
        data = json.loads(request.body)

        # Example data structure
        txn_status = data.get("status")
        txn_id = data.get("txnid")
        user_email = data.get("buyer_email")
        product_id = data.get("productinfo")  # or your custom field

        # Handle transaction success
        if txn_status == "success":
            # Update your models
            payment = NewPayment.objects.filter(transaction_id=txn_id).first()
            if payment:
                payment.status = "Success"
                payment.save()

                # Give course access (optional)
                UserCourseAccess.objects.get_or_create(
                    user=payment.user,
                    course=payment.course
                )

        elif txn_status == "failure":
            # Update status if needed
            payment = NewPayment.objects.filter(transaction_id=txn_id).first()
            if payment:
                payment.status = "Failed"
                payment.save()

        return HttpResponse("Webhook received", status=200)

    except Exception as e:
        print("Webhook Error:", e)
        return HttpResponse("Error", status=400)



from django.shortcuts import render
from .models import Invoice

def canceled_invoice_view(request):
    # Get filter parameters
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    specific_date = request.GET.get('specific_date')
    course_id = request.GET.get('course')
    
    canceled_invoices = Invoice.objects.filter(is_canceled=True)
    
    # Apply date filters
    if specific_date:
        canceled_invoices = canceled_invoices.filter(date_created__date=specific_date)
    else:
        if date_from:
            canceled_invoices = canceled_invoices.filter(date_created__gte=date_from)
        if date_to:
            canceled_invoices = canceled_invoices.filter(date_created__lte=date_to)
    
    # Apply course filter
    if course_id:
        canceled_invoices = canceled_invoices.filter(course_id=course_id)
    
    canceled_invoices = canceled_invoices.select_related('course', 'user').order_by('-date_created')
    
    return render(request, 'canceled_invoice.html', {
        'canceled_invoices': canceled_invoices,
        'filter_params': request.GET,
    })



# views.py
from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from .models import UserCourseAccess, CustomUser, PaidCourse, RevokedAccess  # include RevokedAccess

# def revoke_course_access(request, user_id, course_id):
#     if not request.user.is_superuser:
#         messages.error(request, "Permission denied.")
#         return redirect('admin_dashboard')

#     access = get_object_or_404(UserCourseAccess, user_id=user_id, course_id=course_id)
#     access.delete()

#     # Optionally log this revocation
#     RevokedAccess.objects.create(user_id=user_id, course_id=course_id)

#     messages.success(request, "Access to the course has been revoked.")
#     return redirect('user_detail', user_id=user_id)


def manual_access_report(request):
    # Get filter parameters
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    specific_date = request.GET.get('specific_date')
    course_id = request.GET.get('course')
    
    manual_payments = NewPayment.objects.filter(status='manual')
    
    # Apply date filters
    if specific_date:
        manual_payments = manual_payments.filter(created_at__date=specific_date)
    else:
        if date_from:
            manual_payments = manual_payments.filter(created_at__gte=date_from)
        if date_to:
            manual_payments = manual_payments.filter(created_at__lte=date_to)
    
    # Apply course filter
    if course_id:
        manual_payments = manual_payments.filter(course_id=course_id)
    
    manual_payments = manual_payments.select_related('user', 'course')
    
    # Get all courses for filter display (if needed in template)
    all_courses = PaidCourse.objects.all()
    
    return render(request, 'manual_access_report.html', {
        'manual_payments': manual_payments,
        'all_courses': all_courses,
        'filter_params': request.GET,
    })


def course_report(request):
    # Get filter parameters
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    specific_date = request.GET.get('specific_date')
    course_id = request.GET.get('course')
    
    courses = PaidCourse.objects.filter(newpayment__status__in=['manual', 'success'])
    
    # Apply date filters
    if specific_date:
        courses = courses.filter(newpayment__created_at__date=specific_date)
    else:
        if date_from:
            courses = courses.filter(newpayment__created_at__gte=date_from)
        if date_to:
            courses = courses.filter(newpayment__created_at__lte=date_to)
    
    # Apply course filter if selected
    if course_id:
        courses = courses.filter(id=course_id)
    
    courses = courses.annotate(total_enrollments=Count('newpayment')).distinct()
    
    return render(request, 'course_report.html', {
        'courses': courses,
        'all_courses': PaidCourse.objects.all(),  # For filter display
        'filter_params': request.GET,
    })

def course_enrollment_detail(request, course_id):
    course = get_object_or_404(PaidCourse, id=course_id)
    enrollments = NewPayment.objects.filter(course=course, status__in=['manual', 'success']).select_related('user')
    return render(request, 'course_enrollment_detail.html', {
        'course': course,
        'enrollments': enrollments
    })

    
    
def revoked_access_list_view(request):
    if not request.user.is_superuser:
        return redirect('admin_dashboard')
    
    # Get filter parameters
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    specific_date = request.GET.get('specific_date')
    course_id = request.GET.get('course')
    
    revoked_entries = RevokedAccess.objects.all()
    
    # Apply date filters
    if specific_date:
        revoked_entries = revoked_entries.filter(revoked_on__date=specific_date)
    else:
        if date_from:
            revoked_entries = revoked_entries.filter(revoked_on__gte=date_from)
        if date_to:
            revoked_entries = revoked_entries.filter(revoked_on__lte=date_to)
    
    # Apply course filter
    if course_id:
        revoked_entries = revoked_entries.filter(course_id=course_id)
    
    revoked_entries = revoked_entries.select_related('user', 'course').order_by('-revoked_on')
    
    return render(request, 'revoked_courses_list.html', {
        'revoked_entries': revoked_entries,
        'all_courses': PaidCourse.objects.all(),  # For filter display
        'filter_params': request.GET,
    })



from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required, user_passes_test

# Restrict to superuser

@login_required
@user_passes_test(lambda u: u.is_superuser)
def change_password_view(request):
    if request.method == 'POST':
        form = PasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Keeps the user logged in
            return redirect('password_change_done')
    else:
        form = PasswordChangeForm(user=request.user)
    return render(request, 'change_password.html', {'form': form})



from django.contrib.auth.decorators import login_required
from django.shortcuts import render


@login_required
@user_passes_test(lambda u: u.is_superuser)
def password_change_done_view(request):
    return render(request, 'password_change_done.html')



from openpyxl import Workbook
from django.http import HttpResponse
from .models import NewPayment

from openpyxl import Workbook
from django.http import HttpResponse
from .models import NewPayment, Invoice, PaidCourse, RevokedAccess
from django.db.models import Count

# excel button to reports section

def export_to_excel(request):
    report_type = request.GET.get('report_type')  # manual / canceled / course / revoked
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    specific_date = request.GET.get('specific_date')
    course_id = request.GET.get('course')

    wb = Workbook()
    ws = wb.active

    if report_type == 'manual':
        payments = NewPayment.objects.filter(status='manual')
        if specific_date:
            payments = payments.filter(created_at__date=specific_date)
        else:
            if date_from:
                payments = payments.filter(created_at__gte=date_from)
            if date_to:
                payments = payments.filter(created_at__lte=date_to)
        if course_id:
            payments = payments.filter(course_id=course_id)
        payments = payments.select_related('user', 'course')
        ws.title = "Manual Access Report"
        ws.append(['Sr. No.', 'Student Name', 'Email', 'Mobile', 'Course', 'Date'])
        for idx, p in enumerate(payments, start=1):
            ws.append([
                idx,
                f"{p.user.first_name or ''} {p.user.last_name or ''}".strip(),
                p.user.email,
                p.user.mobile,
                p.course.course_title if p.course else 'N/A',
                p.created_at.strftime("%Y-%m-%d")
            ])

    elif report_type == 'canceled':
        invoices = Invoice.objects.filter(is_canceled=True)
        if specific_date:
            invoices = invoices.filter(date_created__date=specific_date)
        else:
            if date_from:
                invoices = invoices.filter(date_created__gte=date_from)
            if date_to:
                invoices = invoices.filter(date_created__lte=date_to)
        if course_id:
            invoices = invoices.filter(course_id=course_id)
        invoices = invoices.select_related('user', 'course')
        ws.title = "Canceled Invoices"
        ws.append(['Sr. No.', 'Student Name', 'Email', 'Mobile', 'Course', 'Invoice No.', 'Date'])
        for idx, inv in enumerate(invoices, start=1):
            ws.append([
                idx,
                f"{inv.user.first_name or ''} {inv.user.last_name or ''}".strip(),
                inv.user.email,
                inv.user.mobile,
                inv.course.course_title if inv.course else 'N/A',
                inv.invoice_number,
                inv.date_created.strftime("%Y-%m-%d")
            ])

    elif report_type == 'course':
        courses = PaidCourse.objects.filter(newpayment__status__in=['manual', 'success'])
        if specific_date:
            courses = courses.filter(newpayment__created_at__date=specific_date)
        else:
            if date_from:
                courses = courses.filter(newpayment__created_at__gte=date_from)
            if date_to:
                courses = courses.filter(newpayment__created_at__lte=date_to)
        if course_id:
            courses = courses.filter(id=course_id)
        courses = courses.annotate(total_enrollments=Count('newpayment')).distinct()
        ws.title = "Course Report"
        ws.append(['Sr. No.', 'Course Title', 'Course Price', 'Total Enrollments'])
        for idx, c in enumerate(courses, start=1):
            ws.append([
                idx,
                c.course_title,
                c.course_price,
                c.total_enrollments
            ])

    elif report_type == 'revoked':
        revoked = RevokedAccess.objects.all()
        if specific_date:
            revoked = revoked.filter(revoked_on__date=specific_date)
        else:
            if date_from:
                revoked = revoked.filter(revoked_on__gte=date_from)
            if date_to:
                revoked = revoked.filter(revoked_on__lte=date_to)
        if course_id:
            revoked = revoked.filter(course_id=course_id)
        revoked = revoked.select_related('user', 'course')
        ws.title = "Revoked Access List"
        ws.append(['Sr. No.', 'Student Name', 'Email', 'Mobile', 'Course', 'Revoked On'])
        for idx, r in enumerate(revoked, start=1):
            ws.append([
                idx,
                f"{r.user.first_name or ''} {r.user.last_name or ''}".strip(),
                r.user.email,
                r.user.mobile,
                r.course.course_title if r.course else 'N/A',
                r.revoked_on.strftime("%Y-%m-%d")
            ])


    elif report_type == 'enrollment_detail':
        course_id = request.GET.get('course_id')
        course = get_object_or_404(PaidCourse, id=course_id)
        enrollments = NewPayment.objects.filter(course=course, status__in=['manual', 'success']).select_related('user')

        ws.title = f"Enrollments - {course.course_title[:20]}"
        ws.append(['Sr. No.', 'Student Name', 'Email', 'Mobile', 'Course', 'Payment Status', 'Date'])

        for idx, e in enumerate(enrollments, start=1):
            ws.append([
                idx,
                f"{e.user.first_name or ''} {e.user.last_name or ''}".strip(),
                e.user.email,
                e.user.mobile,
                course.course_title,
                e.status,
                e.created_at.strftime("%Y-%m-%d")
            ])
       

    else:
        ws.title = "Invalid Report"
        ws.append(['Invalid report type specified.'])

    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename={report_type}_report.xlsx'
    wb.save(response)
    return response



from django.shortcuts import render, redirect
from .models import Category

def create_category(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')
        icon = request.FILES.get('icon')

        if name:
            Category.objects.create(name=name, description=description, icon=icon)
            return redirect('view_categories')

    return render(request, 'create_category.html')

from django.shortcuts import render, get_object_or_404
from .models import Category


def view_categories(request):
    categories = Category.objects.all()
    category_data = []

    for category in categories:
        free_courses = FreeCourse.objects.filter(category=category)[:3]
        paid_courses = PaidCourse.objects.filter(category=category)[:3]
        category_data.append({
            'category': category,
            'free_courses': free_courses,
            'paid_courses': paid_courses
        })

    return render(request, 'categories.html', {'category_data': category_data})


from django.shortcuts import get_object_or_404

def courses_by_category(request, category_id):
    category = get_object_or_404(Category, id=category_id)
    courses = PaidCourse.objects.filter(category=category).order_by('-id')
    return render(request, 'courses_by_category.html', {
        'category': category,
        'courses': courses
    })
    






from django.shortcuts import render, get_object_or_404
from .models import Category, FreeCourse, PaidCourse

def category_detail(request, category_id):
    category = get_object_or_404(Category, id=category_id)
    free_courses = FreeCourse.objects.filter(category=category)[:3]
    paid_courses = PaidCourse.objects.filter(category=category)[:3]
    
    return render(request, 'category_detail.html', {
        'category': category,
        'free_courses': free_courses,
        'paid_courses': paid_courses
    })


from django.shortcuts import get_object_or_404, render
from .models import Category, FreeCourse, PaidCourse

def free_courses_by_category(request, category_id):
    category = get_object_or_404(Category, id=category_id)
    courses = FreeCourse.objects.filter(category=category)
    return render(request, 'free_courses_by_category.html', {
        'category': category,
        'courses': courses  # ✅ matches HTML
    })

def paid_courses_by_category(request, category_id):
    category = get_object_or_404(Category, id=category_id)
    courses = PaidCourse.objects.filter(category=category)
    return render(request, 'paid_courses_by_category.html', {
        'category': category,
        'courses': courses  # ✅ matches HTML
    })

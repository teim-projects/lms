from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User

 


from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin, Group, Permission
from django.db import models
from django.utils.translation import gettext_lazy as _


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(_('email address'), unique=True)
    mobile = models.CharField(max_length=12, unique=True)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)

    groups = models.ManyToManyField(
        Group,
        related_name="customuser_groups",
        blank=True,
        help_text=_("The groups this user belongs to."),
        verbose_name=_("groups"),
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name="customuser_permissions",
        blank=True,
        help_text=_("Specific permissions for this user."),
        verbose_name=_("user permissions"),
    )

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email

    @property
    def username(self):
        return self.email  # Fallback so Django admin etc. works




import random
class OTP(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    code = models.CharField(max_length=4)
    created_at = models.DateTimeField(auto_now_add=True)

    @staticmethod
    def generate_otp():
        return str(random.randint(1000, 9999))
        







# models.py
from django.db import models

class FreeCourse(models.Model):
    title = models.CharField(max_length=255)
    
    thumbnail = models.ImageField(upload_to='thumbnails/')
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title


class CourseChapter(models.Model):
    course = models.ForeignKey(FreeCourse, on_delete=models.CASCADE, related_name="chapters")
    title = models.CharField(max_length=255)  # Title for the chapter
    youtube_link = models.URLField()

    def __str__(self):
        return f"{self.course.title} - {self.title}"






from django.db import models

from django.db import models

class PaidCourse(models.Model):
    COURSE_LEVELS = [
        ('Beginner', 'Beginner'),
        ('Intermediate', 'Intermediate'),
        ('Advanced', 'Advanced'),
    ]

    course_title = models.CharField(max_length=255)
    duration = models.CharField(max_length=100)
    description = models.TextField()
    instructor_name = models.CharField(max_length=255)
    course_level = models.CharField(max_length=20, choices=COURSE_LEVELS, default='Beginner')
    course_price = models.DecimalField(max_digits=10, decimal_places=2)
    thumbnail = models.ImageField(upload_to='thumbnails/')

    # ✅ Newly added fields
    about = models.TextField(blank=True, null=True)
    benefits = models.TextField(blank=True, null=True)
    testimonials = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.course_title


class CourseContent(models.Model):
    course = models.ForeignKey(PaidCourse, on_delete=models.CASCADE, related_name='contents')
    title = models.CharField(max_length=255)
    subtitle = models.CharField(max_length=255, blank=True, null=True)
    resource_file = models.FileField(upload_to='course_resources/')
    completed = models.BooleanField(default=False)

    

    def __str__(self):
        return self.title

from django.db import models
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.contrib.auth.models import AbstractUser

from django.contrib.auth.models import AbstractUser
from django.db import models

class SubAdmin(AbstractUser):
    email = models.EmailField(unique=True)  # 👈 Make email unique

    phone_number = models.CharField(max_length=15, blank=True, null=True)
    plain_password = models.CharField(max_length=128, blank=True, null=True)
    is_subadmin = models.BooleanField(default=True)

    groups = models.ManyToManyField(
        'auth.Group',
        related_name='subadmin_set',
        blank=True,
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='subadmin_permissions_set',
        blank=True,
    )

    # Remove unused fields and override username
    username = None
    first_name = None
    last_name = None
    address = None  # You can remove this if not declared elsewhere

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['phone_number']

    def __str__(self):
        return self.email


# class Payment(models.Model):
#     STATUS_CHOICES = [
#         ('Pending', 'Pending'),
#         ('Success', 'Success'),
#         ('Failed', 'Failed'),
#     ]

#     user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
#     course = models.ForeignKey(PaidCourse, on_delete=models.CASCADE)
#     first_name=models.CharField(max_length=100, null=True)
#     transaction_id = models.CharField(max_length=100, unique=True)
#     amount = models.DecimalField(max_digits=10, decimal_places=2)
#     status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='Pending')
#     timestamp = models.DateTimeField(auto_now_add=True)

#     def __str__(self):
#         return f"{self.user.user} - {self.course.course} - {self.status}"

from django.db import models
from django.contrib.auth.models import User

class Notification(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField()
    image = models.ImageField(upload_to='notifications/', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title
    




from django.db import models
from django.contrib.auth import get_user_model


User = get_user_model()

from django.db import models
from .models import CustomUser
from .models import PaidCourse, CourseContent

class CourseProgress(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    course = models.ForeignKey(PaidCourse, on_delete=models.CASCADE)
    completed = models.BooleanField(default=False)
    progress_percentage = models.IntegerField(default=0)

    class Meta:
        unique_together = ('user', 'course')

    def __str__(self):
        return f"{self.user} - {self.course} - {self.progress_percentage}%"





from django.db import models
from django.conf import settings

class Ticket(models.Model):
    STATUS_CHOICES = [
        ("open", "Open"),
        ("closed", "Closed"),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    subject = models.CharField(max_length=255)
    description = models.TextField()
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="open")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.subject} - {self.status}"



# models.py


class NewPayment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    course = models.ForeignKey(PaidCourse, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    txnid = models.CharField(max_length=100, unique=True)
    status = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.course.course_title} - {self.txnid}"


# models.py


class UserCourseAccess(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)  # ✅ make sure it's CustomUser
    course = models.ForeignKey(PaidCourse, on_delete=models.CASCADE)
    granted_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.email} - {self.course.course_title}"


# testimonials models

from django.db import models
from django.contrib.auth.models import User

class CourseReview(models.Model):
    course = models.ForeignKey('PaidCourse', on_delete=models.CASCADE, related_name='reviews')
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    review = models.TextField()
    rating = models.PositiveSmallIntegerField()  # 1 to 5
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username}'s review on {self.course.course_title}"



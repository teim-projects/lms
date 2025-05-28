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
    mobile = models.CharField(max_length=12)  # Mobile number field

    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)

    # Adding unique related_name values
    groups = models.ManyToManyField(
        Group,
        related_name="customuser_groups",  # Unique related_name
        blank=True,
        help_text=_("The groups this user belongs to."),
        verbose_name=_("groups"),
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name="customuser_permissions",  # Unique related_name
        blank=True,
        help_text=_("Specific permissions for this user."),
        verbose_name=_("user permissions"),
    )

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email





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

class SubAdmin(AbstractUser):
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    plain_password = models.CharField(max_length=128, blank=True, null=True)  # Store plain-text password
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

    # Remove unused fields and override username to None
    username = None
    first_name = None
    last_name = None
    address = None
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['phone_number']

    def __str__(self):
        return self.email

class Payment(models.Model):
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Success', 'Success'),
        ('Failed', 'Failed'),
    ]

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    course = models.ForeignKey(PaidCourse, on_delete=models.CASCADE)
    first_name=models.CharField(max_length=100, null=True)
    transaction_id = models.CharField(max_length=100, unique=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='Pending')
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.user} - {self.course.course} - {self.status}"

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
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)  # Ensure it is linked to the user
    course = models.ForeignKey(PaidCourse, on_delete=models.CASCADE)
    content = models.ForeignKey(CourseContent, on_delete=models.CASCADE,default='',null=True)  # Track specific content
    completed = models.BooleanField(default=False)  # Track whether the content is completed

    def __str__(self):
        return f"{self.user} - {self.course} - {self.content} - {'Completed' if self.completed else 'Not Completed'}"



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


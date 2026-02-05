from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.utils.crypto import get_random_string
from django.contrib.auth import get_user_model
# Category
class Category(models.Model):
    category_name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.category_name
# Pet
GENDER_CHOICES = (
    ('Male', 'Male'),
    ('Female', 'Female'),
)
STATUS_CHOICES = (
    ('pending', 'Pending'),
    ('approved', 'Approved'),
    ('rejected', 'Rejected'),
    ('adopted', 'Adopted'),
)


class Pet(models.Model):
    name = models.CharField(max_length=100)
    category = models.ForeignKey(Category, on_delete=models.CASCADE)

    donor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="donated_pets",
        null=True,
        blank=True
    )
    
    buyer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="purchased_pets"
    )


    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending'   
    )

    description = models.TextField(blank=True, null=True)
    age = models.IntegerField(blank=True, null=True)
    breed = models.CharField(max_length=100, blank=True, null=True)
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES, blank=True, null=True)

    price = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        default=0
    )

    image = models.ImageField(upload_to='pets/', default='pets/default_pet.png')
    
    adopted_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name



class Adoption(models.Model):
    pet = models.ForeignKey(Pet, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    donor = models.ForeignKey(
    settings.AUTH_USER_MODEL,
    on_delete=models.CASCADE,
    null=True,
    blank=True,
    related_name="donor_adoptions"
)



    price = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    gst = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)

    status = models.CharField(
        max_length=20,
        choices=(('paid', 'Paid'), ('pending', 'Pending')),
        default='paid'
    )

    adopted_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.user.username} adopted {self.pet.name}"

class Donor(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    phone = models.CharField(max_length=15, blank=True)
    address = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)   
    photo = models.ImageField(
    upload_to='profile_photos/',
    blank=True,
    null=True
)

    def __str__(self):
        return self.user.name

from django.db import models
from django.conf import settings

class UserProfile(models.Model):
    GENDER_CHOICES = (
        ('Male', 'Male'),
        ('Female', 'Female'),
    )
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES, default='Male')
    phone = models.CharField(max_length=10, null=True, blank=True)
    age = models.IntegerField(null=True, blank=True)

    address = models.TextField(blank=True, null=True)
    photo = models.ImageField(
    upload_to='profile_photos/',
    blank=True,
    null=True
)
    def __str__(self):
     return self.user.username


ROLE_CHOICES = (
    ('BUYER', 'Buyer'),
    ('DONOR', 'Donor'),
)


class UserManager(BaseUserManager):

    def create_user(self, username, email, password=None, **extra_fields):
        if not username:
            raise ValueError("Username is required")
        if not email:
            raise ValueError("Email is required")

        email = self.normalize_email(email)

        user = self.model(
            username=username,
            email=email,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user


    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        return self.create_user(username, email, password, **extra_fields)


class UserModel(AbstractBaseUser, PermissionsMixin):

    user_code = models.CharField(max_length=20, unique=True, editable=False)

    full_name = models.CharField(max_length=150)
    username = models.CharField(max_length=100, unique=True)

    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=10, blank=True, null=True)

    gender = models.CharField(max_length=10, blank=True, null=True)
    age = models.IntegerField(blank=True, null=True)
    address = models.TextField(blank=True, null=True)

    photo = models.ImageField(upload_to='profile_photos/', blank=True, null=True)

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='BUYER')

    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email', 'full_name']

    objects = UserManager()

    def save(self, *args, **kwargs):
        if not self.user_code:
            self.user_code = "USR" + get_random_string(6, allowed_chars="0123456789")
        super().save(*args, **kwargs)

    def __str__(self):
        return self.username

User = get_user_model()

class Notification(models.Model):
    MESSAGE_TYPE = (
        ('donor_pet', 'Donor Added Pet'),
        ('pet_approved', 'Pet Approved'),
        ('adoption', 'Pet Adopted'),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    pet = models.ForeignKey('Pet', null=True, blank=True, on_delete=models.CASCADE) 
    message = models.TextField()
    type = models.CharField(max_length=50, choices=MESSAGE_TYPE)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.type} - {self.message[:20]}"


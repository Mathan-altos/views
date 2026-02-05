from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.contrib.auth import logout, update_session_auth_hash
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from .models import Category, Pet, Adoption, UserProfile
from .forms import PetDonationForm,  UserProfileForm
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import get_user_model
User = get_user_model()
from .models import Adoption
from .models import UserProfile, Donor
from django.contrib.auth import login as django_login
from django.contrib.auth.hashers import check_password
from .models import UserModel
from django.views.decorators.cache import never_cache
from decimal import Decimal 
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from .models import Notification
from django.http import JsonResponse
from django.contrib.admin.views.decorators import staff_member_required
import random
import string
import re


def home(request):
    return render(request, 'home.html')



def about(request):
    return render(request, 'about.html')


def contact(request):
    if request.method == "POST":
        name = request.POST.get('name')
        email = request.POST.get('email')
        message = request.POST.get('message')
        messages.success(request, "Thank you! We will contact you soon.")

    return render(request, 'contact.html')

def logout_view(request):
    logout(request)
    return redirect("user_login")

def user_login(request):
    error = None

    if request.method == "POST":
        login_input = request.POST.get("login", "").strip()
        password = request.POST.get("password", "").strip()

        if not login_input or not password:
            error = "All fields are required"
            return render(request, "auth/login.html", {"error": error})

        
        try:
            user_obj = UserModel.objects.get(username__iexact=login_input)
        except UserModel.DoesNotExist:
            try:
                user_obj = UserModel.objects.get(email__iexact=login_input)
            except UserModel.DoesNotExist:
                error = "Invalid username/email or password"
                return render(request, "auth/login.html", {"error": error})

       
        if not user_obj.is_active:
            error = "Account not approved by admin"
            return render(request, "auth/login.html", {"error": error})

        if not check_password(password, user_obj.password):
            error = "Invalid username/email or password"
            return render(request, "auth/login.html", {"error": error})

      
        django_login(request, user_obj)

        
        if user_obj.is_superuser:
            return redirect("admin_dashboard")
        elif getattr(user_obj, "role", "").upper() == "DONOR":
            return redirect("donor_dashboard")
        else:
            return redirect("user_dashboard")

    return render(request, "auth/login.html", {"error": error})

import re
from django.contrib import messages
from django.shortcuts import render
from django.contrib.auth import get_user_model
from .models import UserProfile, Notification

User = get_user_model()

def user_register(request):
    if request.method == "POST":
        full_name = request.POST.get("full_name")
        age = request.POST.get("age")
        username = request.POST.get("username")
        gender = request.POST.get("gender")
        phone = request.POST.get("phone")
        email = request.POST.get("email")
        address = request.POST.get("address")
        role = request.POST.get("role")
        photo = request.FILES.get("photo")

        form_data = request.POST
        errors = []

        # FULL NAME
        if not full_name:
            errors.append("Full name is required.")

        # AGE (18+)
        if not age:
            errors.append("Age is required.")
        else:
            try:
                age = int(age)
                if age < 18:
                    errors.append("You must be at least 18 years old to register.")
            except ValueError:
                errors.append("Enter a valid age.")

        # USERNAME
        if not username:
            errors.append("Username is required.")
        elif User.objects.filter(username=username).exists():
            errors.append("Username already exists.")

        # EMAIL
        if not email:
            errors.append("Email is required.")
        elif User.objects.filter(email=email).exists():
            errors.append("Email already registered.")
        elif not re.match(r"^[a-zA-Z0-9._%+-]+@gmail\.com$", email):
            errors.append("Enter a valid Gmail address.")

        # PHONE
        if not re.match(r"^\d{10}$", phone):
            errors.append("Phone must be 10 digits.")
        elif UserProfile.objects.filter(phone=phone).exists():
            errors.append("Phone number already exists.")

        # ROLE
        if role not in ["BUYER", "DONOR"]:
            errors.append("Invalid role selected.")

        # SHOW ERRORS
        if errors:
            return render(request, "auth/register.html", {
                "errors": errors,
                "form_data": form_data
            })

        # CREATE USER
        user = User.objects.create_user(
            username=username,
            email=email,
            password=None,  # or generate temporary password
            full_name=full_name,
            role=role,
            is_active=False
        )

        # CREATE PROFILE
        UserProfile.objects.create(
            user=user,
            age=age,
            gender=gender,
            phone=phone,
            address=address,
            photo=photo
        )

        # ADMIN NOTIFICATION
        admin = User.objects.filter(is_superuser=True).first()
        if admin:
            Notification.objects.create(
                user=admin,
                type="new_user",
                message=f"New user registered: {username}"
            )

        messages.success(
            request,
            "✅ Registration successful. Wait for admin approval."
        )

        return render(request, "auth/register.html", {"form_data": {}})

    return render(request, "auth/register.html")


#ADMIN
def admin_required(user):
    return user.is_superuser


@login_required
def admin_dashboard(request):

    notifications = Notification.objects.filter(
        user=request.user
    ).order_by("-created_at")

    unread_count = Notification.objects.filter(
        user=request.user,
        is_read=False
    ).count()

    total_users = User.objects.count()
    
    #Only approved pets
    total_pets = Pet.objects.filter(status="approved").count()
    
    #Only pending pets 
    pending_pets = Pet.objects.filter(status="pending").count()
    
    total_categories = Category.objects.count()

    context = {
        "notifications": notifications,
        "unread_count": unread_count,
        "total_users": total_users,
        "total_pets": total_pets,        
        "pending_pets": pending_pets,    
        "total_categories": total_categories,
    }

    return render(request, "admin/admin_dashboard.html", context)

@login_required
@user_passes_test(admin_required)
def view_adoptions(request):
    adoptions = Adoption.objects.select_related("user", "pet").order_by("-adopted_at")
    return render(request, "admin/view_adoptions.html", {"adoptions": adoptions})


@login_required
def adopt_pet(request, pet_id):
    pet = get_object_or_404(Pet, id=pet_id)

    #  Already adopted
    if pet.status == "adopted":
        messages.warning(request, "Pet already adopted.")
        return redirect("browse_pets")

    # Price calculation
    price = pet.price or Decimal("0")
    gst = price * Decimal("0.18")
    total = price + gst

    #  Create adoption record
    Adoption.objects.create(
        pet=pet,
        user=request.user,      
        donor=pet.donor,    
        price=price,
        gst=gst,
        total_amount=total,
        status="paid"
    )

    #  Update pet status AND set buyer
    pet.status = "adopted"
    pet.buyer = request.user
    pet.adopted_at = timezone.now()
    pet.save()   
    #  CREATE NOTIFICATIONS
    #  Notify ADMIN
    admins = User.objects.filter(is_superuser=True)
    for admin in admins:
        Notification.objects.create(
            user=admin,
            pet=pet,
            message=f"{pet.buyer.username} purchased pet '{pet.name}' from {pet.donor.username}",
            type="adoption"
        )
  #  Notify DONOR
    Notification.objects.create(
        user=pet.donor,
        pet=pet,
        message=f"{pet.buyer.username} purchased your pet '{pet.name}'",
        type="adoption"
    )
 # Notify BUYER
    Notification.objects.create(
        user=pet.buyer,
        pet=pet,
        message=f"You successfully adopted '{pet.name}' from {pet.donor.username}",
        type="adoption"
    )

    messages.success(request, "Pet adopted successfully!")
    return redirect("user_dashboard")

@login_required
@user_passes_test(lambda u: u.is_staff)
def admin_adoptions(request):
    adoptions = Adoption.objects.all().order_by("-adopted_at")
    return render(request, "admin/adoptions.html", {
        "adoptions": adoptions
    })


@login_required
@user_passes_test(admin_required)
def view_donated_pets(request):
    pets = Pet.objects.select_related("donor", "category").all()
    return render(request, "admin/view_donated_pets.html", {"pets": pets})

from django.db import IntegrityError
@login_required
@user_passes_test(admin_required)
def manage_categories(request):
    if request.method == "POST":
        category_name = request.POST.get("category_name", "").strip()

        if not category_name:
            messages.error(request, "Category name cannot be empty.")
            return redirect("manage_categories")

        try:
            Category.objects.create(category_name=category_name)
            messages.success(request, "Category added successfully.")
        except IntegrityError:
            messages.error(request, "Category already exists.")

        return redirect("manage_categories")

    categories = Category.objects.all()
    return render(request, "admin/manage_categories.html", {
        "categories": categories
    })


@login_required
@user_passes_test(admin_required)
def delete_category(request, category_id):
    category = get_object_or_404(Category, id=category_id)
    category.delete()
    messages.success(request, "Category deleted successfully")
    return redirect("manage_categories")

@login_required
@user_passes_test(admin_required)
def edit_category(request, category_id):
    category = get_object_or_404(Category, id=category_id)

    if request.method == "POST":
        new_name = request.POST.get("category_name", "").strip()

        if not new_name:
            messages.error(request, "Category name cannot be empty ❌")
        else:
            category.category_name = new_name
            try:
                category.save()
                messages.success(request, "Category updated successfully ")
                return redirect("manage_categories")
            except IntegrityError:
                # This triggers if the category name already exists
                messages.error(request, f"Category '{new_name}' already exists! ")

    return render(request, "admin/edit_category.html", {"category": category})

@login_required
@user_passes_test(admin_required)
def pending_pets(request):
    pets = Pet.objects.filter(status='pending')
    return render(request, "admin/pending_pets.html", {"pets": pets})

@login_required
@user_passes_test(admin_required)
def approve_pet(request, pet_id):
    pet = get_object_or_404(Pet, id=pet_id)
    pet.status = "approved"
    pet.save()

    # Notify the donor that their pet was approved
    Notification.objects.create(
        user=pet.donor,
        message=f"Your pet '{pet.name}' has been approved!",
        type='pet_approved'
    )

    #  Notify admin 
    Notification.objects.create(
        user=request.user,
        message=f"You approved pet '{pet.name}'.",
        type='pet_approved'
    )

    messages.success(request, "Pet approved successfully")
    return redirect("pending_pets")


@login_required
@user_passes_test(admin_required)
def reject_pet(request, pet_id):
    pet = get_object_or_404(Pet, id=pet_id)

    pet.status = 'rejected'
    pet.save()

    messages.error(request, "Pet rejected")

    return redirect("pending_pets")



# DONOR DASHBOARD
@login_required
def donor_dashboard(request):

    notifications = request.user.notifications.order_by('-created_at')
    unread_count = notifications.filter(is_read=False).count()
    latest_notification = notifications.filter(is_read=False).first()

    profile, _ = UserProfile.objects.get_or_create(
        user=request.user,
        defaults={
            'phone': '',
            'address': '',
            'age': 0
        }
    )

    pet_form = PetDonationForm()
    password_form = PasswordChangeForm(request.user)

    active_tab = request.GET.get("tab", "donate")

    if request.method == "POST":

      
        # DONATE PET
      
        if 'donate_pet' in request.POST:

            pet_form = PetDonationForm(request.POST, request.FILES)
            active_tab = "donate"

            if pet_form.is_valid():

                pet = pet_form.save(commit=False)
                pet.donor = request.user
                pet.status = 'pending'
                pet.save()

                # notify admins
                User = get_user_model()
                admins = User.objects.filter(is_superuser=True)

                for admin in admins:
                    Notification.objects.create(
                        user=admin,
                        pet=pet,
                        message=f"New pet '{pet.name}' donated by {request.user.username}",
                        type='donor_pet'
                    )

                messages.success(request, "✅ Pet donated successfully!")
                return redirect('donor_dashboard')

            else:
                messages.error(
                    request,
                    "❌ Please correct the errors below."
                )

        # CHANGE PASSWORD
       
        elif 'change_password' in request.POST:

            password_form = PasswordChangeForm(
                request.user,
                request.POST
            )
            active_tab = "password"

            if password_form.is_valid():

                new_password = password_form.cleaned_data['new_password1']

                strong_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$'

                if not re.match(strong_regex, new_password):

                    password_form.add_error(
                        'new_password1',
                        "Password must contain at least 8 characters, "
                        "uppercase, lowercase, number, and special symbol."
                    )

                    messages.error(
                        request,
                        "❌ Password does not meet security requirements."
                    )

                else:
                    password_form.save()
                    logout(request)

                    messages.success(
                        request,
                        "🔐 Password changed successfully. Please login again."
                    )
                    return redirect('user_login')

            else:
                messages.error(
                    request,
                    "❌ Please fix the password form errors."
                )

 
    # RENDER
   
    return render(request, 'donor/donor_dashboard.html', {
        'notifications': notifications,
        'unread_count': unread_count,
        'latest_notification': latest_notification,
        'pet_form': pet_form,
        'password_form': password_form,
        'active_tab': active_tab,
    })



@never_cache
@login_required
def user_dashboard(request):
    profile = UserProfile.objects.filter(user=request.user).first()

    # Get category from GET request
    category_query = request.GET.get('category', '').strip()

    # Only fetch pets if a category is selected
    pets = Pet.objects.none()
    if category_query:
        pets = Pet.objects.filter(
            status__in=['available', 'approved'],
            category__category_name__iexact=category_query
        )

    # Stats
    total_pets = Pet.objects.filter(status__in=['available', 'approved']).count()
    adopted_count = Adoption.objects.filter(user=request.user).exclude(adopted_at__isnull=True).count()
    pending_count = Adoption.objects.filter(user=request.user, adopted_at__isnull=True).count()
    favorite_pets_count = profile.favorites.count() if hasattr(profile, 'favorites') else 0

    # Notifications
    notifications = request.user.notifications.filter(is_read=False)
    notifications.update(is_read=True)

    # Calculate GST and total price for each pet
    pets_with_gst = []
    for pet in pets:
        gst = (pet.price * Decimal('0.18')).quantize(Decimal('0.01'))  
        total_price = (pet.price + gst).quantize(Decimal('0.01'))
        pets_with_gst.append({
            'pet': pet,
            'gst': gst,
            'total_price': total_price
        })

    return render(request, 'user/user_dashboard.html', {
        'profile_form': profile,
        'total_pets': total_pets,
        'adopted_pets_count': adopted_count,
        'pending_requests': pending_count,
        'favorite_pets_count': favorite_pets_count,
        'notifications': notifications,
        'category_query': category_query,
        'pets_with_gst': pets_with_gst,  
    })
@login_required
def view_pets(request):
    pets = Pet.objects.filter(status='approved')
    return render(request, 'user/view_pets.html', {'pets': pets})


@login_required
def pet_detail(request, pet_id):
    pet = get_object_or_404(Pet, id=pet_id)
    return render(request, 'user/pet_detail.html', {'pet': pet})



@login_required
def pet_list(request):
    pets = Pet.objects.filter(status='approved')
    return render(request, 'app/pet_list.html', {'pets': pets})
@login_required
def my_adoptions(request):
    # Get adoptions for current user
    adoptions = Adoption.objects.filter(user=request.user).select_related('pet')
    
    return render(request, 'user/my_adopted_pets.html', {'adoptions': adoptions})

@login_required
def user_change_password(request):
    if request.method == "POST":
        form = PasswordChangeForm(request.user, request.POST)

        if form.is_valid():
            new_password = form.cleaned_data.get('new_password1')

            
            strong_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$'
            if not re.match(strong_regex, new_password):
                form.add_error(
                    'new_password1',
                    "Password must be at least 8 characters and include uppercase, lowercase, number, and special character."
                )
            else:
                form.save()  
                logout(request)  
                messages.success(request, "Password changed successfully! Please login again.")
                return redirect("user_login")  
    else:
        form = PasswordChangeForm(request.user)

    return render(request, "user/changepassword.html", {"form": form})

# ADMIN PROFILE
@login_required
def admin_profile(request):
    user = request.user

    if request.method == "POST":
        full_name = request.POST.get("full_name", "").strip()
        email = request.POST.get("email", "").strip()
        photo = request.FILES.get("photo")

        # VALIDATION
        if not full_name:
            messages.error(request, "Full name is required.")
            return redirect("admin_profile")

        if not email:
            messages.error(request, "Email is required.")
            return redirect("admin_profile")

        try:
            validate_email(email)
        except ValidationError:
            messages.error(request, "Enter a valid email address.")
            return redirect("admin_profile")

        #DUPLICATE EMAIL CHECK
        if User.objects.filter(email=email).exclude(id=user.id).exists():
            messages.error(request, "This email is already used by another account.")
            return redirect("admin_profile")

        #PHOTO VALIDATION
        if photo:
            if not photo.content_type.startswith("image"):
                messages.error(request, "Only image files are allowed.")
                return redirect("admin_profile")

            if photo.size > 2 * 1024 * 1024:
                messages.error(request, "Image size must be under 2MB.")
                return redirect("admin_profile")

        #SAVE USER
        user.full_name = full_name
        user.email = email

        if photo:
            if user.photo:
                user.photo.delete(save=False)
            user.photo = photo

        user.save()

        messages.success(request, "Profile updated successfully.")
        return redirect("admin_profile")

    return render(request, "admin/admin_profile.html")

@login_required
@user_passes_test(lambda u: u.is_superuser)
def admin_change_password(request):
    if request.method == "POST":
        old_password = request.POST.get("old_password")
        new_password = request.POST.get("new_password")
        confirm_password = request.POST.get("confirm_password")

        user = request.user

        if not user.check_password(old_password):
            messages.error(request, "Old password is incorrect")
            return redirect("admin_change_password")

        if new_password != confirm_password:
            messages.error(request, "New passwords do not match")
            return redirect("admin_change_password")

        if len(new_password) < 8:
            messages.error(request, "Password must be at least 8 characters")
            return redirect("admin_change_password")

        
        user.set_password(new_password)
        user.save()

        
        logout(request)

        messages.success(request, "Password changed successfully. Please log in again.")
        return redirect("user_login")  #

    return render(request, "admin/admin_change_password.html")


def manage_users(request):
    users = User.objects.all()
    return render(request, 'manage_users.html', {'users': users})

@login_required
@user_passes_test(lambda u: u.is_superuser)
def delete_pet(request, pet_id):
    pet = get_object_or_404(Pet, id=pet_id)
    pet.delete()
    messages.success(request, f"Pet '{pet.name}' has been deleted successfully!")
    return redirect('view_donated_pets')  

@login_required
def my_pets(request):
    pets = Pet.objects.filter(donor=request.user).select_related('category')
    return render(request, 'donor/my_pets.html', {'pets': pets})

@login_required
def browse_pets(request):
    pets = Pet.objects.filter(status='approved')  
    return render(request, 'user/browse_pets.html', {
        'pets': pets
    })


import re
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
from .models import UserProfile

User = get_user_model()


@login_required
def donor_profile(request):
    user = request.user
    profile, _ = UserProfile.objects.get_or_create(user=user)

    if request.method == "POST":

        full_name = request.POST.get("full_name", "").strip()
        username = request.POST.get("username", "").strip()
        email = request.POST.get("email", "").strip()
        age = request.POST.get("age", "").strip()
        gender = request.POST.get("gender", "").strip()
        phone = request.POST.get("phone", "").strip()
        address = request.POST.get("address", "").strip()
        photo = request.FILES.get("photo")

        valid = True

        # ================= FULL NAME =================
        if not full_name:
            messages.error(request, "Full name is required.")
            valid = False

        # ================= USERNAME =================
        if not username:
            messages.error(request, "Username is required.")
            valid = False
        elif User.objects.filter(username=username).exclude(id=user.id).exists():
            messages.error(request, "Username already exists.")
            valid = False

        # ================= EMAIL =================
        if not email:
            messages.error(request, "Email is required.")
            valid = False
        elif User.objects.filter(email__iexact=email).exclude(id=user.id).exists():
            messages.error(request, "Email already exists.")
            valid = False

        # ================= AGE =================
        if not age:
            messages.error(request, "Age is required.")
            valid = False
        else:
            try:
                age_int = int(age)
                if age_int < 18 or age_int > 120:
                    messages.error(request, "Age must be between 18 and 120.")
                    valid = False
            except ValueError:
                messages.error(request, "Age must be a valid number.")
                valid = False

        # ================= PHONE =================
        if not phone:
            messages.error(request, "Phone number is required.")
            valid = False
        elif not re.match(r"^\d{10}$", phone):
            messages.error(request, "Phone must be exactly 10 digits.")
            valid = False
        elif UserProfile.objects.filter(phone=phone).exclude(user=user).exists():
            messages.error(request, "Phone number already exists.")
            valid = False

        # ================= ADDRESS =================
        if not address:
            messages.error(request, "Address is required.")
            valid = False

        # ================= GENDER =================
        if gender not in ["Male", "Female"]:
            messages.error(request, "Select gender.")
            valid = False

        if not valid:
            return redirect("donor_profile")

        # ================= SAVE USER =================
        user.full_name = full_name
        user.username = username
        user.email = email
        user.save()

        # ================= SAVE PROFILE =================
        profile.age = age_int
        profile.gender = gender
        profile.phone = phone
        profile.address = address

        if photo:
            profile.photo = photo

        profile.save()

        messages.success(request, "Profile updated successfully.")
        return redirect("donor_profile")

    return render(request, "donor/profile.html", {
        "user": user,
        "profile": profile
    })


import re
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
from .models import UserProfile

User = get_user_model()


@login_required
def user_profile(request):
    profile, _ = UserProfile.objects.get_or_create(user=request.user)

    if request.method == "POST":

        full_name = request.POST.get("full_name", "").strip()
        username = request.POST.get("username", "").strip()
        age = request.POST.get("age", "").strip()
        email = request.POST.get("email", "").strip()
        gender = request.POST.get("gender", "")
        phone = request.POST.get("phone", "").strip()
        address = request.POST.get("address", "").strip()
        photo = request.FILES.get("photo")

        valid = True

        # ================= FULL NAME (last name optional) =================
        if not full_name:
            messages.error(request, "Full name is required.")
            valid = False
        else:
            parts = full_name.split(" ", 1)
            first_name = parts[0]
            last_name = parts[1] if len(parts) > 1 else ""

        # ================= USERNAME =================
        if not username:
            messages.error(request, "Username is required.")
            valid = False
        elif User.objects.filter(username__iexact=username).exclude(id=request.user.id).exists():
            messages.error(request, "Username already exists.")
            valid = False

        # ================= AGE =================
        if not age:
            messages.error(request, "Age is required.")
            valid = False
        else:
            try:
                age = int(age)
                if age < 18 or age > 120:
                    messages.error(request, "Age must be between 18 and 120.")
                    valid = False
            except:
                messages.error(request, "Invalid age.")
                valid = False

        # ================= EMAIL =================
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            messages.error(request, "Enter a valid email.")
            valid = False
        elif User.objects.filter(email__iexact=email).exclude(id=request.user.id).exists():
            messages.error(request, "Email already exists.")
            valid = False

        # ================= PHONE =================
        if not re.match(r"^\d{10}$", phone):
            messages.error(request, "Phone must be 10 digits.")
            valid = False
        elif UserProfile.objects.filter(phone=phone).exclude(user=request.user).exists():
            messages.error(request, "Phone number already exists.")
            valid = False

        # ================= ADDRESS =================
        if not address:
            messages.error(request, "Address is required.")
            valid = False

        if not valid:
            return redirect("user_profile")

        # ================= SAVE USER =================
        user = request.user
        user.username = username
        user.full_name = first_name
        user.email = email
        user.save()

        # ================= SAVE PROFILE =================
        profile.age = age
        profile.gender = gender
        profile.phone = phone
        profile.address = address

        if photo:
            profile.photo = photo

        profile.save()

        messages.success(request, "Profile updated successfully.")
        return redirect("user_profile")

    return render(request, "user/profile.html", {"profile": profile})



@login_required
def profile_update(request):
    user = request.user

    # profile to use based on group
    if user.groups.filter(name='Donor').exists():
        profile, created = Donor.objects.get_or_create(user=user)
        template_path = 'donor/profile.html'
    else:
        profile, created = UserProfile.objects.get_or_create(user=user)
        template_path = 'user/profile.html'

    if request.method == 'POST':
        # Common fields
        if hasattr(profile, 'phone'):
            profile.phone = request.POST.get('phone', profile.phone)
        if hasattr(profile, 'address'):
            profile.address = request.POST.get('address', profile.address)
        if hasattr(profile, 'gender'):
            profile.gender = request.POST.get('gender', profile.gender)

        # Profile image
        if 'image' in request.FILES:
            if hasattr(profile, 'image'):
                profile.image = request.FILES['image']
            elif hasattr(profile, 'profile_photo'):
                profile.profile_photo = request.FILES['image']

        profile.save()
        messages.success(request, 'Profile updated successfully!')
        return redirect('profile_update')

    return render(request, template_path, {'profile': profile})

def admin_users(request):
    users = User.objects.select_related('userprofile')
    return render(request, 'admin_users.html', {'users': users})

def admin_donors(request):
    donors = Donor.objects.select_related('user')
    return render(request, 'admin_donors.html', {'donors': donors})


@login_required
@user_passes_test(admin_required)
def users_list(request):
    users = User.objects.filter(is_superuser=False)
    return render(request, "admin/users.html", {"users": users})

@login_required
def edit_profile(request):
    profile = request.user.profile  
    if request.method == 'POST':
        form = UserProfileForm(request.POST, request.FILES, instance=profile)
        if form.is_valid():
            form.save()
            return redirect('home') 
    else:
        form = UserProfileForm(instance=profile)

    return render(request, 'edit_profile.html', {'form': form})

@login_required
@user_passes_test(admin_required)
def admin_adoptions(request):
    adoptions = Adoption.objects.select_related('user', 'pet').order_by('-adopted_at')

    return render(request, 'admin/adoptions.html', {
        'adoptions': adoptions
    })

def is_admin(user):
    return user.is_superuser

@login_required
@user_passes_test(lambda u: u.is_superuser)
def admin_user_list(request):
    users = UserModel.objects.filter(
        is_active=False,      
        is_superuser=False,
        is_staff=False
    ).order_by('-created_at')

    return render(request, 'admin/user_list.html', {
        'users': users
    })

def generate_numeric_password(length=6):
    return ''.join(random.choices(string.digits, k=length))

@login_required
@user_passes_test(lambda u: u.is_superuser)
def approve_user(request, user_id):

    user = get_object_or_404(UserModel, id=user_id)

    if user.is_active:
        messages.warning(request, "User already approved.")
        return redirect('admin_user_list')

    raw_password = ''.join(random.choices(string.digits, k=6))

    user.set_password(raw_password)
    user.is_active = True
    user.save()

    send_mail(
        subject="Account Approved",
        message=f"""
Hello {user.full_name},

Your account has been approved.

Login details:
Username: {user.username}
Password: {raw_password}

Please login and change your password immediately.
""",
        from_email=settings.EMAIL_HOST_USER,
        recipient_list=[user.email],
        fail_silently=False
    )

    messages.success(request, f"User {user.username} approved successfully.Login details will be sent to your email.")
    return redirect('admin_user_list')

@login_required
@user_passes_test(lambda u: u.is_superuser)
def disapprove_user(request, user_id):
    if request.method != "POST":
        messages.error(request, "Invalid request method.")
        return redirect('admin_user_list')

    user = get_object_or_404(UserModel, id=user_id)

    if user.is_active:
        messages.error(request, "Cannot disapprove an already approved user.")
        return redirect('admin_user_list')

    # Store info before deleting
    full_name = getattr(user, 'full_name', user.username)
    email = user.email

    # Delete user
    user.delete()
    messages.success(request, f"User '{full_name}' disapproved and removed.")

    # Send email notification
    if email:
        subject = "Your account has been disapproved"
        message = (
            f"Hello {full_name},\n\n"
            "We regret to inform you that your account has been disapproved and removed from our system.\n"
            "If you have any questions, please contact our support team.\n\n"
            "Thank you,\nPet Adoption Team"
        )
        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,  # Make sure this is set in settings.py
                [email],
                fail_silently=False,
            )
        except Exception as e:
            # Optional: log the error
            messages.warning(request, f"User disapproved but email could not be sent: {str(e)}")

    return redirect('admin_user_list')
def users_list(request):
    role = request.GET.get('role')  
    if role in ['DONOR', 'BUYER']:
        users = UserModel.objects.filter(role=role)
    else:
        users = UserModel.objects.all()

    return render(request, 'admin/users_list.html', {
        'users': users,
        'selected_role': role
    })

def donor_profiles(request):
    users = UserModel.objects.filter(
        role='DONOR',
        is_active=True,
        is_superuser=False,
        is_staff=False
    ).select_related('userprofile')

    # Ensure profile exists
    for user in users:
        UserProfile.objects.get_or_create(user=user)

    return render(request, 'admin/donor_profiles.html', {'users': users})


def buyer_profiles(request):
    users = UserModel.objects.filter(
        role='BUYER',
        is_active=True,   
        is_superuser=False,
        is_staff=False
    )
    return render(request, 'admin/buyer_profiles.html', {'users': users})

@login_required
@user_passes_test(lambda u: u.is_superuser)
def delete_user(request, user_id):
    user = get_object_or_404(UserModel, id=user_id, is_superuser=False)  
    full_name = getattr(user, 'full_name', user.username)  
    user.delete()
    messages.success(request, f"User '{full_name}' deleted successfully!")
    return redirect(request.META.get('HTTP_REFERER', '/admin-dashboard/users/'))

def purchase_pet(request, pet_id):
    pet = Pet.objects.get(id=pet_id)
    buyer = request.user

    # Create adoption object
    adoption = Adoption.objects.create(
        pet=pet,
        user=buyer,
        donor=pet.donor,
        price=pet.price,
        gst=0,  
        total_amount=pet.price,
        status='paid'
    )
    #notification for admin 
    admin_users = User.objects.filter(is_superuser=True)
    for admin in admin_users:
        Notification.objects.create(
            user=admin,
            pet=pet,
            message=f"{buyer.username} purchased {pet.name}",
            type='adoption'
        )
    #notify donor
    if pet.donor:
        Notification.objects.create(
            user=pet.donor,
            pet=pet,
            message=f"{buyer.username} purchased your pet: {pet.name}",
            type='adoption'
        )
    pet.status = 'adopted'
    pet.adopted_at = timezone.now()
    pet.save()

    return redirect('some_success_page')

@login_required
def mark_notification_read(request, noti_id):
    notification = get_object_or_404(
        Notification,
        id=noti_id,
        user=request.user
    )

    notification.is_read = True
    notification.save()

    next_url = request.GET.get("next")
    if next_url:
        return redirect(next_url)

    return redirect("admin_dashboard")
@login_required
def mark_donor_notifications_read(request):
    request.user.notifications.filter(is_read=False).update(is_read=True)
    return JsonResponse({"status": "ok"})
    
@staff_member_required
def available_approved_pets(request):

    pets = Pet.objects.filter(status__iexact='approved').select_related('category', 'donor')

    context = {
        'pets': pets
    }
    return render(request, 'admin/available_approved_pets.html', context)

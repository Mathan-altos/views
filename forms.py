from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserChangeForm, PasswordChangeForm as DjangoPasswordChangeForm
from django.core.exceptions import ValidationError
from .models import Pet, UserProfile
User = get_user_model()

class PetDonationForm(forms.ModelForm):

    class Meta:
        model = Pet
        fields = [
            'name', 'category', 'gender', 'description',
            'age', 'breed', 'price', 'image'
        ]
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'category': forms.Select(attrs={'class': 'form-select'}),
            'gender': forms.Select(attrs={'class': 'form-select'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
            'age': forms.NumberInput(attrs={'class': 'form-control'}),
            'breed': forms.TextInput(attrs={'class': 'form-control'}),
            'price': forms.NumberInput(attrs={'class': 'form-control'}),
            'image': forms.ClearableFileInput(attrs={'class': 'form-control'}),
        }

    # Pet 
    def clean_name(self):
        name = self.cleaned_data.get('name')
        if not name:
            raise ValidationError("Pet name is required.")
        if len(name) < 2:
            raise ValidationError("Pet name must contain at least 2 characters.")
        return name

    
    def clean_age(self):
        age = self.cleaned_data.get('age')
        if age is None:
            raise ValidationError("Pet age is required.")
        if age < 0 or age > 30:
            raise ValidationError("Pet age must be between 0 and 30.")
        return age

    
    def clean_price(self):
        price = self.cleaned_data.get('price')
        if price is None:
            raise ValidationError("Price is required.")
        if price < 0:
            raise ValidationError("Price cannot be negative.")
        return price

    
    def clean_description(self):
        description = self.cleaned_data.get('description')
        if len(description) < 10:
            raise ValidationError("Description must be at least 20 characters.")
        return description

   


class UserRegisterForm(forms.ModelForm):

    class Meta:
        model = User
        fields = ['full_name', 'username', 'email', 'role']

        widgets = {
            'full_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Full Name'
            }),

            'username': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Username'
            }),

            'email': forms.EmailInput(attrs={
                'class': 'form-control',
                'placeholder': 'Email'
            }),

            'role': forms.Select(attrs={
                'class': 'form-control'
            }),
        }

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exists():
            raise ValidationError("Username already exists")
        return username

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise ValidationError("Email already registered")
        return email


class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['gender', 'phone', 'age', 'address', 'photo']

        widgets = {
            'gender': forms.RadioSelect(),
            'phone': forms.TextInput(attrs={'class': 'form-control'}),
            'age': forms.NumberInput(attrs={'class': 'form-control'}),
            'address': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }

    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        if phone and (not phone.isdigit() or len(phone) != 10):
            raise ValidationError("Phone number must be 10 digits")
        return phone

class UserUpdateForm(UserChangeForm):
    password = None  

    class Meta:
        model = User
        fields = ['full_name', 'username', 'email']

        widgets = {
            'full_name': forms.TextInput(attrs={'class': 'form-control'}),
            'username': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
        }

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.exclude(pk=self.instance.pk).filter(email=email).exists():
            raise ValidationError("Email already in use")
        return email




class PasswordChangeForm(DjangoPasswordChangeForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        
        for field_name in ['old_password', 'new_password1', 'new_password2']:
            self.fields[field_name].widget.attrs.update({
                'class': 'form-control password-input'
            })

class AdminProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['photo']

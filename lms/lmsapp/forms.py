from django import forms
from .models import Ticket

class TicketForm(forms.ModelForm):
    class Meta:
        model = Ticket
        fields = ["subject", "description"]




from captcha.fields import CaptchaField

class CaptchaForm(forms.Form):
    captcha = CaptchaField()

class LoginForm(forms.Form):
    identifier = forms.CharField(label="Email or Mobile Number", required=True)
    password = forms.CharField(widget=forms.PasswordInput, required=True)
    captcha = CaptchaField()


from captcha.fields import CaptchaField
from django import forms

class SignupForm(forms.Form):
    first_name = forms.CharField(max_length=100)
    last_name = forms.CharField(max_length=100)
    email = forms.EmailField()
    mobile = forms.CharField(max_length=10)
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)
    captcha = CaptchaField()  # 👈 Important!


# class LoginForm(forms.Form):
#     email_or_mobile = forms.CharField(
#         label='Email or Mobile Number',
#         required=True,
#         widget=forms.TextInput(attrs={'placeholder': 'Enter Email or Mobile'})
#     )
#     password = forms.CharField(
#         widget=forms.PasswordInput(attrs={'placeholder': 'Enter Password'}),
#         required=True
#     )
#     captcha = CaptchaField()

from django import forms
from .models import Ticket

class TicketForm(forms.ModelForm):
    class Meta:
        model = Ticket
        fields = ["subject", "description"]




from captcha.fields import CaptchaField

class LoginForm(forms.Form):
    identifier = forms.CharField(label="Email or Mobile Number", required=True)
    password = forms.CharField(widget=forms.PasswordInput, required=True)
    captcha = CaptchaField()


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

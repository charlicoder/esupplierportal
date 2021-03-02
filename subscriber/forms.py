from django import forms 
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.utils.text import capfirst

class RegistrationForm(forms.Form):
    """
    Registration Form
    """
    first_name = forms.CharField(required=True, max_length=255)
    email = forms.EmailField(required=True)

    def __init__(self, request=None, *args, **kwargs):
        super(RegistrationForm, self).__init__(*args, **kwargs)

        self.fields['first_name'].widget = forms.TextInput(
            attrs={
            'class': 'form-control placeholder-no-fix',
            'autocomplete': 'off',
            'placeholder': 'Name'
        })

        self.fields['email'].widget = forms.EmailInput(
            attrs={
                'class': 'form-control placeholder-no-fix',
                'placeholder': 'Email'
            }
        )

    def clean_email(self):
        """
        Validating email address
        """
        email = self.cleaned_data['email']

        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("The email address is already in use")
        return email

    def save(self, send_email=True):
        """
        Save user and generate activation code..
        """
        email_sent = False

        activation_code, created = RegisterNowActivationCode.objects.get_or_create(
            email=self.cleaned_data['email'],
            defaults={
                'first_name': self.cleaned_data['first_name'],
                'code':md5(str(uuid.uuid4())).hexdigest()
            }
        )
        
        if created:
            email_sent = activation_code.send_email()

        if not created and activation_code.is_expired:
            activation_code.expire_data = datetime.now()+timedelta(days=2)
            activation_code.save()
            email_sent = activation_code.send_email()
        
        

        return email_sent


class CreateUserAccount(UserCreationForm):
    """
    This use by the flow of registration landing page form and supported for
    RegisterNowActivationCode data
    """
    profile_image = forms.ImageField()
    phone = forms.CharField(label="Phone",)

    class Meta:
        model = User
        fields = ("first_name", "username", "email", "password1", "password2",
                  "profile_image", 'phone'
                  )

    def __init__(self, request=None, *args, **kwargs):
        self.request = kwargs.pop('request', None)
        super(CreateUserAccount, self).__init__(*args, **kwargs)

        self.fields['first_name'].widget = forms.HiddenInput(
            attrs={
                   'class': 'form-control placeholder-no-fix',
                   'autocomplete': 'off',
                   'placeholder': 'Name'
                   })

        self.fields['username'].widget = forms.TextInput(
            attrs={
                'class': 'form-control placeholder-no-fix',
                'autocomplete': 'off',
                'placeholder': 'Username'
            }
        )
        self.fields['email'].widget = forms.HiddenInput(
            attrs={
                'class': 'form-control placeholder-no-fix',
                'placeholder': 'Email'
            }
        )
        self.fields['password1'].widget = forms.PasswordInput(
            attrs={
                'class': 'form-control placeholder-no-fix',
                'autocomplete': 'off',
                'placeholder': 'Password'
            }
        )
        self.fields['password2'].widget = forms.PasswordInput(
            attrs={
                'class': 'form-control placeholder-no-fix',
                'autocomplete': 'off',
                'placeholder': 'Repeat the password'
            }
        )
        self.fields['phone'].widget = forms.TextInput(
            attrs={
                'class': 'form-control placeholder-no-fix',
                'autocomplete': 'off',
                'placeholder': 'Enter phone with country code'
            }
        )

    def save(self, send_email=False):
        # creating user without email activation...
        return super(CreateUserAccount, self).save(send_email)


class AuthenticationForm(forms.Form):
    """
    Login form, Subscribers
    """
    username = forms.CharField(max_length=254)
    password = forms.CharField(widget=forms.PasswordInput)

    error_messages = {
        'invalid_username': 'User does not exists',
        'invalid_login': 'Please enter a correct username and password, Note that both fields may be case-sensitive.',
        'inactive': 'this account is inactive, you need confirm your email'
    }

    def __init__(self, request=None, *args, **kwargs):
        """
        The 'request' parameter is set for custom auth use by subclasses.
        The form data comes in via the standard 'data' kwarg.
        """
        self.request = request
        self.user_cache = None
        super(AuthenticationForm, self).__init__(*args, **kwargs)

        UserModel = get_user_model()

        self.username_field = UserModel._meta.get_field(UserModel.USERNAME_FIELD)

        self.fields['username'].widget = forms.TextInput(
            attrs={
                'class': 'form-control form-control-solid placeholder-no-fix',
                'placeholder': 'Username',
                'autocomplete': 'off'
            }
        )

        self.fields['password'].widget = forms.PasswordInput(
            attrs={
                'class': 'form-control form-control-solid placeholder-no-fix',
                'autocomplete': 'off',
                'placeholder': 'Password'
            }
        )

        if self.fields['username'].label is None:
            self.fields['username'].label = capfirst(self.username_field.verbose_name)

    def clean(self):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')

        UserModel = get_user_model()

        # if user does not exists
        if not UserModel.objects.filter(username=username):
            raise forms.ValidationError(
                self.error_messages['invalid_username'],
                code='invalid_login',
            )

        if username and password:
            self.user_cache = authenticate(username=username,
                                           password=password)
            if self.user_cache is None:
                raise forms.ValidationError(
                    self.error_messages['invalid_login'],
                    code='invalid_login',
                )
            else:
                self.confirm_login_allowed(self.user_cache)

        return self.cleaned_data

    def confirm_login_allowed(self, user):
        """
        Controls whether the given User may log in.
        """
        if not user.is_active:
            raise forms.ValidationError(
                self.error_messages['inactive'],
                code='inactive',
            )

    def get_user_id(self):
        if self.user_cache:
            return self.user_cache.id
        return None

    def get_user(self):
        return self.user_cache


class PasswordResetForm(forms.Form):
    """
    Reset password
    """
    email = forms.EmailField(max_length=200)

    def __init__(self, *args, **kwargs):
        super(PasswordResetForm, self).__init__(*args, **kwargs)

        self.fields['email'].widget = forms.EmailInput(
            attrs={
                'class': "form-control placeholder-no-fix",
                'autocomplete': "off",
                'placeholder': 'Type your email here'
            }
        )

    def clean_email(self):
        """
        Validating email address
        """
        email = self.cleaned_data['email']

        if not User.objects.filter(email=email).exists():
            raise forms.ValidationError("Account does not exist with this email.")
        return email


class PasswordChangeForm(forms.Form):
    """
    Password reset form
    """
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)


class VerifyOtpForm(forms.Form):
    """
    Reset password
    """
    otp = forms.CharField(max_length=200)

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request', None)
        super(VerifyOtpForm, self).__init__(*args, **kwargs)
        self.fields['otp'].widget = forms.TextInput(
            attrs={
                'class': 'form-control form-control-solid placeholder-no-fix',
                'placeholder': 'Enter otp',
                'autocomplete': 'off'
            }
        )

    def clean_otp(self):
        """
        Validating email address
        """
        otp = self.cleaned_data['otp']

        phone_num = self.request.user.userprofile.phone
        results = verify_otp(self.request, phone_num, otp)
        results = results['results']
        if not results['status']:
            raise forms.ValidationError(results['msg'])
        return otp
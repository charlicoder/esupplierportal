from django.shortcuts import render
from django.views.generic import FormView
from django.views.generic.base import View
from django.views.generic import TemplateView
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.csrf import csrf_protect
from subscriber.forms import VerifyOtpForm, AuthenticationForm, CreateUserAccount, PasswordResetForm, RegistrationForm
# Create your views here.

def supplier_logout(request):
    auth.logout(request)
    return HttpResponseRedirect(reverse('subscriber:login'))
    
class ResetPasswordFormView(FormView):
    """
    Reset password form view...
    """
    form_class = PasswordResetForm
    template_name = 'subscriber/forget_password.html'

    def form_valid(self, form):
        """
        Form valid...
        """
        email = form.cleaned_data.get('email')
        user = User.objects.get(email=email)

        activation_code = md5(str(uuid.uuid4())).hexdigest()

        code = ActivationCode.objects.create(
            code=activation_code,
            user=user,
            creation_date=datetime.now(),
            code_for=1,
            status=0
        )
        email_message = NewEmail(template='password_reset',
                                 context={'user': user,
                                          'reset_code': code.code,
                                          'request': self.request
                                          },
                         subject='Account password reset', to=email
                         )
        email_message.send()

        return render(self.request,
                      'subscriber/notifications/forget_password.html',
                      {'email_sent': True, 'email': email}
                      )


class ContinueRegistrationFormView(FormView):
    """
    Finish the registration flow, the flow started from LandingPage Registration
    """
    form_class = CreateUserAccount
    template_name = 'subscriber/continue_registration.html'

    def __init__(self, *args, **kwargs):
        self.activation_code = None
        return super(ContinueRegistrationFormView, self).__init__(*args, **kwargs)

    def dispatch(self, *args, **kwargs):
        if self.request.method == 'GET':

            self.activation_code = RegisterNowActivationCode.objects.get(
                code=self.kwargs.get('activation_code')
            )
            if self.activation_code.is_expired:
                return HttpResponseRedirect(reverse('registration'))

        return super(ContinueRegistrationFormView, self).dispatch(*args, **kwargs)

    def get_initial(self):
        self.activation_code = RegisterNowActivationCode.objects.get(
                code=self.kwargs.get('activation_code')
            )
        return dict(
            first_name=self.activation_code.first_name,
            email=self.activation_code.email
        )

    def get_context_data(self, **kwargs):
        context = super(ContinueRegistrationFormView, self).get_context_data(**kwargs)
        context['activation_code'] = self.activation_code.code

        return context

    def form_valid(self, form):
        form.cleaned_data['first_name'] = self.activation_code.first_name
        form.cleaned_data['email'] = self.activation_code.email
        user_created = form.save()
        user_created.is_active = True
        user_created.save()

        #New user profile creation
        usr_profile, created = UserProfile.objects.get_or_create(user=user_created)
        usr_profile.profile_image = form.cleaned_data['profile_image']
        usr_profile.phone = form.cleaned_data['phone']
        usr_profile.save() 

        # automatic authentication and redirect!!

        user_created.backend = 'django.contrib.auth.backends.ModelBackend'
        auth.login(self.request, user_created)
        self.activation_code.delete()
        send_otp(phone_number=usr_profile.phone)
        return HttpResponseRedirect('/supplier/')

class RegistrationFormView(FormView):
    """
    Registration Form View...
    """
    form_class = RegistrationForm
    redirect_field_name = REDIRECT_FIELD_NAME
    template_name = 'subscriber/register.html'

    # @method_decorator(csrf_protect)
    # @method_decorator(never_cache)
    # def dispatch(self, *args, **kwargs):
    #     return super(RegistrationFormView, self).dispatch(*args, **kwargs)
    
    # def post(self, request, *args, **kwargs):
    #     """
    #     Handles POST requests, instantiating a form instance with the passed
    #     POST variables and then checked for validity.
    #     """
    #     form = self.get_form()
    #     if form.is_valid():
    #         return self.form_valid(form)
    #     else:
    #         return self.form_invalid(form)

    def form_valid(self, form):
        # create new user
        email_sent = form.save()

        context = self.get_context_data()
        context['first_name'] = form.cleaned_data['first_name']
        context['email'] = form.cleaned_data['email']
        context['email_sent'] = email_sent

        return render(self.request, 'subscriber/notifications/confirmation-sent.html', context)


class SupplierLoginFormView(FormView):
    """
    Supplier Login View
    """
    form_class = AuthenticationForm
    redirect_field_name = REDIRECT_FIELD_NAME
    template_name = 'subscriber/login.html'
    success_url = '/supplier/'

    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def dispatch(self, *args, **kwargs):
        return super(SupplierLoginFormView, self).dispatch(*args, **kwargs)

    def form_valid(self, form):
        """
        The user has provided valid credentials (this was checked in AuthenticationForm.is_valid()). So now we
        can check the test cookie stuff and log him in.
        :param form:
        :return:
        """
        self.check_and_delete_test_cookie()
        login(self.request, form.get_user())
        send_otp(phone_number=self.request.user.userprofile.phone)
        return super(SupplierLoginFormView, self).form_valid(form)

    def form_invalid(self, form):
        """
        The user has provided invalid credentials (this was checked in AuthenticationForm.is_valid()). So now we
        set the test cookie again and re-render the form with errors.
        :param form:
        :return:
        """
        self.set_test_cookie()
        return super(SupplierLoginFormView, self).form_invalid(form)

    def get_success_url(self):
        if self.success_url:
            redirect_to = self.success_url
        else:
            redirect_to = self.request.REQUEST.get(self.redirect_field_name, '')

        netloc = urlparse.urlparse(redirect_to)[1]
        if not redirect_to:
            redirect_to = resolve_url(settings.LOGIN_REDIRECT_URL)
        # Security check -- don't allow redirection to a different host.
        elif netloc and netloc != self.request.get_host():
            redirect_to = resolve_url(settings.LOGIN_REDIRECT_URL)
        return redirect_to

    def set_test_cookie(self):
        self.request.session.set_test_cookie()

    def check_and_delete_test_cookie(self):
        if self.request.session.test_cookie_worked():
            self.request.session.delete_test_cookie()
            return True
        return False

    def get(self, request, *args, **kwargs):
        """
        Same as django.views.generic.edit.ProcessFormView.get(), but adds test cookie stuff
        """
        self.set_test_cookie()
        return super(SupplierLoginFormView, self).get(request, *args, **kwargs)



class UserOppurtunityPreferenceView(View):

    def post(self, request, *args, **kwargs):
        user_pref = request.user.userprofile.user_preferences
        if not user_pref:
            user_pref = {} 
        opp_preferences = {}

        if request.POST.get('set_aside_all'):
            opp_preferences['oppurtunity_options'] = "all"
        elif request.POST.getlist('oprotunity_options'):
            opp_preferences['oppurtunity_options'] = request.POST.getlist('oprotunity_options')
        if request.POST.get('notification_type'):
            opp_preferences['notification_type'] = request.POST.get('notification_type')
            if request.POST['notification_type'].lower() == 'daily':
                opp_preferences['max_emails'] = request.POST.get('max_emails', '100')
        user_pref['opprtunity_preferences'] = opp_preferences 
        request.user.userprofile.user_preferences = user_pref 
        request.user.userprofile.save()
        messages.add_message(request, messages.INFO, 'Your preferences has been saved successfully.')
        return HttpResponseRedirect(reverse('supplier:user_settings'))


class VerifyOtpFormView(FormView):
    """
    Supplier Login View
    """
    form_class = VerifyOtpForm
    template_name = 'subscriber/verify_otp.html'
    success_url = '/supplier/'

    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def dispatch(self, *args, **kwargs):
        return super(VerifyOtpFormView, self).dispatch(*args, **kwargs)

    def get_context_data(self, **kwargs):
        if 'view' not in kwargs:
            kwargs['view'] = self
        if not self.request.user.is_anonymous():
            if self.request.user.userprofile.phone:
                phone = self.request.user.userprofile.phone
                kwargs['partial_phone_no'] = "{}".format(phone[-4:])
        return kwargs

    def get_form_kwargs(self):
        kwargs = super(VerifyOtpFormView, self).get_form_kwargs()
        kwargs['request'] = self.request
        return kwargs

    def form_valid(self, form):
        """
        If the form is valid, redirect to the supplied URL.
        """
        self.request.session['opt_verified'] = True
        return HttpResponseRedirect(self.get_success_url())

    def form_invalid(self, form):
        """
        If the form is invalid, re-render the context data with the
        data-filled form and errors.
        """
        return self.render_to_response(self.get_context_data(form=form))


class ResendOtpView(TemplateView):
    """Class to resend OTP
    """
    template_name = 'subscriber/verify_otp.html'

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        send_otp(phone_number=self.request.user.userprofile.phone)
        return HttpResponseRedirect(reverse('subscriber:verify_otp'))


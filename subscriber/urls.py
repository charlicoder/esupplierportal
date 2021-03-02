from django.urls import path, include
from django.views.generic import TemplateView
from subscriber.views import supplier_logout, SupplierLoginFormView, RegistrationFormView, ContinueRegistrationFormView, ResetPasswordFormView, UserOppurtunityPreferenceView, VerifyOtpFormView, ResendOtpView

# get_started, get_coupon, reset_password, registration_success, registration_active

app_name = 'subscriber'

urlpatterns = [
    path('login/', SupplierLoginFormView.as_view(), name='login'),
    path('verify-otp/', VerifyOtpFormView.as_view(), name='verify_otp'),
    path('resend-otp/', ResendOtpView.as_view(), name='resend_otp'),
    path('test/', TemplateView.as_view(template_name='subscriber/notifications/thank-you.html')),
    path('logout/', supplier_logout, name='logout'),
    path('forget-password/', ResetPasswordFormView.as_view(), name='forget_password'),
    # path('reset-password/<code>/', reset_password, name='reset_password'),
    
    path('registration/', RegistrationFormView.as_view(), name='registration'),

    # path('registration/<activation_code>/active/', registration_active, name='registration-active'),
    path('registration/continue/<activation_code>/', ContinueRegistrationFormView.as_view(), name='registration_landing_activate'),

    # path('<uid>/registration/success/', registration_success, name='registration-success'),

    # path('get-started/', get_started, name='get-started'),

    # path('get-coupon/<code>/', get_coupon, name='get-coupon'),

    # # url(r'^payment/$', 'supplier.views.payment', name='payment'),
    # path('payment/create/$', 'subscriber.views.payment_create', name='payment_create'),
    # path('payment/execute/$', 'subscriber.views.payment_execute', name='payment_execute'),
    # path('payment/success/$', 'subscriber.views.payment_success', name='payment_success'),
    # path('payment/error/$', 'subscriber.views.payment_error', name='payment_error'),
    # path('save/user-prefernce/$', UserOppurtunityPreferenceView.as_view(), name='user_oppr_pref'),
]
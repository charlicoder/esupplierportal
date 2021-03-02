from django.urls import path, include

from portal.views import HomePageView, PricingPageView, AboutPageView, ContactPageView

app_name = 'portal'

urlpatterns = [
    path('', HomePageView.as_view(), name='home'),
    path('pricing/', PricingPageView.as_view(), name='pricing'),
    path('about/', AboutPageView.as_view(), name='about'),
    path('contact/', ContactPageView.as_view(), name='contact'),
]
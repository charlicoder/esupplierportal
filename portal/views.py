from django.views.generic import TemplateView


class HomePageView(TemplateView):
    """
    Home page view
    """
    template_name = 'portal/homepage.html'
    

class PricingPageView(TemplateView):
    """
    Princing Page view
    """
    template_name = 'portal/pricing.html'
    
    
class AboutPageView(TemplateView):
    """
    About page view
    """
    template_name = 'portal/about.html'
    
    
class ContactPageView(TemplateView):
    """
    Contact page view
    """
    template_name = 'portal/contact.html'
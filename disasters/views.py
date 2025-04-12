from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate, get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.conf import settings
from django.contrib.sites.shortcuts import get_current_site
import random
from .models import Details,alert

# Get the custom User model
User = get_user_model()

def home(request):
    if alert.objects.all().exists():
        alt=alert.objects.all().first()
        return render(request,'Home.html',{'alt':alt})
    return render(request, 'Home.html')

def generate_otp():
    """Generate a 6-digit OTP."""
    return random.randint(100000, 999999)

def register(request):
    """Handles user registration with email verification."""
    if request.method == 'POST':
        first_name = request.POST['name']
        email = request.POST['email']
        username = request.POST['username']
        password = request.POST['password']
        confirmation_password = request.POST['cnfm_password']

        if password != confirmation_password:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'register.html')

        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists, please choose a different one.')
            return redirect('register')

        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already exists, please choose a different one.')
            return redirect('register')

        user = User.objects.create_user(
            username=username,
            password=password,
            email=email,
            first_name=first_name
        )
        user.is_active = False  # User must verify email before activation
        user.save()

        otp = generate_otp()
        Details.objects.create(user=user, otp=otp)  # Save OTP in database

        send_activation_email(user, request, otp)
        return redirect(f'/mailsend/?username={username}&email={email}')
    return render(request, 'register.html')

def send_activation_email(user, request, otp):
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    current_site = get_current_site(request)
    domain = current_site.domain
    activation_link = f"http://{domain}/activate/{uid}/{token}/"

    subject = 'Activate Your Account'
    html_message = render_to_string('Acc-act/activation_email.html', {
        'user': user,
        'activation_link': activation_link,
        'otp': otp
    })

    email = EmailMultiAlternatives(subject, html_message, settings.DEFAULT_FROM_EMAIL, [user.email])
    email.attach_alternative(html_message, "text/html")
    email.send()
def activate_account(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user)
        return redirect('home')
    else:
        return render(request, 'Acc-act/activation_invalid.html')

def login_view(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = User.objects.filter(username=username).first()
        if user:
            if user.check_password(password):
                if user.is_active:
                    user = authenticate(username=username, password=password)
                    if user:
                        login(request, user)
                        messages.success(request, 'Login successful.')
                        return redirect('home')
                    else:
                        messages.error(request, 'Invalid password.')
                else:
                    uid = urlsafe_base64_encode(force_bytes(user.pk))
                    return render(request, 'Acc-act/Reactivate_acc.html', {'username': user, 'uid': uid})
            else:
                messages.error(request, "Invalid password.")
        else:
            messages.error(request, "Username doesn't exist.")

        return redirect('login')

    return render(request, 'login.html')

def logout_view(request):
    """Logs out the user and redirects to login page."""
    logout(request)
    return redirect('login')

def active_mail(request):
    username = request.GET.get('username') if request.method == 'GET' else request.POST.get('username')
    if request.method == "POST":
        otp = ''.join([request.POST.get(f'otp{i}', '') for i in range(1, 7)])  # Collects all 6 OTP digits
        user = get_object_or_404(User, username=username)
        details = Details.objects.filter(user=user).last()
        print(username)
        if details and int(details.otp) == int(otp):
            user.is_active = True
            user.save()
            return redirect('login')
        else:
            messages.error(request, "Invalid OTP.")
            email=user.email
            return redirect(f'/mailsend/?username={username}&email={email}')
    return render(request, 'Acc-act/mail_send.html', {'username': username})

def reactivate_acc(request, uidb64):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
        send_activation_email(user, request, generate_otp())
    except (User.DoesNotExist, TypeError, ValueError, OverflowError):
        return render(request, 'Acc-act/activation_invalid.html')
    return render(request, 'Acc-act/reactivate_message.html')

def raise_alert(request):
    if request.method=='POST':
        message=request.POST['message']
        raised_by=request.user
        alert.objects.create(message=message,raise_by=raised_by)
        return redirect('raise_alert')
    return render(request,'createaleart.html')
def recent_alert(request):
    info=alert.objects.all().order_by('-id')
    return render (request,'recent.html',{'info':info})
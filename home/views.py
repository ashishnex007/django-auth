from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, logout, login
from django.contrib import messages
from django.contrib.auth.models import User

# Create your views here.
def index(request):
    if request.user.is_authenticated:
        return render(request, "index.html")
    return redirect('/login')
    
def loginUser(request):
    if request.method == "POST":
        #check the credentials
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('/')
        else:
            messages.error(request, "Invalid Credentials.")
            return render(request, "login.html")
        
    return render(request, "login.html")

def signupUser(request):
    if request.method == "POST":
        # Get the post parameters
        username = request.POST.get('username')
        password = request.POST.get('password')
        cpassword = request.POST.get('cpassword')
        
        # Check for errorneous inputs
        if len(username) > 10:
            messages.error(request, "Username must be under 10 characters.")
            return render(request, "signup.html")
        if not username.isalnum():
            messages.error(request, "Username should only contain letters and numbers.")
            return render(request, "signup.html")
        if len(password) < 8:
            messages.error(request, "Password must be at least 8 characters.")
            return render(request, "signup.html")
        if password != cpassword:
            messages.error(request, "Passwords do not match.")
            return render(request, "signup.html")
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username is already taken.")
            return render(request, "signup.html")
        
        # Create the user
        myuser = User.objects.create_user(username= username, password= password)
        myuser.save()
        messages.success(request, "Your account has been successfully created.")

        #login user
        user = authenticate(username=username, password=password)
        login(request, user)
        return redirect('/')
    
    return render(request, "signup.html")

def logoutUser(request):
    logout(request)
    return redirect("/login")
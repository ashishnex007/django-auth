from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, logout, login

# Create your views here.
def index(request):
    if request.user.is_authenticated:
        return render(request, "index.html")
    return redirect('/login')
    
def loginUser(request):
    if request.method == "POST":
        #check the credentials
        usernamex = request.POST.get('username')
        passwordx = request.POST.get('password')
        user = authenticate(username=usernamex, password=passwordx)
        if user is not None:
            login(request, user)
            return redirect('/')
        else:
            return redirect('/login')
        
    return render(request, "login.html")
def logoutUser(request):
    logout(request)
    return redirect("/login")
from django.shortcuts import render

# Create your views here.
def index(request):
    return render(request, 'web_manager/index.html')

from django.urls import path
from .views import UserCreate, CustomTokenObtainPairView


urlpatterns = [
    path('register/', UserCreate.as_view(), name='register'),
    #path('login/', login_view, name='login'),
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    #path('logout/', logout_view, name='logout'),
]
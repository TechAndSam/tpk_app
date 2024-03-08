from django.urls import path
from .views import SubjectListCreateView, SubjectRetrieveUpdateDestroyView, LevelListCreateView, \
LevelRetrieveUpdateDestroyView, QuestionListCreateView, QuestionRetrieveUpdateDestroyView, ResultListCreateView, \
ResultRetrieveUpdateDestroyView


urlpatterns = [
    path('subjects/', SubjectListCreateView.as_view(), name='subject-list-create'),
    path('subjects/<int:pk>/', SubjectRetrieveUpdateDestroyView.as_view(), name='subject-retrieve-update-destroy'),
    path('levels/', LevelListCreateView.as_view(), name='level-list-create'),
    path('levels/<int:pk>/', LevelRetrieveUpdateDestroyView.as_view(), name='level-retrieve-update-destroy'),
    path('questions/', QuestionListCreateView.as_view(), name='question-list-create'),
    path('questions/<int:pk>/', QuestionRetrieveUpdateDestroyView.as_view(), name='question-retrieve-update-destroy'),
    path('results/', ResultListCreateView.as_view(), name='result-list-create'),
    path('results/<int:pk>/', ResultRetrieveUpdateDestroyView.as_view(), name='result-retrieve-update-destroy'),
]

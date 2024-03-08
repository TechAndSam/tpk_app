from django.db import models
from django.contrib.auth import get_user_model
from main.models import UniqueRegistrationCode

# Create your models here.
User = get_user_model()


class Subject(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name



class Level(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name


class Question(models.Model):
    code = models.ForeignKey(UniqueRegistrationCode, on_delete=models.CASCADE)
    subject = models.ForeignKey(Subject, on_delete=models.CASCADE)
    level = models.ForeignKey(Level, on_delete=models.CASCADE)
    question_text = models.TextField()
    option1 = models.CharField(max_length=100)
    option2 = models.CharField(max_length=100)
    option3 = models.CharField(max_length=100)
    option4 = models.CharField(max_length=100)
    correct_option = models.CharField(max_length=100)

    def __str__(self):
        return self.question_text


class Result(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.ForeignKey(UniqueRegistrationCode, on_delete=models.CASCADE)
    score = models.IntegerField()
    date_attempted = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.code.code} - Score: {self.score}"


# class Quiz(models.Model):
#     LEVEL_CHOICES = (
#         ('Beginner', 'Beginner'),
#         ('Intermediate', 'Intermediate'),
#         ('Advanced', 'Advanced')
#     )

#     SUBJECT_CHOICES = (
#         ('Python', 'Python'),
#         ('PHP', 'PHP'),
#         ('Data Analysis', 'Data Analysis')
#     )
#     level = models.CharField(max_length=20, choices=LEVEL_CHOICES)
#     subject = models.CharField(max_length=50, choices=SUBJECT_CHOICES, default='PHP')
#     question = models.TextField()
#     option1 = models.CharField(max_length=100)
#     option2 = models.CharField(max_length=100)
#     option3 = models.CharField(max_length=100)
#     option4 = models.CharField(max_length=100)
#     correct_option = models.CharField(max_length=100)


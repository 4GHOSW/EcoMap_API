from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth.models import AbstractUser, UserManager
from . import managers
from django.contrib.sessions.models import Session

class User(AbstractUser):
    objects = managers.CustomUserModelManager()
    gender = models.CharField(null=True, blank=True, max_length=1000)
    avatar = models.ImageField(null=True, upload_to='avatar', max_length=1000, default="avatar/default_avatar.png")
    kakao_id = models.BigIntegerField(null=True, blank=True)
    naver_id = models.CharField(max_length=1000, null=True, blank=True)
    google_id = models.CharField(max_length=1000, null=True, blank=True)
    
    """ Custom User model """

    LOGIN_EMAIL = "Email"
    LOGIN_KAKAO = "Kakao"
    LOGIN_NAVER = "Naver"

    LOGIN_CHOICES = (
        (LOGIN_EMAIL, "Email"),
        (LOGIN_KAKAO, "Kakao"),
        (LOGIN_NAVER, "Naver"),
    )
    
    sign_up_platform = models.CharField(max_length=10, choices=LOGIN_CHOICES, null=True, blank=True)

    def __str__(self):
        if self.is_staff:
            is_staff = '✅'
        else:
            is_staff = ''
        return str(self.id) + '. ' + self.first_name + ' (' + self.username + ') ' + is_staff
    
    # def get_user_by_session_key(self, session_key): # get_user_by_session_key
    #     if session_key is None:
    #         return None
    #     try:
    #         session = Session.objects.get(session_key=session_key)
    #     except Session.DoesNotExist:
    #         return None
    #     user_id = session.get_decoded().get('_auth_user_id')
    #     if user_id:
    #         return User.objects.get(pk=user_id)
    #     return None

class UserCarbon(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='carbon_user', null=True, blank=True)
    total_carbon = models.FloatField(default=0.0, null=True, blank=True)
    created_at = models.DateField(auto_now_add=True)
    updated_at = models.DateField(auto_now_add=False, null=True, blank=True)

    def __str__(self):
        return str(self.user.first_name) + ' : ' + str(self.total_carbon)


from io import BytesIO
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db.models.signals import pre_save
from django.dispatch import receiver
from PIL import Image

@receiver(pre_save, sender=User)
def crop_image(sender, instance, **kwargs):
    if instance.avatar and not instance.avatar._committed:
        img = Image.open(instance.avatar)
        width, height = img.size

        # Calculate the dimensions for the square crop
        if width > height:
            left = (width - height) // 2
            right = left + height
            top = 0
            bottom = height
        else:
            top = (height - width) // 2
            bottom = top + width
            left = 0
            right = width

        # Crop the image
        cropped_img = img.crop((left, top, right, bottom))

        # Resize the image to your desired size if necessary
        cropped_img = cropped_img.resize((500, 500))

        # Convert image to RGB color mode
        cropped_img = cropped_img.convert('RGB')

        # Save the cropped image back to the instance.avatar field
        buffer = BytesIO()
        cropped_img.save(buffer, format='JPEG')
        buffer.seek(0)

        instance.avatar = SimpleUploadedFile(
            name=instance.avatar.name,
            content=buffer.read(),
            content_type='image/jpeg'
        )

## models에서 커스텀 유저 모델을 위한 manager 파일

from django.contrib.auth.models import UserManager as AbstractUserManager

class CustomUserModelManager(AbstractUserManager):
    def get_or_none(self, **kwargs):
        try:
            return self.get(**kwargs)
        except self.model.DoesNotExist:
            return None
# shop/auth.py
from django.contrib.auth import get_user_model


def user_from_owner(owner: str):
    return get_user_model().objects.filter(pk=owner).first()   # owner 存的是 user.pk 字串

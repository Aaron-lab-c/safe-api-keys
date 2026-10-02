# shop/urls.py
from django.contrib import admin
from django.urls import path

from . import views_account, views_api
from .api_drf import OrdersView
from .views_api import health

urlpatterns = [
    path("admin/", admin.site.urls),                                   # API keys 頁面：發行 / 撤銷 / 輪替
    path("account/csrf/", views_account.csrf),                         # GET：設定 csrftoken cookie
    path("account/api-keys/", views_account.list_keys),               # GET
    path("account/api-keys/create/", views_account.create_key),       # POST
    path("account/api-keys/<str:key_id>/revoke/", views_account.revoke_key),
    path("account/api-keys/<str:key_id>/rotate/", views_account.rotate_key),
    path("api/orders/", views_api.orders),
    path("api/orders/create/", views_api.create_order),
    path("api/reports/<str:name>/", views_api.report),
    path("api/health/", health),                                      # 在 EXEMPT 內，不需 key
    path("api/v2/orders/", OrdersView.as_view()),
]

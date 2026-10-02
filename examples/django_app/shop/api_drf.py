# shop/api_drf.py — 同一件事的 DRF 寫法
from rest_framework.response import Response
from rest_framework.views import APIView

from safe_api_keys.contrib.django.drf import APIKeyAuthentication, HasAPIKeyScope

from .models import Order


class OrdersView(APIView):
    # request.user 由 USER_RESOLVER 解析，request.auth 是 KeyRecord
    authentication_classes = [APIKeyAuthentication]
    permission_classes = [HasAPIKeyScope("orders:read")]

    def get(self, request):
        return Response(list(Order.objects.filter(owner_id=request.auth.owner).values("id", "item", "qty")))

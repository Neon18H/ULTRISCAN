from rest_framework import serializers

from .models import ScanProfile


class ScanProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanProfile
        fields = '__all__'
        read_only_fields = ['organization']

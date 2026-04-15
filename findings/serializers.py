from rest_framework import serializers

from .models import Finding


class FindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Finding
        fields = '__all__'
        read_only_fields = ['organization']

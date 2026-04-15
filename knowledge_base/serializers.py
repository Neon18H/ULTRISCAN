from rest_framework import serializers
from .models import VulnerabilityRule


class VulnerabilityRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = VulnerabilityRule
        fields = '__all__'

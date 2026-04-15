from rest_framework import serializers
from .models import RawEvidence, ScanExecution, ServiceFinding, WebFinding


class RawEvidenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = RawEvidence
        fields = '__all__'


class ServiceFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = ServiceFinding
        fields = '__all__'


class WebFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = WebFinding
        fields = '__all__'


class ScanExecutionSerializer(serializers.ModelSerializer):
    raw_evidences = RawEvidenceSerializer(many=True, read_only=True)
    service_findings = ServiceFindingSerializer(many=True, read_only=True)
    web_findings = WebFindingSerializer(many=True, read_only=True)

    class Meta:
        model = ScanExecution
        fields = '__all__'

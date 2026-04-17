from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('findings', '0005_finding_ai_confidence_finding_ai_cwe_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='finding',
            name='ai_generated_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
